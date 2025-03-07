from django.contrib.gis.db.models.functions import Distance
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import D
from django.db.models import Avg, Count, Q
from django.http import Http404
from django.utils import timezone
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import filters, generics, status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from listings.models import (
    Category,
    Comment,
    Favorite,
    Listing,
    RecommendedListing,
    SavedSearch,
    SearchQuery,
)
from listings.serializers import (
    CommentSerializer,
    PublicListingSerializer,
    RecommendedListingSerializer,
    SavedSearchSerializer,
)


class StandardResultsPagination(PageNumberPagination):
    """Standard pagination for marketplace listings.

    Provides configurable page-based pagination.
    """

    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 1000


class PublicListingListView(generics.ListAPIView):
    """List and filter marketplace listings.

    Provides comprehensive filtering and search capabilities for public
    listings with location-based features and tracking.
    """

    serializer_class = PublicListingSerializer
    pagination_class = StandardResultsPagination
    filter_backends = [filters.SearchFilter]
    search_fields = [
        'title',
        'description',
        'category__name',
        'category__parent__name',
        'seller__user__username',
    ]

    # Define query parameters for Swagger documentation
    location_params = [
        openapi.Parameter(
            'latitude',
            openapi.IN_QUERY,
            description="User's latitude for distance calculation",
            type=openapi.TYPE_NUMBER,
            required=False,
        ),
        openapi.Parameter(
            'longitude',
            openapi.IN_QUERY,
            description="User's longitude for distance calculation",
            type=openapi.TYPE_NUMBER,
            required=False,
        ),
        openapi.Parameter(
            'radius',
            openapi.IN_QUERY,
            description="Search radius in kilometers",
            type=openapi.TYPE_NUMBER,
            required=False,
        ),
    ]

    filter_params = [
        openapi.Parameter(
            'min_price',
            openapi.IN_QUERY,
            description="Minimum price filter",
            type=openapi.TYPE_NUMBER,
            required=False,
        ),
        openapi.Parameter(
            'max_price',
            openapi.IN_QUERY,
            description="Maximum price filter",
            type=openapi.TYPE_NUMBER,
            required=False,
        ),
        openapi.Parameter(
            'category',
            openapi.IN_QUERY,
            description="Category ID (includes subcategories)",
            type=openapi.TYPE_INTEGER,
            required=False,
        ),
        openapi.Parameter(
            'category_name',
            openapi.IN_QUERY,
            description="Category name (partial match)",
            type=openapi.TYPE_STRING,
            required=False,
        ),
        openapi.Parameter(
            'condition',
            openapi.IN_QUERY,
            description="Item condition (comma-separated for multiple)",
            type=openapi.TYPE_STRING,
            required=False,
        ),
        openapi.Parameter(
            'sort',
            openapi.IN_QUERY,
            description="Sort order (distance, price_low, price_high, recent)",
            type=openapi.TYPE_STRING,
            required=False,
            enum=[
                'distance',
                'price_low',
                'price_high',
                'recent',
                'ending_soon',
                'popular',
                'featured',
                'seller_rating',
                'most_commented',
                'alphabetical',
                'most_favorited',
            ],
        ),
    ]

    @swagger_auto_schema(
        operation_description="List and filter marketplace listings",
        manual_parameters=location_params + filter_params,
        responses={200: PublicListingSerializer(many=True)},
    )
    def get(self, request, *args, **kwargs):
        print('session_cookie', request.COOKIES.get('sessionid'))
        """Get a filtered and sorted list of marketplace listings.

        Supports comprehensive filtering and geo-location sorting.
        """
        return super().get(request, *args, **kwargs)

    def get_queryset_with_tracking(self):
        """Get the queryset and track the search query.

        Returns
        -------
            QuerySet: Filtered and sorted listings
        """
        # First, get the filtered queryset
        queryset = self.get_untracked_queryset()

        # Then track the search query
        self.track_search_query(queryset.count())

        return queryset

    def get_queryset(self):
        """Override to include search tracking.

        Returns
        -------
            QuerySet: Filtered and sorted listings with tracking
        """
        return self.get_queryset_with_tracking()

    def get_untracked_queryset(self):
        """Get the filtered and sorted queryset without tracking.

        Applies all filters from query parameters and sorts according to
        specified criteria.

        Returns
        -------
            QuerySet: Filtered and sorted listings
        """
        queryset = (
            Listing.objects.filter(status=Listing.StatusChoices.ACTIVE)
            .select_related(
                'category', 'category__parent', 'seller', 'seller__user'
            )
            .prefetch_related('images', 'comments', 'favorites')
            .annotate(total_comments=Count('comments'))
        )

        # Apply filters from query parameters
        filters = {}

        # Price range filter
        min_price = self.request.query_params.get('min_price')
        max_price = self.request.query_params.get('max_price')
        if min_price:
            filters['price__gte'] = float(min_price)
        if max_price:
            filters['price__lte'] = float(max_price)

        # Negotiable price filter
        negotiable = self.request.query_params.get('negotiable')
        if negotiable:
            filters['price_negotiable'] = negotiable.lower() == 'true'

        # Category filters
        # By ID
        category_id = self.request.query_params.get('category')
        if category_id:
            # Get all subcategories as well
            category_ids = self._get_category_and_children(category_id)
            filters['category__in'] = category_ids

        # By category name
        category_name = self.request.query_params.get('category_name')
        if category_name:
            filters['category__name__icontains'] = category_name

        # By parent category name
        parent_category_name = self.request.query_params.get(
            'parent_category_name'
        )
        if parent_category_name:
            filters['category__parent__name__icontains'] = parent_category_name

        # Condition filter
        condition = self.request.query_params.get('condition')
        if condition:
            # Handle multiple conditions (comma-separated)
            if ',' in condition:
                conditions = condition.split(',')
                queryset = queryset.filter(condition__in=conditions)
            else:
                filters['condition'] = condition

        # Location filters
        city = self.request.query_params.get('city')
        state = self.request.query_params.get('state')
        country = self.request.query_params.get('country')
        postal_code = self.request.query_params.get('postal_code')

        if city:
            filters['city__iexact'] = city
        if state:
            filters['state__iexact'] = state
        if country:
            filters['country__iexact'] = country
        if postal_code:
            filters['postal_code__iexact'] = postal_code

        # Date range filters
        published_after = self.request.query_params.get('published_after')
        published_before = self.request.query_params.get('published_before')

        if published_after:
            try:
                filters['published_at__gte'] = timezone.datetime.fromisoformat(
                    published_after
                )
            except ValueError:
                pass

        if published_before:
            try:
                filters['published_at__lte'] = timezone.datetime.fromisoformat(
                    published_before
                )
            except ValueError:
                pass

        # Seller filter
        seller_id = self.request.query_params.get('seller_id')
        if seller_id:
            filters['seller__id'] = seller_id

        # Seller rating filter
        min_seller_rating = self.request.query_params.get('min_seller_rating')
        if min_seller_rating:
            try:
                queryset = queryset.filter(
                    seller__ratings__value__gte=float(min_seller_rating)
                )
            except ValueError:
                pass

        # Featured listings
        featured = self.request.query_params.get('featured')
        if featured and featured.lower() == 'true':
            filters['is_featured'] = True

        # Currency filter
        currency = self.request.query_params.get('currency')
        if currency:
            filters['currency'] = currency.upper()

        # Recently added filter (last X days)
        recent_days = self.request.query_params.get('recent_days')
        if recent_days:
            try:
                days = int(recent_days)
                filters['published_at__gte'] = (
                    timezone.now() - timezone.timedelta(days=days)
                )
            except ValueError:
                pass

        # Ending soon filter (expiring in X days)
        ending_soon = self.request.query_params.get('ending_soon')
        if ending_soon:
            try:
                days = int(ending_soon)
                queryset = queryset.filter(
                    expires_at__isnull=False,
                    expires_at__lte=(
                        timezone.now() + timezone.timedelta(days=days)
                    ),
                )
            except ValueError:
                pass

        # Favorites filter (show only listings favorited by current user)
        favorited = self.request.query_params.get('favorited')
        if (
            favorited
            and favorited.lower() == 'true'
            and self.request.user.is_authenticated
        ):
            queryset = queryset.filter(
                favorites__user=self.request.user, favorites__is_active=True
            )

        # Free text search
        query = self.request.query_params.get('q')
        if query:
            queryset = queryset.filter(
                Q(title__icontains=query)
                | Q(description__icontains=query)
                | Q(category__name__icontains=query)
                | Q(category__parent__name__icontains=query)
                | Q(seller__user__username__icontains=query)
            )

        # Apply all filters
        queryset = queryset.filter(**filters)

        # Get user location from request parameters
        user_lat = self.request.query_params.get('latitude')
        user_lng = self.request.query_params.get('longitude')
        radius = self.request.query_params.get('radius')  # in kilometers

        # In your view code
        if user_lat and user_lng:
            try:
                user_lat = float(user_lat)
                user_lng = float(user_lng)
                user_location = Point(user_lng, user_lat, srid=4326)

                # Filter by radius if provided
                if radius:
                    radius_km = float(radius)
                    queryset = queryset.filter(
                        location__isnull=False,
                        location__distance_lte=(user_location, D(km=radius_km)),
                    )

                # Order listings by distance to user location
                queryset = queryset.filter(location__isnull=False).annotate(
                    distance=Distance('location', user_location)
                )

                # Sort parameter
                sort = self.request.query_params.get('sort', 'distance')
            except (ValueError, TypeError):
                # Fall back to default sorting if coordinates are invalid
                sort = self.request.query_params.get('sort', 'recent')
        else:
            # Default sorting if no user location is provided
            sort = self.request.query_params.get('sort', 'recent')

        # Apply sorting
        if sort == 'distance' and user_lat and user_lng:
            queryset = queryset.order_by('distance')
        elif sort == 'price_low':
            queryset = queryset.order_by('price')
        elif sort == 'price_high':
            queryset = queryset.order_by('-price')
        elif sort == 'recent':
            queryset = queryset.order_by('-published_at')
        elif sort == 'ending_soon':
            # Order by time remaining until expiry
            queryset = queryset.filter(expires_at__isnull=False).order_by(
                'expires_at'
            )
        elif sort == 'popular':
            queryset = queryset.order_by('-view_count')
        elif sort == 'most_favorited':
            queryset = queryset.order_by('-favorite_count')
        elif sort == 'featured':
            queryset = queryset.order_by('-is_featured', '-published_at')
        elif sort == 'seller_rating':
            queryset = queryset.annotate(
                avg_seller_rating=Avg('seller__ratings__value')
            ).order_by('-avg_seller_rating', '-published_at')
        elif sort == 'most_commented':
            queryset = queryset.order_by('-total_comments')
        elif sort == 'alphabetical':
            queryset = queryset.order_by('title')

        # Ensure distinct results when using multiple joins
        return queryset.distinct()

    def _get_category_and_children(self, category_id):
        """Get the category and all its children recursively.

        Args:
        ----
            category_id (int): Primary key of the category

        Returns:
        -------
            list: List of category IDs including parent and all children
        """
        try:
            # Get the category
            category = Category.objects.get(id=category_id)

            # Get all subcategories recursively using the method from your model
            subcategories = category.get_all_subcategories()

            # Return list of IDs including the parent category
            result = [category.id]
            result.extend([subcat.id for subcat in subcategories])

            return result

        except Category.DoesNotExist:
            # Return just the original ID if category doesn't exist
            return [category_id]

    def get_serializer_context(self):
        """Add request to serializer context for building absolute URLs.

        Returns
        -------
            dict: Context dictionary with request object
        """
        context = super().get_serializer_context()
        context['request'] = self.request
        return context

    def track_search_query(self, result_count):
        """Track the search query in the database.

        Creates a SearchQuery record for analytics and personalization.

        Args:
        ----
            result_count (int): Number of results from the search

        Returns:
        -------
            SearchQuery: The created search query or None
        """
        request = self.request

        # Don't track if this is not a user request with session
        if not hasattr(request, 'user') or not hasattr(request, 'session'):
            return

        # Extract query parameters
        query_text = request.query_params.get('q', '')

        # Skip tracking for simple navigation without search terms
        if (
            not query_text
            and not request.query_params.get('category')
            and not request.query_params.get('category_name')
        ):
            return

        # Get related category if any
        category_id = request.query_params.get('category')
        category = None
        if category_id:
            try:
                category = Category.objects.get(id=category_id)
            except Category.DoesNotExist:
                pass

        # Extract location data
        user_lat = request.query_params.get('latitude')
        user_lng = request.query_params.get('longitude')
        radius = request.query_params.get('radius')

        coordinates = None
        if user_lat and user_lng:
            try:
                user_lat = float(user_lat)
                user_lng = float(user_lng)
                coordinates = Point(user_lng, user_lat, srid=4326)
            except (ValueError, TypeError):
                pass

        # Collect all filter parameters
        filter_params = {}
        for key, value in request.query_params.items():
            # Skip pagination parameters
            if key in ['page', 'page_size']:
                continue
            filter_params[key] = value

        # Create the search query record
        location_text = (
            request.query_params.get('city', '')
            or request.query_params.get('state', '')
            or request.query_params.get('country', '')
        )

        radius_value = None
        if radius and radius.replace('.', '').isdigit():
            radius_value = float(radius)

        search_query = SearchQuery(
            user=request.user if request.user.is_authenticated else None,
            query_text=query_text,
            category=category,
            filters=filter_params,
            location_text=location_text,
            coordinates=coordinates,
            radius=radius_value,
            result_count=result_count,
            ip_address=self.get_client_ip(request),
            session_id=request.session.session_key,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )
        search_query.save()

        # Store search query ID in session for potential saving later
        request.session['last_search_query_id'] = search_query.id

        return search_query

    def get_client_ip(self, request):
        """Get client IP address from request.

        Args:
        ----
            request: HTTP request object

        Returns:
        -------
            str: IP address as string
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SaveSearchView(APIView):
    """Save the current search query for alerts.

    Allows users to save their recent searches and receive alerts
    when new matching listings are added.
    """

    permission_classes = [IsAuthenticated]

    search_request_schema = openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['name'],
        properties={
            'name': openapi.Schema(
                type=openapi.TYPE_STRING,
                description="Name for this saved search",
            ),
            'alert_enabled': openapi.Schema(
                type=openapi.TYPE_BOOLEAN,
                description="Whether to enable alerts for this search",
            ),
            'alert_frequency': openapi.Schema(
                type=openapi.TYPE_STRING,
                description="Alert frequency (instant, daily, weekly)",
                enum=['instant', 'daily', 'weekly'],
            ),
        },
    )

    @swagger_auto_schema(
        operation_description="Save the current search query for alerts",
        request_body=search_request_schema,
        responses={
            201: SavedSearchSerializer,
            400: "Bad request - missing name or invalid frequency",
            404: "Search query not found",
        },
    )
    def post(self, request, *args, **kwargs):
        """Save the most recent search query for the current user.

        Requires a name for the saved search and accepts optional
        alert preferences.

        Args:
        ----
            request: HTTP request with search parameters
            *args: Variable length argument list passed to the parent method
            **kwargs: Arbitrary keyword arguments passed to the parent method

        Returns:
        -------
            Response: Saved search data or error
        """
        # Get the last search query ID from session
        search_query_id = request.session.get('last_search_query_id')
        if not search_query_id:
            return Response(
                {
                    "error": "No recent search to save. Please perform a \
                        search first."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Get the name for this saved search
        name = request.data.get('name')
        if not name:
            return Response(
                {"error": "Please provide a name for this saved search."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Get alert preferences
        alert_enabled = request.data.get('alert_enabled', True)
        alert_frequency = request.data.get('alert_frequency', 'daily')

        # Validate alert frequency
        valid_frequencies = ['instant', 'daily', 'weekly']
        if alert_frequency not in valid_frequencies:
            return Response(
                {
                    "error": f"Invalid alert frequency. Must be one of: \
                        {', '.join(valid_frequencies)}"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Get the search query
            search_query = SearchQuery.objects.get(id=search_query_id)

            # Create the saved search
            saved_search = SavedSearch.objects.create(
                user=request.user,
                search_query=search_query,
                name=name,
                alert_enabled=alert_enabled,
                alert_frequency=alert_frequency,
            )

            # Return the saved search
            serializer = SavedSearchSerializer(saved_search)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except SearchQuery.DoesNotExist:
            return Response(
                {"error": "The search query could not be found."},
                status=status.HTTP_404_NOT_FOUND,
            )


class SavedSearchListView(generics.ListAPIView):
    """List all saved searches for the current user.

    Returns the user's saved searches ordered by creation date.
    """

    serializer_class = SavedSearchSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List all saved searches for the current user",
        responses={200: SavedSearchSerializer(many=True)},
    )
    def get(self, request, *args, **kwargs):
        """Get all saved searches for the current user.

        Returns
        -------
            Response: List of saved searches
        """
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        """Filter saved searches for the current user.

        Returns
        -------
            QuerySet: User's saved searches
        """
        return SavedSearch.objects.filter(user=self.request.user).order_by(
            '-created_at'
        )


class SavedSearchDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update or delete a saved search.

    Provides full CRUD operations for a specific saved search.
    """

    serializer_class = SavedSearchSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get a specific saved search",
        responses={200: SavedSearchSerializer, 404: "Saved search not found"},
    )
    def get(self, request, *args, **kwargs):
        """Get a specific saved search"""
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Update a saved search",
        request_body=SavedSearchSerializer,
        responses={
            200: SavedSearchSerializer,
            400: "Invalid data",
            404: "Saved search not found",
        },
    )
    def put(self, request, *args, **kwargs):
        """Update a saved search"""
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Delete a saved search",
        responses={204: "Successfully deleted", 404: "Saved search not found"},
    )
    def delete(self, request, *args, **kwargs):
        """Delete a saved search"""
        return super().delete(request, *args, **kwargs)

    def get_queryset(self):
        """Filter saved searches to only include the current user's.

        Returns
        -------
            QuerySet: Current user's saved searches
        """
        return SavedSearch.objects.filter(user=self.request.user)


class RecommendationsView(generics.ListAPIView):
    """Get personalized listing recommendations for the current user.

    Returns tailored listing recommendations based on user behavior.
    """

    serializer_class = RecommendedListingSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get personalized listing recommendations",
        responses={200: RecommendedListingSerializer(many=True)},
    )
    def get(self, request, *args, **kwargs):
        """Get personalized recommendations for current user.

        Returns
        -------
            Response: List of recommended listings
        """
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        """Get and mark recommendations for the current user.

        Automatically marks recommendations as viewed when retrieved.

        Returns
        -------
            QuerySet: Sorted list of recommendations
        """
        # Filter recommendations for the current user
        queryset = (
            RecommendedListing.objects.filter(user=self.request.user)
            .select_related('listing', 'listing__category', 'listing__seller')
            .prefetch_related('listing__images')
            .order_by('-score')
        )

        # Mark recommendations as viewed
        for recommendation in queryset:
            recommendation.mark_viewed()

        return queryset


class MarkRecommendationClickedView(APIView):
    """Mark a recommendation as clicked.

    Tracks when a user clicks on a recommended listing.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Mark a recommendation as clicked",
        responses={
            200: openapi.Response(
                description="Successfully marked as clicked",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING)
                    },
                ),
            ),
            404: "Recommendation not found",
        },
    )
    def post(self, request, pk, *args, **kwargs):
        """Mark a specific recommendation as clicked.

        Args:
        ----
            request: HTTP request
            pk (int): Recommendation ID
            *args: Variable length argument list passed to the parent method
            **kwargs: Arbitrary keyword arguments passed to the parent method

        Returns:
        -------
            Response: Success status or error
        """
        try:
            # Get the recommendation
            recommendation = RecommendedListing.objects.get(
                id=pk, user=request.user
            )

            # Mark as clicked
            recommendation.mark_clicked()

            return Response({"status": "success"}, status=status.HTTP_200_OK)

        except RecommendedListing.DoesNotExist:
            return Response(
                {"error": "Recommendation not found"},
                status=status.HTTP_404_NOT_FOUND,
            )


class GenerateRecommendationsView(APIView):
    """Admin endpoint to generate recommendations for all users.

    Creates personalized listing recommendations based on user behavior.
    """

    permission_classes = [IsAuthenticated]

    generate_schema = openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'count': openapi.Schema(
                type=openapi.TYPE_INTEGER,
                description="Number of recommendations to generate per user",
                default=5,
            )
        },
    )

    @swagger_auto_schema(
        operation_description="Generate recommendations for all users",
        request_body=generate_schema,
        responses={
            200: openapi.Response(
                description="Successfully generated recommendations",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING),
                        'created': openapi.Schema(type=openapi.TYPE_INTEGER),
                    },
                ),
            ),
            403: "Permission denied - admin only",
        },
    )
    def post(self, request, *args, **kwargs):
        """Generate personalized recommendations for all active users.

        Requires staff privileges.

        Args:
        ----
            request: HTTP request with optional parameters
            *args: Variable length argument list passed to the parent method
            **kwargs: Arbitrary keyword arguments passed to the parent method

        Returns:
        -------
            Response: Success status and count of created recommendations
        """
        # Check if user has admin permissions
        if not request.user.is_staff:
            return Response(
                {"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN
            )

        # This would call your recommendation algorithm
        from django.contrib.auth import get_user_model

        User = get_user_model()

        # Get number of recommendations to generate per user
        num_recommendations = int(request.data.get('count', 5))

        # Counter for created recommendations
        created_count = 0

        # Process all active users
        for user in User.objects.filter(is_active=True):
            # 1. Get the user's search history
            search_queries = user.search_queries.all().order_by('-created_at')[
                :10
            ]

            " ".join([sq.query_text for sq in search_queries if sq.query_text])

            # 2. Get the user's favorite listings
            favorite_listings = Listing.objects.filter(
                favorites__user=user, favorites__is_active=True
            )

            # 3. Get active listings that might be relevant
            potential_recommendations = (
                Listing.objects.filter(status=Listing.StatusChoices.ACTIVE)
                .exclude(
                    # Exclude listings the user has already favorited
                    id__in=[listing.id for listing in favorite_listings]
                )
                .exclude(
                    # Exclude listings the user has already had recommended
                    id__in=RecommendedListing.objects.filter(
                        user=user
                    ).values_list('listing_id', flat=True)
                )
            )

            # If they've searched for specific categories, prioritize those
            category_ids = set()
            for sq in search_queries:
                if sq.category:
                    category_ids.add(sq.category.id)

            if category_ids:
                potential_recommendations = potential_recommendations.filter(
                    category_id__in=category_ids
                )

            # Limit to recent and prioritize featured listings
            potential_recommendations = potential_recommendations.order_by(
                '-is_featured', '-published_at'
            )[:50]

            # Take the top N listings
            for i, listing in enumerate(
                potential_recommendations[:num_recommendations]
            ):
                # Calculate a score based on recency and features
                score = 0.9 - (i * 0.01)  # Simple decreasing score

                # Add bonus for featured listings
                if listing.is_featured:
                    score += 0.1

                # Generate a reason
                reason = (
                    "Based on your recent searches"
                    if i < 3
                    else "You might be interested in this"
                )

                # Create the recommendation
                RecommendedListing.objects.create(
                    user=user, listing=listing, score=score, reason=reason
                )
                created_count += 1

        return Response(
            {"status": "success", "created": created_count},
            status=status.HTTP_200_OK,
        )


class ListingDetailView(generics.RetrieveAPIView):
    """Retrieve a specific marketplace listing.

    Provides detailed information about a single listing and
    increments the view count when accessed.
    """

    queryset = Listing.objects.all()
    serializer_class = PublicListingSerializer
    lookup_field = 'slug'

    @swagger_auto_schema(
        operation_description="Get a specific listing by slug",
        responses={200: PublicListingSerializer, 404: "Listing not found"},
    )
    def get(self, request, *args, **kwargs):
        """Get a specific listing by slug.

        Increments the view count for the listing.

        Returns
        -------
            Response: Detailed listing data
        """
        return super().get(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Retrieve the listing and increment view count.

        Override to increment view count on successful retrieval.

        Returns
        -------
            Response: Listing data
        """
        # Get the instance
        instance = self.get_object()

        # Increment view count
        instance.increment_view_count()

        # Serialize and return
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


class FavoriteListingView(APIView):
    """Add a listing to user's favorites.

    Allows users to mark listings as favorites for later reference.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Add a listing to favorites",
        responses={
            200: openapi.Response(
                description="Successfully added to favorites",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING),
                        'favorite_count': openapi.Schema(
                            type=openapi.TYPE_INTEGER
                        ),
                    },
                ),
            ),
            400: "Already favorited",
            404: "Listing not found",
        },
    )
    def post(self, request, slug, *args, **kwargs):
        """Add a listing to the user's favorites.

        Args:
        ----
            request: HTTP request
            slug (str): Listing slug
            *args: Variable length argument list passed to the parent method
            **kwargs: Arbitrary keyword arguments passed to the parent method

        Returns:
        -------
            Response: Success status or error
        """
        try:
            listing = Listing.objects.get(slug=slug)

            favorite, created = Favorite.objects.get_or_create(
                user=request.user, listing=listing, defaults={'is_active': True}
            )

            if not created and favorite.is_active:
                return Response(
                    {"error": "This listing is already in your favorites"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Update if it exists but was inactive
            if not created and not favorite.is_active:
                favorite.is_active = True
                favorite.save()

            # Update favorite count and return
            return Response(
                {"status": "success", "favorite_count": listing.favorite_count}
            )

        except Listing.DoesNotExist:
            return Response(
                {"error": "Listing not found"}, status=status.HTTP_404_NOT_FOUND
            )


class UnfavoriteListingView(APIView):
    """Remove a listing from user's favorites.

    Allows users to remove listings from their favorites list.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Remove a listing from favorites",
        responses={
            200: openapi.Response(
                description="Successfully removed from favorites",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING),
                        'favorite_count': openapi.Schema(
                            type=openapi.TYPE_INTEGER
                        ),
                    },
                ),
            ),
            400: "Not favorited",
            404: "Listing not found",
        },
    )
    def post(self, request, slug, *args, **kwargs):
        """Remove a listing from the user's favorites.

        Args:
        ----
            request: HTTP request
            slug (str): Listing slug
            *args: Variable length argument list passed to the parent method
            **kwargs: Arbitrary keyword arguments passed to the parent method

        Returns:
        -------
            Response: Success status or error
        """
        try:
            listing = Listing.objects.get(slug=slug)

            try:
                favorite = Favorite.objects.get(
                    user=request.user, listing=listing
                )
                favorite.is_active = False
                favorite.save()

                return Response(
                    {
                        "status": "success",
                        "favorite_count": listing.favorite_count,
                    }
                )

            except Favorite.DoesNotExist:
                return Response(
                    {"error": "This listing is not in your favorites"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except Listing.DoesNotExist:
            return Response(
                {"error": "Listing not found"}, status=status.HTTP_404_NOT_FOUND
            )


class CommentListCreateView(generics.ListCreateAPIView):
    """List and create comments for a listing.

    Provides comment functionality for marketplace listings.
    """

    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]

    comment_params = [
        openapi.Parameter(
            'listing_slug',
            openapi.IN_PATH,
            description="Slug of the listing",
            type=openapi.TYPE_STRING,
            required=True,
        )
    ]

    @swagger_auto_schema(
        operation_description="List comments for a listing",
        manual_parameters=comment_params,
        responses={200: CommentSerializer(many=True), 404: "Listing not found"},
    )
    def get(self, request, *args, **kwargs):
        """Get all comments for a specific listing.

        Returns
        -------
            Response: List of comments
        """
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Add a comment to a listing",
        manual_parameters=comment_params,
        request_body=CommentSerializer,
        responses={
            201: CommentSerializer,
            400: "Invalid comment data",
            404: "Listing not found",
        },
    )
    def post(self, request, *args, **kwargs):
        """Add a new comment to a listing.

        Returns
        -------
            Response: Created comment data
        """
        return super().post(request, *args, **kwargs)

    def get_queryset(self):
        """Get comments for the specified listing.

        Returns
        -------
            QuerySet: Filtered comments
        """
        listing_slug = self.kwargs.get('listing_slug')
        return Comment.objects.filter(
            listing__slug=listing_slug, is_approved=True
        ).order_by('-created_at')

    def perform_create(self, serializer):
        """Create a new comment with the current user.

        Args:
        ----
            serializer: Comment serializer
        """
        listing_slug = self.kwargs.get('listing_slug')
        try:
            listing = Listing.objects.get(slug=listing_slug)
            serializer.save(user=self.request.user, listing=listing)
        except Listing.DoesNotExist:
            raise Http404("Listing not found")
