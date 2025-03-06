from django.contrib.gis.db.models.functions import Distance
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import D
from django.db import models
from django.db.models import Count, F, Q
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg.utils import swagger_auto_schema
from rest_framework import filters, generics, mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from listings.models import (
    Category,
    Listing,
    ListingImage,
    RecommendedListing,
    SavedSearch,
    SearchQuery,
)
from listings.serializers import (
    ListingDetailSerializer,
    ListingImageSerializer,
    ListingSerializer,
    PublicListingSerializer,
    RecommendedListingSerializer,
    SavedSearchSerializer,
)
from utils import IsSellerPermission


class StandardResultsPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


class ListingViewSet(viewsets.ModelViewSet):
    """API endpoint for managing marketplace listings.

    Provides CRUD operations for listings with filtering, searching, and
    ordering capabilities.
    Only sellers can create, update, or delete their own listings.
    """

    serializer_class = ListingSerializer
    permission_classes = [IsSellerPermission]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = [
        'category',
        'status',
        'condition',
        'city',
        'state',
        'country',
    ]
    search_fields = ['title', 'description', 'address', 'city']
    ordering_fields = [
        'price',
        'created_at',
        'view_count',
        'published_at',
        'search_appearance_count',
    ]  # ✅ Added search_appearance_count for ordering

    def get_queryset(self):
        return (
            Listing.objects.filter(
                is_active=True, is_deleted=False, seller__user=self.request.user
            )
            .select_related('seller', 'category')
            .prefetch_related('images')
        )

    def get_serializer_class(self):
        """Return appropriate serializer class based on the action.

        For retrieve action, use the detailed serializer.
        For all other actions, use the standard serializer.
        """
        if self.action == 'retrieve':
            return ListingDetailSerializer
        return ListingSerializer

    def perform_create(self, serializer):
        """Create a new listing and associate it with the current
        user's seller profile.
        """
        serializer.save()

    def perform_update(self, serializer):
        """Update an existing listing while ensuring the
        seller remains unchanged.
        """
        serializer.save()

    def perform_destroy(self, instance):
        """Soft delete the listing instead of permanently
        removing it from the database.
        """
        instance.soft_delete()

    def list(self, request, *args, **kwargs):
        """Override the list method to increment `search_appearance_count`
        only when a search query is applied.
        """
        response = super().list(request, *args, **kwargs)

        # ✅ Ensure response.data is a list (Django Rest Framework pagination)
        if isinstance(response.data, dict) and "results" in response.data:
            listings = response.data["results"]  # Use results if paginated
        else:
            listings = response.data  # Fallback for non-paginated response

        # ✅ Check if a search query is applied
        search_query = self.request.query_params.get("search", None)
        if search_query and isinstance(listings, list):
            # ✅ Extract listing IDs from the response data
            listing_ids = [
                listing["id"] for listing in listings if "id" in listing
            ]

            if listing_ids:
                # ✅ Update `search_appearance_count` for the matched listings
                Listing.objects.filter(id__in=listing_ids).update(
                    search_appearance_count=F('search_appearance_count') + 1
                )

        return response

    @swagger_auto_schema(
        method='post',
        operation_description="Mark a listing as sold",
        responses={200: "Listing marked as sold"},
    )
    @action(detail=True, methods=['post'])
    def mark_as_sold(self, request, pk=None):
        """Mark a listing as sold."""
        listing = self.get_object()
        listing.status = Listing.StatusChoices.SOLD
        listing.save(update_fields=['status', 'updated_at'])
        return Response({"message": "Listing marked as sold"})

    @swagger_auto_schema(
        method='post',
        operation_description="Increment the view count of a listing",
        responses={200: "View count incremented"},
    )
    @action(detail=True, methods=['post'])
    def increment_view(self, request, pk=None):
        """Increment the view count for a listing."""
        listing = self.get_object()
        listing.increment_view_count()
        listing.refresh_from_db()
        return Response({"view_count": listing.view_count})

    @swagger_auto_schema(
        method='post',
        operation_description="Toggle the active state of a listing",
        responses={200: "Listing active state toggled successfully."},
    )
    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        """Toggle the active state of a listing."""
        listing = self.get_object()
        listing.is_active = not listing.is_active
        listing.save(update_fields=['is_active', 'updated_at'])
        return Response({"is_active": listing.is_active})

    @swagger_auto_schema(
        method='post',
        operation_description="Toggle the featured status of a listing",
        responses={200: "Listing featured status toggled successfully."},
    )
    @action(detail=True, methods=['post'])
    def toggle_feature(self, request, pk=None):
        """Toggle the featured status of a listing."""
        listing = self.get_object()
        listing.is_featured = not listing.is_featured
        listing.save(update_fields=['is_featured', 'updated_at'])
        return Response({"is_featured": listing.is_featured})


class ListingImageViewSet(
    mixins.CreateModelMixin, mixins.DestroyModelMixin, viewsets.GenericViewSet
):
    """API endpoint for managing Listing Images.

    Provides endpoints for creating and deleting ListingImage objects.
    The image list is already available via the Listing endpoint.
    """

    serializer_class = ListingImageSerializer
    permission_classes = [IsSellerPermission]

    def get_queryset(self):
        return ListingImage.objects.filter(
            listing__is_active=True,
            listing__is_deleted=False,
            listing__seller__user=self.request.user,
        )


class PublicListingListView(generics.ListAPIView):
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

    def get_queryset_with_tracking(self):
        """Get the queryset and track the search query"""
        # First, get the filtered queryset
        queryset = self.get_untracked_queryset()

        # Then track the search query
        self.track_search_query(queryset.count())

        return queryset

    def get_queryset(self):
        """Override to include search tracking"""
        return self.get_queryset_with_tracking()

    def get_untracked_queryset(self):
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
                # This assumes there's a way to filter by seller rating
                # Adjust based on your actual models
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
                    expires_at__lte=timezone.now()
                    + timezone.timedelta(days=days),
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
                # If there's an error with the coordinates, fall back to
                # default sorting
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
            # This assumes there's a way to sort by seller rating
            # Adjust based on your actual models
            queryset = queryset.annotate(
                avg_seller_rating=models.Avg('seller__ratings__value')
            ).order_by('-avg_seller_rating', '-published_at')
        elif sort == 'most_commented':
            queryset = queryset.order_by('-total_comments')
        elif sort == 'alphabetical':
            queryset = queryset.order_by('title')

        return (
            queryset.distinct()
        )  # Ensure distinct results when using multiple joins

    def _get_category_and_children(self, category_id):
        """Get the category and all its children recursively"""
        try:
            # This implementation assumes there's a way to get child categories
            # You may need to adjust based on your actual Category model
            # implementation
            category = Category.objects.get(id=category_id)
            # Assuming there's a method to get all descendants
            descendants = category.get_descendants(include_self=True)
            return [cat.id for cat in descendants]
        except Category.DoesNotExist:
            return [
                category_id
            ]  # Return just the original ID if category doesn't exist

    def get_serializer_context(self):
        """Add request to serializer context for building absolute URLs"""
        context = super().get_serializer_context()
        context['request'] = self.request
        return context

    def track_search_query(self, result_count):
        """Track the search query in the database"""
        from django.contrib.gis.geos import Point

        request = self.request

        # Don't track if this is an API key request or other non-user request
        if not hasattr(request, 'user') or not hasattr(request, 'session'):
            return

        # Extract query parameters
        query_text = request.query_params.get('q', '')

        # Skip tracking if this is just a simple navigation with no search terms
        # unless it's a category browse which is still useful to track
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
        from users.models import (  # Import here to avoid circular imports
            SearchQuery,
        )

        search_query = SearchQuery(
            user=request.user if request.user.is_authenticated else None,
            query_text=query_text,
            category=category,
            filters=filter_params,
            location_text=request.query_params.get('city', '')
            or request.query_params.get('state', '')
            or request.query_params.get('country', ''),
            coordinates=coordinates,
            radius=(
                float(radius)
                if radius and radius.replace('.', '').isdigit()
                else None
            ),
            result_count=result_count,
            ip_address=self.get_client_ip(request),
            session_id=request.session.session_key,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )
        search_query.save()

        # Store the search query ID in session for potential saving later
        request.session['last_search_query_id'] = search_query.id

        return search_query

    def get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SaveSearchView(APIView):
    """Save the current search query for alerts"""

    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
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
    """List all saved searches for the current user"""

    serializer_class = SavedSearchSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return SavedSearch.objects.filter(user=self.request.user).order_by(
            '-created_at'
        )


class SavedSearchDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update or delete a saved search"""

    serializer_class = SavedSearchSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return SavedSearch.objects.filter(user=self.request.user)


class RecommendationsView(generics.ListAPIView):
    """Get personalized listing recommendations for the current user"""

    serializer_class = RecommendedListingSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
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
    """Mark a recommendation as clicked"""

    permission_classes = [IsAuthenticated]

    def post(self, request, pk, *args, **kwargs):
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
    """Admin endpoint to generate recommendations for all users"""

    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Check if user has admin permissions
        if not request.user.is_staff:
            return Response(
                {"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN
            )

        # This would call your recommendation algorithm
        # For this example, we'll create a placeholder implementation
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
            # search_terms = " ".join(
            #     [sq.query_text for sq in search_queries if sq.query_text]
            # )

            # 2. Get the user's favorite listings
            favorite_listings = Listing.objects.filter(
                favorites__user=user, favorites__is_active=True
            )

            # 3. Get the user's viewed listings
            # Assuming you track this elsewhere

            # 4. Get active listings that might be relevant
            # In a real implementation, you'd use ML or more sophisticated
            # matching
            # This is just a simple example that gets recent listings in
            # categories the user has searched for

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
                # In a real implementation, this would be a ML-based relevance
                # score
                score = 0.9 - (i * 0.01)  # Simple decreasing score

                # Add bonus for featured listings
                if listing.is_featured:
                    score += 0.1

                # Generate a reason
                if i < 3:
                    reason = "Based on your recent searches"
                else:
                    reason = "You might be interested in this"

                # Create the recommendation
                RecommendedListing.objects.create(
                    user=user, listing=listing, score=score, reason=reason
                )
                created_count += 1

        return Response(
            {"status": "success", "created": created_count},
            status=status.HTTP_200_OK,
        )
