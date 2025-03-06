from django.db.models import F
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg.utils import swagger_auto_schema
from rest_framework import filters, mixins, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from listings.models import Listing, ListingImage
from listings.serializers import (
    ListingDetailSerializer,
    ListingImageSerializer,
    ListingSerializer,
)
from utils import IsSellerPermission


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
