import logging

from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import filters, generics, status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from listings.models import Category
from listings.serializers import CategorySerializer

logger = logging.getLogger(__name__)


class CategoryListView(generics.ListAPIView):
    """API endpoint to list categories with filtering, search, and ordering.

    This endpoint provides access to all active categories in the system with
    comprehensive filtering and search capabilities.

    ## Access Requirements:
    - No authentication required (public endpoint)
    - Categories are filtered to show only active ones by default

    ## Features:
    - Hierarchical category data with parent-child relationships
    - Filtering by multiple criteria (name, parent, featured status)
    - Advanced search across multiple fields
    - Flexible ordering options
    - Pagination support for large category sets

    ## Use Cases:
    - Populating category navigation menus
    - Building category browsing interfaces
    - Retrieving category metadata for SEO purposes
    - Finding specific categories via search
    """

    queryset = Category.objects.filter(
        is_active=True, is_deleted=False, parent=None
    )
    serializer_class = CategorySerializer
    permission_classes = [AllowAny]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]

    filterset_fields = {
        "name": ["exact", "icontains"],
        "parent": ["exact", "isnull"],
        "is_featured": ["exact"],
        "slug": ["exact"],
    }

    search_fields = [
        "name",
        "parent__name",
        "meta_name",
        "meta_description",
        "keyword",
    ]

    ordering_fields = [
        "name",
        "display_order",
        "created_at",
        "updated_at",
    ]

    ordering = ["display_order", "name"]  # Default ordering

    @swagger_auto_schema(
        tags=['Categories'],
        operation_id='list_categories',
        operation_summary="List Categories",
        operation_description="""
        Retrieve a list of categories with filtering, search, and ordering.

        ## Request Parameters:
        - Standard pagination parameters (page, page_size)
        - Filter parameters for precise filtering
        - Search parameter for text search
        - Ordering parameter for custom sorting

        ## Filters:
        - **`name`**: Filter by exact name or contains text
        - **`parent`**: Filter by parent ID or get root categories (parent=null)
        - **`is_featured`**: Filter featured categories (true/false)
        - **`slug`**: Filter by exact slug

        ## Search:
        Search across multiple fields with a single query:
        - Category name
        - Parent category name
        - Meta title and description
        - Keywords

        ## Ordering:
        Order results by any of the following:
        - name (alphabetical)
        - display_order (sequence number)
        - created_at (newest/oldest)
        - updated_at (recently updated)

        ## Response:
        List of category objects with complete metadata and hierarchy info.
        """,
        manual_parameters=[
            openapi.Parameter(
                'parent__isnull',
                openapi.IN_QUERY,
                description="Filter root categories (true) or subcategories \
                    (false)",
                type=openapi.TYPE_BOOLEAN,
            ),
        ],
        responses={
            200: openapi.Response(
                description="Success",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'count': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'next': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            format=openapi.FORMAT_URI,
                            nullable=True,
                        ),
                        'previous': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            format=openapi.FORMAT_URI,
                            nullable=True,
                        ),
                        'results': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_OBJECT),
                        ),
                    },
                ),
            ),
        },
    )
    def get(self, request, *args, **kwargs):
        """Retrieve categories with optional filtering, search, and ordering.

        This method handles GET requests for categories with support for:
        - Filtering on multiple fields
        - Text search across name and metadata
        - Custom ordering of results
        - Pagination of result sets

        Args:
        ----
            request: The HTTP request object containing query parameters
            *args: Variable length argument list passed to the parent method
            **kwargs: Arbitrary keyword arguments passed to the parent method

        Returns:
        -------
            Response: Paginated list of serialized categories
        """
        try:
            return super().get(request, *args, **kwargs)
        except Exception as e:
            logger.error(f"Error retrieving categories: {str(e)}")
            return Response(
                {"detail": "Error retrieving categories"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
