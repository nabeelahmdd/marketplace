from rest_framework import serializers

from listings.models import Category


class CategorySerializer(serializers.ModelSerializer):
    """Serializer for the Category model.

    Provides JSON representation of category data with related information.

    ## Fields:
    - Standard category fields (name, slug, image, etc.)
    - Parent category details with parent_name for display
    - Full path showing complete category hierarchy
    - SEO metadata for frontend rendering

    ## Features:
    - Read-only parent_name field for display purposes
    - Full category path for breadcrumb navigation
    - Complete SEO metadata for frontend use
    """

    # Additional read-only fields for related data
    parent_name = serializers.CharField(
        source="parent.name",
        read_only=True,
        help_text="Name of the parent category",
    )

    full_path = serializers.CharField(
        read_only=True, help_text="Full hierarchical path of the category"
    )

    subcategory_count = serializers.SerializerMethodField(
        help_text="Number of direct child categories"
    )
    subcategories = serializers.SerializerMethodField()

    class Meta:
        model = Category
        fields = [
            "id",
            "name",
            "slug",
            "image",
            "keyword",
            "meta_name",
            "meta_description",
            "parent",
            "parent_name",
            "full_path",
            "is_featured",
            "is_active",
            "display_order",
            "subcategory_count",
            "created_at",
            "updated_at",
            "subcategories",
        ]

    def get_subcategory_count(self, obj):
        """Get the number of direct child categories.

        Args:
        ----
            obj: Category instance

        Returns:
        -------
            int: Count of active subcategories
        """
        return obj.subcategories.filter(is_active=True).count()

    def get_subcategories(self, obj):
        """Recursively fetch child categories."""
        children = obj.subcategories.filter(is_active=True)
        return CategorySerializer(children, many=True).data
