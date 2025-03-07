from django.contrib import admin
from django.utils.html import format_html

from .models import (
    Category,
    Comment,
    Favorite,
    Listing,
    ListingImage,
    Rating,
    RecommendedListing,
    SavedSearch,
    SearchQuery,
    Tag,
)


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    """Admin configuration for the Category model with search and bulk
    editing support.
    """

    list_display = (
        'name',
        'parent_name',
        'is_featured',
        'image_preview',
        'created_at',
        'is_deleted',
    )
    list_display_links = ('name',)  # Keeps the name clickable
    list_editable = (
        'is_featured',
        'is_deleted',
    )  # Allows bulk editing of featured status

    search_fields = (
        'name',
        'slug',
        'keyword',
        'meta_name',
        'meta_description',
    )  # Enables search functionality
    list_filter = (
        'is_featured',
        'created_at',
        'is_deleted',
    )  # Filter options in admin
    ordering = ('name',)
    readonly_fields = ('created_at', 'updated_at', 'image_preview')

    fieldsets = (
        (
            'Category Details',
            {
                'fields': (
                    'name',
                    'slug',
                    'parent',
                    'is_featured',
                    'image',
                    'image_preview',
                    'is_deleted',
                )
            },
        ),
        (
            'SEO & Metadata',
            {'fields': ('keyword', 'meta_name', 'meta_description')},
        ),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )

    prepopulated_fields = {"slug": ("name",)}  # Auto-fills slug from name
    autocomplete_fields = [
        'parent'
    ]  # Enables search in parent category dropdown

    def image_preview(self, obj):
        """Displays a preview of the category image in Django Admin."""
        if obj.image:
            return format_html(
                '''<img src="{}" style="height:50px; width:auto;
                border-radius:5px;" />''',
                obj.image.url,
            )
        return "-"

    image_preview.short_description = 'Image Preview'


@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    """Admin configuration for the Tag model with search and bulk
    editing support.
    """

    list_display = (
        'name',
        'slug',
        'created_at',
        'is_deleted',
    )  # Displays in list view
    list_display_links = ('name',)  # Name is clickable
    list_editable = (
        'slug',
        'is_deleted',
    )  # Allows bulk editing of slug
    search_fields = ('name', 'slug')  # Enables search by tag name and slug
    ordering = ('name',)
    list_filter = (
        'created_at',
        'is_deleted',
    )  # Allows filtering by created date
    readonly_fields = ('created_at', 'updated_at')  # Prevents accidental edits
    prepopulated_fields = {"slug": ("name",)}  # Auto-fills slug from name

    fieldsets = (
        ('Tag Details', {'fields': ('name', 'slug')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )


@admin.register(Listing)
class ListingAdmin(admin.ModelAdmin):
    """Django Admin configuration for the Listing model."""

    list_display = (
        'title',
        'seller',
        'category',
        'is_active',
        'is_featured',
        'status',
        'price',
        'image_preview',
        'created_at',
    )
    list_display_links = ('title',)  # Title is clickable to edit
    list_editable = (
        'status',
        'is_active',
        'is_featured',
    )  # ✅ Ensure it's a tuple

    search_fields = (
        'title',
        'seller__user__name',
        'category__name',
    )  # ✅ Ensures search works
    list_filter = ('status', 'category', 'created_at')
    ordering = ('-created_at',)
    readonly_fields = (
        'created_at',
        'updated_at',
        'image_preview',
    )  # ✅ Removed `slug`

    fieldsets = (
        (
            'Listing Details',
            {
                'fields': (
                    'title',
                    'description',
                    'price',
                    'price_negotiable',
                    'currency',
                    'category',
                    'seller',
                    'status',
                    'condition',
                )
            },
        ),
        (
            'Location Details',
            {'fields': ('address', 'city', 'state', 'postal_code', 'country')},
        ),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
        ('Images', {'fields': ('image_preview',)}),
        (
            'Tracking',
            {
                'fields': (
                    'view_count',
                    'favorite_count',
                    'search_appearance_count',
                )
            },
        ),
    )

    prepopulated_fields = (
        {}
    )  # ✅ Removed `prepopulated_fields` because `slug` is not available

    def image_preview(self, obj):
        """Displays the first image of the listing in Django Admin."""
        first_image = obj.images.first()  # Fetch first image
        if first_image:
            return format_html(
                '<img src="{}" style="height:50px; width:auto; \
                    border-radius:5px;" />',
                first_image.image.url,
            )
        return "-"

    image_preview.short_description = 'Image Preview'


admin.site.register(ListingImage)
admin.site.register(Favorite)
admin.site.register(Comment)
admin.site.register(Rating)
admin.site.register(SearchQuery)
admin.site.register(SavedSearch)
admin.site.register(RecommendedListing)
