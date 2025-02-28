from django.contrib import admin
from django.utils.html import format_html

from .models import Category, Tag


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
        'created_on',
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
        'created_on',
        'is_deleted',
    )  # Filter options in admin
    ordering = ('name',)
    readonly_fields = ('created_on', 'updated_on', 'image_preview')

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
        ('Timestamps', {'fields': ('created_on', 'updated_on')}),
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
        'created_on',
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
        'created_on',
        'is_deleted',
    )  # Allows filtering by created date
    readonly_fields = ('created_on', 'updated_on')  # Prevents accidental edits
    prepopulated_fields = {"slug": ("name",)}  # Auto-fills slug from name

    fieldsets = (
        ('Tag Details', {'fields': ('name', 'slug')}),
        ('Timestamps', {'fields': ('created_on', 'updated_on')}),
    )
