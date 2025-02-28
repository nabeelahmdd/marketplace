from django.contrib import admin
from django.utils.html import format_html

from .models import Banner


@admin.register(Banner)
class BannerAdmin(admin.ModelAdmin):
    """Admin configuration for the Banner model with bulk edit support."""

    list_display = (
        'title',
        'subtitle',
        'image_preview',
        'url',
        'is_active',
        'is_deleted',
        'created_by',
        'updated_by',
        'created_on',
    )
    search_fields = (
        'title',
        'subtitle',
        'url',
        'created_by__email',
        'updated_by__email',
    )
    list_filter = ('is_active', 'is_deleted', 'created_on')
    ordering = ('-created_on',)
    readonly_fields = (
        'created_on',
        'updated_on',
        'image_preview',
        'created_by',
        'updated_by',
    )

    fieldsets = (
        (
            'Banner Details',
            {'fields': ('title', 'subtitle', 'image', 'image_preview', 'url')},
        ),
        (
            'Status & Ownership',
            {'fields': ('is_active', 'is_deleted', 'created_by', 'updated_by')},
        ),
        ('Timestamps', {'fields': ('created_on', 'updated_on')}),
    )

    # Enable bulk editing in list view
    list_editable = ('is_active', 'is_deleted')

    def image_preview(self, obj):
        """Display a preview of the banner image in Django Admin."""
        if obj.image:
            return format_html(
                '''<img src="{}"
                style="height:50px; width:auto; border-radius:5px;" />''',
                obj.image.url,
            )
        return "-"

    image_preview.short_description = 'Image Preview'
