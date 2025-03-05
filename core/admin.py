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
        'created_at',
    )
    search_fields = (
        'title',
        'subtitle',
        'url',
    )
    list_filter = ('is_active', 'is_deleted', 'created_at')
    ordering = ('-created_at',)
    readonly_fields = (
        'created_at',
        'updated_at',
        'image_preview',
    )

    fieldsets = (
        (
            'Banner Details',
            {'fields': ('title', 'subtitle', 'image', 'image_preview', 'url')},
        ),
        (
            'Status & Ownership',
            {'fields': ('is_active', 'is_deleted')},
        ),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
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
