from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import OTP, Seller, SellerVerificationFile, User


@admin.register(User)
class CustomUserAdmin(BaseUserAdmin):
    """Admin configuration for the User model with enhanced management features.

    This admin config provides comprehensive user management with:
    - Bulk editing of key user fields
    - Advanced filtering and search
    - Profile image preview
    - Structured fieldsets by information category
    - Custom user creation form

    Features:
    - Direct image preview in list view
    - One-click role toggling
    - Advanced search across all key fields
    - Comprehensive filter options
    - Fieldsets organized by information type
    """

    # List display configuration
    list_display = (
        'email',
        'mobile',
        'get_full_name_display',
        'is_superuser',
        'is_active',
        'is_verified',
        'is_seller',
        'last_login',
        'created_at',
        'profile_image_preview',
    )

    list_display_links = (
        'email',
        'mobile',
        'profile_image_preview',
    )

    # Bulk editable fields
    list_editable = (
        'is_superuser',
        'is_active',
        'is_verified',
    )

    # Search and filter configuration
    search_fields = (
        'email',
        'mobile',
        'name',
    )
    list_filter = (
        'is_superuser',
        'is_active',
        'is_staff',
        'created_at',
    )

    # Sorting configuration
    ordering = ('-created_at',)

    # Read-only fields
    readonly_fields = (
        'created_at',
        'updated_at',
        'profile_image_preview',
        'last_login',
        'id',
    )

    # Date hierarchy for navigation
    date_hierarchy = 'created_at'

    # Fieldsets for editing existing users
    fieldsets = (
        (
            _('Personal Information'),
            {
                'fields': (
                    'id',
                    'name',
                    'email',
                    'mobile',
                    'profile_image',
                    'profile_image_preview',
                )
            },
        ),
        (
            _('Permissions & Roles'),
            {
                'fields': (
                    'is_active',
                    'is_staff',
                    'is_superuser',
                    'user_permissions',
                )
            },
        ),
        (
            _('Account Security'),
            {
                'fields': (
                    'password',
                    'last_login',
                )
            },
        ),
        (_('Timestamps'), {'fields': ('created_at', 'updated_at')}),
    )

    # Fieldsets for adding new users
    add_fieldsets = (
        (
            _('Create New User'),
            {
                'classes': ('wide',),
                'fields': (
                    'email',
                    'mobile',
                    'name',
                    'password1',
                    'password2',
                    'is_active',
                    'is_superuser',
                    'is_staff',
                ),
            },
        ),
    )

    def profile_image_preview(self, obj):
        """Display a preview of the user's profile image in admin interface.

        Args:
        ----
            obj (User): User instance

        Returns:
        -------
            str: HTML for image display or placeholder text
        """
        if obj.profile_image:
            return format_html(
                '<img src="{}" style="height:40px; width:40px; '
                'border-radius:50%; object-fit:cover;" />',
                obj.profile_image.url,
            )
        return format_html(
            '<div style="height:40px; width:40px; border-radius:50%; '
            'background-color:#e0e0e0; display:flex; justify-content:center; '
            'align-items:center; color:#666;">N/A</div>'
        )

    profile_image_preview.short_description = _('Profile')

    def get_full_name_display(self, obj):
        """Display user's full name or placeholder if not available.

        Args:
        ----
            obj (User): User instance

        Returns:
        -------
            str: Full name or placeholder
        """
        full_name = obj.name
        if full_name and full_name != obj.email:
            return full_name
        return "-"

    get_full_name_display.short_description = _('Full Name')

    def get_queryset(self, request):
        """Override get_queryset to optimize database queries.

        Args:
        ----
            request: The HTTP request

        Returns:
        -------
            QuerySet: Optimized queryset with prefetched related data
        """
        qs = super().get_queryset(request)

        # Prefetch related data to reduce database queries
        # Adjust based on your actual model relationships
        # qs = qs.prefetch_related('user_permissions')

        return qs

    def has_delete_permission(self, request, obj=None):
        """Control delete permissions based on user role.

        Args:
        ----
            request: The HTTP request
            obj (User, optional): The user object

        Returns:
        -------
            bool: Whether the admin has delete permission
        """
        # Prevent deletion of own account
        if obj and obj == request.user:
            return False
        return super().has_delete_permission(request, obj)

    def get_readonly_fields(self, request, obj=None):
        """Dynamically set readonly fields based on user and object.

        Args:
        ----
            request: The HTTP request
            obj (User, optional): The user object being edited

        Returns:
        -------
            tuple: Fields that should be read-only
        """
        readonly_fields = list(self.readonly_fields)

        # If editing superuser and current user is not superuser
        if obj and obj.is_superuser and not request.user.is_superuser:
            readonly_fields.extend(['is_superuser', 'is_staff'])

        # If editing own account, prevent self-demotion
        if obj and obj == request.user:
            readonly_fields.extend(['is_active', 'is_superuser', 'is_staff'])

        return tuple(readonly_fields)


# Unregister Group model from admin
admin.site.unregister(Group)


@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    """Admin configuration for OTP model."""

    list_display = [
        'identifier',
        'type',
        'purpose',
        'otp',
        'is_verified',
        'attempts',
        'created_at',
        'expires_at',
    ]
    list_filter = ['type', 'purpose', 'is_verified', 'created_at']
    search_fields = ['identifier', 'otp']
    readonly_fields = ['created_at', 'expires_at']
    fieldsets = (
        (
            'Basic Information',
            {'fields': ('identifier', 'type', 'purpose', 'otp')},
        ),
        (
            'Verification Status',
            {'fields': ('is_verified', 'attempts', 'max_attempts')},
        ),
        ('Timestamps', {'fields': ('created_at', 'expires_at')}),
    )


admin.site.register(Seller)
admin.site.register(SellerVerificationFile)
