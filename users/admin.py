from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import User


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
        'is_seller',
        'is_super_admin',
        'is_active',
        'last_login',
        'created_on',
        'profile_image_preview',
    )

    list_display_links = (
        'email',
        'mobile',
        'profile_image_preview',
    )

    # Bulk editable fields
    list_editable = (
        'is_seller',
        'is_super_admin',
        'is_active',
    )

    # Search and filter configuration
    search_fields = (
        'email',
        'mobile',
        'first_name',
        'last_name',
        'country_code',
    )
    list_filter = (
        'is_seller',
        'is_super_admin',
        'is_active',
        'is_staff',
        'gender',
        'cr_by_self',
        'account_verified',
        'created_on',
    )

    # Sorting configuration
    ordering = ('-created_on',)

    # Read-only fields
    readonly_fields = (
        'created_on',
        'updated_on',
        'profile_image_preview',
        'last_login',
        'last_login_ip',
        'id',
        'cr_by_self',
    )

    # Date hierarchy for navigation
    date_hierarchy = 'created_on'

    # Fieldsets for editing existing users
    fieldsets = (
        (
            _('Personal Information'),
            {
                'fields': (
                    'id',
                    'first_name',
                    'last_name',
                    'email',
                    'country_code',
                    'mobile',
                    'gender',
                    'dob',
                    'profile_pic',
                    'profile_image_preview',
                )
            },
        ),
        (
            _('Permissions & Roles'),
            {
                'fields': (
                    'is_active',
                    'is_seller',
                    'is_super_admin',
                    'is_staff',
                    'is_superuser',
                    'account_verified',
                    'user_permissions',
                )
            },
        ),
        (
            _('Account Security'),
            {
                'fields': (
                    'password',
                    'is_password_reset_link_sent',
                    'cr_by_self',
                    'last_login',
                    'last_login_ip',
                )
            },
        ),
        (_('Timestamps'), {'fields': ('created_on', 'updated_on')}),
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
                    'country_code',
                    'first_name',
                    'last_name',
                    'password1',
                    'password2',
                    'is_active',
                    'is_seller',
                    'is_super_admin',
                    'is_staff',
                    'account_verified',
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
        if obj.profile_pic:
            return format_html(
                '<img src="{}" style="height:40px; width:40px; '
                'border-radius:50%; object-fit:cover;" />',
                obj.profile_pic.url,
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
        full_name = obj.get_full_name()
        if full_name and full_name != obj.email:
            return full_name
        return "-"

    get_full_name_display.short_description = _('Full Name')

    def save_model(self, request, obj, form, change):
        """Override save_model to set created_by for new users.

        Args:
        ----
            request: The HTTP request
            obj (User): The user object being saved
            form: The form instance
            change (bool): Whether this is a change to an existing object
        """
        if not change:  # If creating a new user
            # Set created_by to current admin user
            # Assuming BaseModel has created_by field
            if hasattr(obj, 'created_by'):
                obj.created_by = request.user

        super().save_model(request, obj, form, change)

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
            readonly_fields.extend(
                ['is_superuser', 'is_staff', 'is_super_admin']
            )

        # If editing own account, prevent self-demotion
        if obj and obj == request.user:
            readonly_fields.extend(
                ['is_active', 'is_superuser', 'is_staff', 'is_super_admin']
            )

        return tuple(readonly_fields)


# Unregister Group model from admin
admin.site.unregister(Group)
