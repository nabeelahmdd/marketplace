from rest_framework import permissions


class IsSellerPermission(permissions.BasePermission):
    """Custom permission to allow only sellers to create, edit,
    and delete listings.
    """

    def has_permission(self, request, view):
        # Ensure the user is authenticated and has a seller profile
        return request.user.is_authenticated and hasattr(
            request.user, 'is_seller'
        )

    def has_object_permission(self, request, view, obj):
        """Only allow the owner (seller) to modify their own listing."""
        return obj.seller == request.user.seller  # Compare with seller profile
