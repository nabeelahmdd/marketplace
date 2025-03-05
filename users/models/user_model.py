from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.contrib.gis.db.models import PointField
from django.db import models
from django.utils import timezone

from core.models import BaseModel


# ============================
# CUSTOM USER MANAGEMENT
# ============================
class CustomUserManager(BaseUserManager):
    """Custom user model manager that supports authentication with either \
    email or mobile.
    """

    def create_user(
        self, name, password=None, email=None, mobile=None, **extra_fields
    ):
        """Create and return a user who can register using either email \
            or mobile.

        Args:
        ----
            name (str): Full name of the user.
            password (str, optional): User's password.
            email (str, optional): User's email (must be unique if provided).
            mobile (str, optional): User's mobile number\
                  (must be unique if provided).
            **extra_fields: Additional attributes for the user.

        Returns:
        -------
            User: The created user instance.

        Raises:
        ------
            ValueError: If neither email nor mobile is provided.
        """
        if not email and not mobile:
            raise ValueError("Either email or mobile must be provided.")

        if email:
            email = self.normalize_email(email)

        user = self.model(name=name, email=email, mobile=mobile, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(
        self, name, password, email=None, mobile=None, **extra_fields
    ):
        """Create and return a superuser with administrative privileges."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(
            name, password, email=email, mobile=mobile, **extra_fields
        )


class User(AbstractBaseUser, PermissionsMixin, BaseModel):
    """Custom User model that allows authentication with either email or mobile.

    Attributes
    ----------
    - `name` (CharField): Full name of the user.
    - `email` (EmailField, optional): Unique email identifier (nullable).
    - `mobile` (CharField, optional): Unique phone number identifier (nullable).
    - `profile_image` (ImageField): Optional profile image.
    - `location` (PointField): Geographical location.
    - `is_verified` (BooleanField): Verification status.
    - `is_seller` (BooleanField): Seller status flag.
    - `is_staff` (BooleanField): Admin panel access.
    - `date_joined` (DateTimeField): User registration timestamp.

    **One of `email` or `mobile` must be provided.**
    """

    name = models.CharField(max_length=150)
    email = models.EmailField(unique=True, null=True, blank=True)
    mobile = models.CharField(max_length=15, unique=True, null=True, blank=True)
    profile_image = models.ImageField(
        upload_to='users/profiles/', blank=True, null=True
    )
    location = PointField(blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_seller = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = CustomUserManager()

    # Authentication field (must be set dynamically)
    USERNAME_FIELD = 'email'  # Default to email
    REQUIRED_FIELDS = ['name']

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=(
                    models.Q(email__isnull=False)
                    | models.Q(mobile__isnull=False)
                ),
                name="user_email_or_mobile_required",
            )
        ]

    def __str__(self):
        return self.name or self.email or self.mobile

    @property
    def seller_profile(self):
        """Returns the associated Seller instance if the user is a seller"""
        return getattr(self, 'seller', None)


# ============================
# SELLER & VERIFICATION MODELS
# ============================
class Seller(BaseModel):
    """Model representing a seller in the marketplace.

    Attributes
    ----------
    - `user` (OneToOneField): Links to the User model.
    - `name` (CharField): Seller name.
    - `id_number` (CharField): National ID or government-issued ID.
    - `mobile` (CharField): Contact number.
    - `is_company` (BooleanField): Whether seller is an individual or company.
    - `owner_name` (CharField): For companies, owner's name.
    - `address` (CharField): Physical address of the seller.
    """

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='seller'
    )
    name = models.CharField(max_length=150, blank=True)
    id_number = models.CharField(max_length=150, blank=True)
    mobile = models.CharField(max_length=15, unique=True, blank=True, null=True)
    is_company = models.BooleanField(default=False)
    owner_name = models.CharField(max_length=150, blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.name or self.user.username


class SellerVerificationFile(BaseModel):
    """Verification documents uploaded by sellers.

    Attributes
    ----------
    - `seller` (ForeignKey): Reference to the seller.
    - `file` (FileField): Verification document.
    """

    seller = models.ForeignKey(
        Seller, on_delete=models.CASCADE, related_name='verification_files'
    )
    file = models.FileField(upload_to="seller/verification/")

    def __str__(self):
        return f"Verification File for \
            {self.seller.name or self.seller.user.username}"


class UserFollow(models.Model):
    """Track which users follow other users"""

    follower = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='following'
    )
    followed = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='followers'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('follower', 'followed')

    def __str__(self):
        return f"{self.follower.username} follows {self.followed.username}"


class UserDevice(models.Model):
    """Track user devices for push notifications"""

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='devices'
    )
    device_id = models.CharField(max_length=255)
    device_type = models.CharField(
        max_length=20,
        choices=[('ios', 'iOS'), ('android', 'Android'), ('web', 'Web')],
    )
    push_token = models.CharField(max_length=255, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'device_id')
