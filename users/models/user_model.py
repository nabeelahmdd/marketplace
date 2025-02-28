from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _

from core.models import BaseModel
from utils import validate_phone_number


class CustomUserManager(BaseUserManager):
    """Custom user model manager where email is the unique identifier for
    authentication.

    This manager overrides the default Django user manager to use email
    instead of username as the primary identifier for user authentication and
    creation processes.

    Implements specialized methods for:
    - Creating standard users with email-based authentication
    - Creating superusers with administrative privileges
    - Handling proper email normalization
    - Setting appropriate default permissions
    """

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a user with the given email and password.

        Args:
        ----
            email (str): User's email address (required)
            password (str, optional): User's password
            **extra_fields: Additional fields to be saved in the User model

        Returns:
        -------
            User: The created user instance

        Raises:
        ------
            ValueError: If email is not provided
        """
        if not email:
            raise ValueError(_("Email must be set"))

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and save a SuperUser with the given email and password.

        Args:
        ----
            email (str): SuperUser's email address (required)
            password (str, optional): SuperUser's password
            **extra_fields: Additional fields to be saved in the User model

        Returns:
        -------
            User: The created superuser instance

        Raises:
        ------
            ValueError: If staff or superuser status is not True
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault(
            "is_super_admin", True
        )  # Set super_admin flag for superusers

        if not extra_fields["is_staff"]:
            raise ValueError(_("Superuser must have is_staff=True."))
        if not extra_fields["is_superuser"]:
            raise ValueError(_("Superuser must have is_superuser=True."))

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser, BaseModel):
    """Custom User model using email as the primary identifier.

    This model extends Django's AbstractUser and replaces username-based auth
    with email-based authentication. It includes comprehensive user profile
    fields and role-based permission flags for access control.

    ## Core Features:
    - Email-based authentication (no username field)
    - Mobile number as secondary identifier
    - Profile information storage with optional fields
    - Role-based access control flags
    - Security tracking for authentication events

    ## Field Categories:
    - Authentication fields: email, mobile, country_code
    - Profile fields: first_name, last_name, profile_pic, gender, dob
    - Role flags: is_super_admin, is_seller
    - Security fields: is_password_reset_link_sent, last_login_ip
    - System fields: created_on, updated_on, is_active

    ## Notes:
    - Both email and mobile are indexed for performance
    - Mobile number requires country_code for full phone number
    - Extends Django's built-in authentication framework
    - Profile completeness can be checked with is_complete_profile
    """

    objects = CustomUserManager()

    GENDER_CHOICES = (
        ("M", _("Male")),
        ("F", _("Female")),
        ("O", _("Other")),
        ("P", _("Prefer not to say")),
    )

    username = None  # Remove default username field
    first_name = models.CharField(
        _("First name"),
        max_length=128,
        null=True,
        blank=True,
        help_text=_("User's first name"),
    )
    last_name = models.CharField(
        _("Last name"),
        max_length=128,
        null=True,
        blank=True,
        help_text=_("User's last name"),
    )
    profile_pic = models.ImageField(
        _("Profile picture"),
        upload_to="profile_pics/%Y/%m/",  # Organize by year/month
        null=True,
        blank=True,
        help_text=_("User's profile picture"),
    )

    country_code = models.CharField(
        _("Country code"),
        max_length=10,
        null=True,
        blank=True,
        help_text=_("Country code for mobile number (e.g., +1, +91)"),
    )
    mobile = models.CharField(
        _("Mobile number"),
        max_length=20,
        unique=True,
        validators=[validate_phone_number],
        null=True,
        blank=True,
        help_text=_("Primary mobile number used for authentication"),
    )
    email = models.EmailField(
        _("Email address"),
        unique=True,
        db_index=True,
        help_text=_("Email address for login and communication"),
    )
    gender = models.CharField(
        _("Gender"),
        max_length=1,
        choices=GENDER_CHOICES,
        null=True,
        blank=True,
        help_text=_("User's gender"),
    )
    dob = models.DateField(
        _("Date of Birth"),
        null=True,
        blank=True,
        help_text=_("User's date of birth"),
    )

    # Role-based fields
    is_super_admin = models.BooleanField(
        _("Super admin status"),
        default=False,
        help_text=_("Designates whether the user has super admin privileges"),
    )
    is_seller = models.BooleanField(
        _("Seller status"),
        default=False,
        help_text=_("Designates whether the user is a seller"),
    )
    cr_by_self = models.BooleanField(
        _("Self-created account"),
        default=False,
        help_text=_("Indicates if the user created their own account"),
    )
    is_password_reset_link_sent = models.BooleanField(
        _("Password reset link sent"),
        default=False,
        help_text=_("Flag indicating if a password reset link has been sent"),
    )
    last_login_ip = models.GenericIPAddressField(
        _("Last login IP"),
        null=True,
        blank=True,
        help_text=_("IP address of the user's last login"),
    )
    account_verified = models.BooleanField(
        _("Account verified"),
        default=False,
        help_text=_("Indicates if the user's account has been verified"),
    )

    # Set email as the primary authentication field
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["mobile"]  # Mobile is required but not primary

    class Meta:
        verbose_name = _("user")
        verbose_name_plural = _("users")
        indexes = [
            models.Index(fields=["email"], name="email_idx"),
            models.Index(fields=["mobile"], name="mobile_idx"),
            models.Index(fields=["created_on"], name="user_created_idx"),
        ]
        ordering = ["-created_on"]  # Assuming BaseModel has created_on

    def __str__(self):
        """String representation of the user."""
        return f"{self.get_full_name()} ({self.email})"

    def get_full_name(self):
        """Returns the user's full name.

        Returns
        -------
            str: First name and last name, with a space in between
        """
        return (
            f"{self.first_name or ''} {self.last_name or ''}".strip()
            or self.email
        )

    def get_short_name(self):
        """Returns the user's short name.

        Returns
        -------
            str: The user's first name if available, otherwise email
        """
        return f"{self.first_name or self.email}"

    def has_perm(self, perm, obj=None):
        """Check if the user has a specific permission.

        Super admins automatically have all permissions.

        Args:
        ----
            perm (str): The permission to check
            obj (Model, optional): The object to check permissions against

        Returns:
        -------
            bool: True if the user has the permission, False otherwise
        """
        # Super admins have all permissions
        if self.is_super_admin:
            return True
        # Otherwise use the default permission system
        return super().has_perm(perm, obj)

    @property
    def is_complete_profile(self):
        """Check if the user has completed their profile.

        Returns
        -------
            bool: True if all required profile fields are filled
        """
        return bool(
            self.first_name
            and self.last_name
            and self.mobile
            and self.country_code
        )
