from django.db import models
from django.utils.translation import gettext_lazy as _

from core.models import BaseModel


class Banner(BaseModel):
    """Model representing a homepage promotional banner.

    This model stores information about banners displayed on the website
    homepage or other promotional areas, including title, subtitle, image, and
    redirect URL.

    ## Fields:
    - title: Optional main heading text
    - subtitle: Optional secondary descriptive text
    - image: Required banner image
    - url: Optional redirect link when banner is clicked
    - is_active: Flag to control banner visibility
    - display_order: Controls the sequence of multiple banners

    ## Usage:
    - Used to create dynamic promotional content on the website
    - Can be managed through admin interface
    - Multiple banners can be active simultaneously
    - Display order determines presentation sequence

    ## Notes:
    - Extends BaseModel for creation/update tracking
    - Supports soft deletion
    - Optimized image field uses dedicated storage path
    """

    title = models.CharField(
        _("Title"),
        max_length=255,
        null=True,
        blank=True,
        help_text=_("Main title displayed on the banner."),
    )

    subtitle = models.CharField(
        _("Subtitle"),
        max_length=255,
        null=True,
        blank=True,
        help_text=_(
            "Short subtitle or descriptive text displayed below the \
            title."
        ),
    )

    image = models.ImageField(
        _("Banner Image"),
        upload_to="banners/%Y/%m/",
        help_text=_("Banner image (recommended size: 1200x500px)."),
    )

    url = models.URLField(
        _("Redirect URL"),
        max_length=255,
        null=True,
        blank=True,
        default="/shop-grid-standard",
        help_text=_("URL where the banner redirects when clicked."),
    )

    is_active = models.BooleanField(
        _("Active Status"),
        default=True,
        help_text=_(
            "Controls whether this banner is currently displayed on \
            the site."
        ),
    )

    display_order = models.PositiveIntegerField(
        _("Display Order"),
        default=0,
        help_text=_(
            "Controls the order in which banners are displayed \
            (lower numbers shown first)."
        ),
    )

    class Meta:
        ordering = ["display_order", "-created_at"]
        verbose_name = _("Banner")
        verbose_name_plural = _("Banners")
        indexes = [
            models.Index(fields=["is_active"], name="banner_active_idx"),
            models.Index(fields=["display_order"], name="banner_order_idx"),
        ]

    def __str__(self):
        """Return a string representation of the banner."""
        if self.title:
            return self.title
        return f"Banner {self.id}"

    def save(self, *args, **kwargs):
        """Override save method to ensure proper data handling."""
        # Ensure URLs starting with / are preserved, otherwise ensure proper
        # URL format
        if (
            self.url
            and not self.url.startswith('/')
            and not self.url.startswith('http')
        ):
            self.url = f"/{self.url.lstrip('/')}"

        super().save(*args, **kwargs)
