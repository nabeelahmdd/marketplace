from django.db import models
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _

from core.models import BaseModel


class Tag(BaseModel):
    """Model representing tags for categorizing products or content.

    Tags provide a flexible way to classify items across different categories,
    enabling efficient filtering, searching, and content organization.

    ## Fields:
    - name: Unique tag identifier
    - slug: SEO-friendly URL representation
    - is_active: Controls tag visibility

    ## Usage:
    - Used to create flexible cross-category classifications
    - Allows for filtering products by attributes or themes
    - Supports searchable content organization
    - Can be applied to multiple content types (products, posts, etc.)

    ## Notes:
    - Extends BaseModel for creation/update tracking
    - Supports soft deletion
    - Automatically generates slugs from names if not provided
    - Maintains uniqueness across active and deleted tags
    """

    name = models.CharField(
        _("Tag Name"),
        max_length=100,
        unique=True,
        help_text=_("Tag name (e.g., Sale, New Arrival, Eco-friendly)."),
    )

    slug = models.SlugField(
        _("URL Slug"),
        max_length=120,
        unique=True,
        null=True,
        blank=True,
        help_text=_("SEO-friendly URL slug (auto-generated if blank)."),
    )

    is_active = models.BooleanField(
        _("Active"),
        default=True,
        help_text=_("Whether this tag is active and visible to users."),
    )

    class Meta:
        ordering = ["name"]
        verbose_name = _("Tag")
        verbose_name_plural = _("Tags")
        indexes = [
            models.Index(fields=["name"], name="tag_name_idx"),
            models.Index(fields=["slug"], name="tag_slug_idx"),
            models.Index(fields=["is_active"], name="tag_active_idx"),
        ]

    def __str__(self):
        """Return a string representation of the tag."""
        return self.name

    def save(self, *args, **kwargs):
        """Override save method to generate slug automatically."""
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)
