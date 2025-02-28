from django.db import models
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _

from core.models import BaseModel


class Category(BaseModel):
    """Model representing product categories.

    This model supports a parent-child hierarchy for nested categories,
    along with SEO-friendly fields like slug, keywords, meta title, and
    description.

    ## Fields:
    - name: Unique category name
    - slug: SEO-friendly URL slug
    - image: Optional category image
    - keyword: SEO keywords for better search ranking
    - meta_name: SEO title for search engine results
    - meta_description: SEO description for search results
    - parent: Optional reference to parent category
    - is_featured: Flag for highlighting important categories
    - display_order: Controls presentation sequence

    ## Hierarchy:
    - Categories can have parent-child relationships
    - A category without a parent is a top-level category
    - Child categories are accessed via the 'subcategories' relation

    ## Usage:
    - Used to organize products into browsable sections
    - Supports multi-level nesting for complex categorization
    - Provides SEO optimization for category pages
    - Featured categories can be highlighted in the UI

    ## Notes:
    - Extends BaseModel for creation/update tracking
    - Supports soft deletion
    - Automatically generates slugs from names if not provided
    """

    name = models.CharField(
        _("Category Name"),
        max_length=100,
        unique=True,
        help_text=_("Name of the category (e.g., Electronics, Clothing)."),
    )

    slug = models.SlugField(
        _("URL Slug"),
        max_length=120,
        unique=True,
        null=True,
        blank=True,
        help_text=_("SEO-friendly URL slug (auto-generated if blank)."),
    )

    image = models.ImageField(
        _("Category Image"),
        upload_to="categories/%Y/%m/",
        null=True,
        blank=True,
        help_text=_("Optional image representing the category."),
    )

    keyword = models.CharField(
        _("SEO Keywords"),
        max_length=350,
        null=True,
        blank=True,
        help_text=_("SEO keywords for the category (comma-separated)."),
    )

    meta_name = models.CharField(
        _("Meta Title"),
        max_length=250,
        null=True,
        blank=True,
        help_text=_("SEO meta title for search engine visibility."),
    )

    meta_description = models.TextField(
        _("Meta Description"),
        max_length=500,
        null=True,
        blank=True,
        help_text=_("SEO meta description to improve search ranking."),
    )

    parent = models.ForeignKey(
        'self',
        verbose_name=_("Parent Category"),
        on_delete=models.RESTRICT,
        related_name="subcategories",
        null=True,
        blank=True,
        help_text=_("Parent category (if this is a sub-category)."),
    )

    is_featured = models.BooleanField(
        _("Featured"),
        default=False,
        help_text=_("Check if this category should be featured."),
    )

    display_order = models.PositiveIntegerField(
        _("Display Order"),
        default=0,
        help_text=_("Controls the display order (lower numbers first)."),
    )

    is_active = models.BooleanField(
        _("Active"),
        default=True,
        help_text=_("Whether this category is active and visible."),
    )

    class Meta:
        verbose_name = _("Category")
        verbose_name_plural = _("Categories")
        ordering = ["display_order", "name"]
        indexes = [
            models.Index(fields=["name"], name="category_name_idx"),
            models.Index(fields=["slug"], name="category_slug_idx"),
            models.Index(fields=["is_active"], name="category_active_idx"),
            models.Index(fields=["is_featured"], name="category_featured_idx"),
            models.Index(fields=["parent"], name="category_parent_idx"),
        ]

    def __str__(self):
        """Return a string representation of the category."""
        return self.name

    def save(self, *args, **kwargs):
        """Override save method to generate slug and handle data."""
        if not self.slug:
            self.slug = slugify(self.name)

        # Ensure meta name defaults to category name if not provided
        if not self.meta_name:
            self.meta_name = self.name

        super().save(*args, **kwargs)

    @property
    def parent_name(self):
        """Returns the name of the parent category or 'None' if no parent.

        Returns
        -------
            str: Parent category name or 'None'
        """
        return self.parent.name if self.parent else "None"

    @property
    def full_path(self):
        """Returns the full hierarchical path of the category.

        Returns
        -------
            str: Full category path (e.g., 'Electronics > Computers > Laptops')
        """
        if not self.parent:
            return self.name

        return f"{self.parent.full_path} > {self.name}"

    def get_all_subcategories(self):
        """Returns all subcategories recursively.

        Returns
        -------
            QuerySet: All subcategories at any level below this category
        """
        subcategories = list(self.subcategories.filter(is_active=True))

        for subcategory in list(subcategories):
            subcategories.extend(subcategory.get_all_subcategories())

        return subcategories
