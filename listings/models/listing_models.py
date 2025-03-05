import uuid

from django.contrib.gis.db.models import PointField
from django.db import models
from django.utils import timezone
from django.utils.text import slugify

from core.models import BaseModel
from listings.models import Category
from users.models import Seller


def generate_unique_slug(instance, new_slug=None):
    """Generate a unique slug using the title and a short UUID if needed."""
    slug = new_slug if new_slug else slugify(instance.title)
    ModelClass = instance.__class__

    # Check if the slug already exists
    if ModelClass.objects.filter(slug=slug).exists():
        unique_id = str(uuid.uuid4())[:8]  # Short UUID
        slug = f"{slug}-{unique_id}"

    return slug


class Listing(BaseModel):
    """Base model for all marketplace listings"""

    class ConditionChoices(models.TextChoices):
        NEW = 'new', 'New'
        LIKE_NEW = 'like_new', 'Like New'
        GOOD = 'good', 'Good'
        FAIR = 'fair', 'Fair'
        POOR = 'poor', 'Poor'

    class StatusChoices(models.TextChoices):
        DRAFT = 'draft', 'Draft'
        ACTIVE = 'active', 'Active'
        PENDING = 'pending', 'Pending Approval'
        SUSPENDED = 'suspended', 'Suspended'
        EXPIRED = 'expired', 'Expired'
        SOLD = 'sold', 'Sold'
        ARCHIVED = 'archived', 'Archived'

    # Basic listing info
    title = models.CharField(max_length=255)
    slug = models.SlugField(unique=True, max_length=255, blank=True)
    description = models.TextField()
    price = models.DecimalField(max_digits=12, decimal_places=2)
    price_negotiable = models.BooleanField(default=False)
    currency = models.CharField(max_length=3, default='USD')

    # Categories and seller
    category = models.ForeignKey(
        Category, on_delete=models.PROTECT, related_name='listings'
    )
    seller = models.ForeignKey(
        Seller, on_delete=models.PROTECT, related_name='listings'
    )  # Changed from Seller

    # Status and visibility
    status = models.CharField(
        max_length=20,
        choices=StatusChoices.choices,
        default=StatusChoices.DRAFT,
    )
    condition = models.CharField(
        max_length=20,
        choices=ConditionChoices.choices,
        default=ConditionChoices.NEW,
    )

    # Location
    location = PointField(null=True, blank=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    state = models.CharField(max_length=100, blank=True, null=True)
    postal_code = models.CharField(max_length=20, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)

    # Tracking metrics
    view_count = models.PositiveIntegerField(default=0)
    favorite_count = models.PositiveIntegerField(default=0)
    search_appearance_count = models.PositiveIntegerField(default=0)

    # Publication schedule
    published_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['category', 'status']),
            models.Index(fields=['seller', 'status']),
            models.Index(fields=['published_at']),
        ]

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = generate_unique_slug(self)

        # Auto-set published_at
        if self.status == self.StatusChoices.ACTIVE and not self.published_at:
            self.published_at = timezone.now()

        # Expiry should be configurable
        if self.published_at and not self.expires_at:
            EXPIRY_DAYS = 30  # Move this to Django settings later
            self.expires_at = self.published_at + timezone.timedelta(
                days=EXPIRY_DAYS
            )

        super().save(*args, **kwargs)

    def increment_view_count(self):
        """Efficiently increment the view count"""
        self.__class__.objects.filter(id=self.id).update(
            view_count=models.F('view_count') + 1
        )

    def update_favorite_count(self):
        """Update the favorite count based on actual favorites"""
        self.favorite_count = self.favorites.filter(is_active=True).count()
        self.save(update_fields=['favorite_count', 'updated_at'])


class ListingImage(models.Model):
    """Images for listings with ordering"""

    listing = models.ForeignKey(
        Listing, on_delete=models.CASCADE, related_name='images'
    )
    image = models.ImageField(upload_to='listings/')
    alt_text = models.CharField(max_length=255, blank=True, null=True)
    is_primary = models.BooleanField(default=False)
    order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['order', 'created_at']

    def __str__(self):
        return f"Image for {self.listing.title}"

    def save(self, *args, **kwargs):
        """Ensure only one primary image per listing and set a default primary \
        if none exists
        """
        if self.is_primary:
            ListingImage.objects.filter(
                listing=self.listing, is_primary=True
            ).update(is_primary=False)

        super().save(*args, **kwargs)

        # Ensure at least one primary image exists
        if not ListingImage.objects.filter(
            listing=self.listing, is_primary=True
        ).exists():
            first_image = (
                ListingImage.objects.filter(listing=self.listing)
                .order_by('created_at')
                .first()
            )
            if first_image:
                first_image.is_primary = True
                first_image.save(update_fields=['is_primary'])


class PropertyListing(models.Model):
    """Additional fields for property listings"""

    PROPERTY_TYPE_CHOICES = [
        ('house', 'House'),
        ('apartment', 'Apartment'),
        ('villa', 'Villa'),
        ('land', 'Land'),
        ('commercial', 'Commercial'),
        ('other', 'Other'),
    ]

    OFFER_TYPE_CHOICES = [
        ('sale', 'For Sale'),
        ('rent', 'For Rent'),
    ]

    listing = models.OneToOneField(
        Listing, on_delete=models.CASCADE, related_name='property_details'
    )
    property_type = models.CharField(
        max_length=20, choices=PROPERTY_TYPE_CHOICES
    )
    offer_type = models.CharField(max_length=10, choices=OFFER_TYPE_CHOICES)
    size = models.DecimalField(
        max_digits=10, decimal_places=2, help_text='Size in square meters'
    )
    bedrooms = models.PositiveSmallIntegerField(blank=True, null=True)
    bathrooms = models.PositiveSmallIntegerField(blank=True, null=True)
    furnished = models.BooleanField(default=False)
    parking_spaces = models.PositiveSmallIntegerField(blank=True, null=True)
    year_built = models.PositiveIntegerField(blank=True, null=True)

    def __str__(self):
        return f"{self.get_property_type_display()} \
            for {self.get_offer_type_display()}"


class VehicleListing(models.Model):
    """Additional fields for vehicle listings"""

    TRANSMISSION_CHOICES = [
        ('manual', 'Manual'),
        ('automatic', 'Automatic'),
        ('semi_auto', 'Semi-Automatic'),
    ]

    FUEL_TYPE_CHOICES = [
        ('petrol', 'Petrol'),
        ('diesel', 'Diesel'),
        ('electric', 'Electric'),
        ('hybrid', 'Hybrid'),
        ('other', 'Other'),
    ]

    listing = models.OneToOneField(
        Listing, on_delete=models.CASCADE, related_name='vehicle_details'
    )
    make = models.CharField(max_length=100)
    model = models.CharField(max_length=100)
    year = models.PositiveIntegerField()
    mileage = models.PositiveIntegerField(help_text='Mileage in kilometers')
    transmission = models.CharField(max_length=20, choices=TRANSMISSION_CHOICES)
    fuel_type = models.CharField(max_length=20, choices=FUEL_TYPE_CHOICES)
    engine_size = models.DecimalField(
        max_digits=4, decimal_places=1, blank=True, null=True
    )
    doors = models.PositiveSmallIntegerField(blank=True, null=True)
    color = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return f"{self.year} {self.make} {self.model}"


class JobListing(models.Model):
    """Additional fields for job listings"""

    JOB_TYPE_CHOICES = [
        ('full_time', 'Full Time'),
        ('part_time', 'Part Time'),
        ('contract', 'Contract'),
        ('temporary', 'Temporary'),
        ('internship', 'Internship'),
    ]

    EXPERIENCE_CHOICES = [
        ('entry', 'Entry Level'),
        ('mid', 'Mid Level'),
        ('senior', 'Senior Level'),
        ('executive', 'Executive'),
    ]

    listing = models.OneToOneField(
        Listing, on_delete=models.CASCADE, related_name='job_details'
    )
    company_name = models.CharField(max_length=255)
    job_type = models.CharField(max_length=20, choices=JOB_TYPE_CHOICES)
    experience_level = models.CharField(
        max_length=20, choices=EXPERIENCE_CHOICES
    )
    salary_min = models.DecimalField(
        max_digits=12, decimal_places=2, blank=True, null=True
    )
    salary_max = models.DecimalField(
        max_digits=12, decimal_places=2, blank=True, null=True
    )
    salary_period = models.CharField(
        max_length=20,
        choices=[
            ('hourly', 'Hourly'),
            ('daily', 'Daily'),
            ('weekly', 'Weekly'),
            ('monthly', 'Monthly'),
            ('yearly', 'Yearly'),
        ],
        default='monthly',
    )
    remote_allowed = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.listing.title} at {self.company_name}"

    @property
    def salary_display(self):
        """Format salary range for display"""
        if not self.salary_min and not self.salary_max:
            return "Negotiable"
        elif self.salary_min and self.salary_max:
            return f"{self.salary_min:,} - {self.salary_max:,} per \
                {self.get_salary_period_display()}"
        elif self.salary_min:
            return f"From {self.salary_min:,} per \
                {self.get_salary_period_display()}"
        else:
            return f"Up to {self.salary_max:,} per \
                {self.get_salary_period_display()}"
