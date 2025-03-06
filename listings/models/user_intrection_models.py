from django.contrib.gis.db.models import PointField
from django.db import models
from django.utils import timezone

from core.models import BaseModel
from listings.models import Category, Listing
from users.models import User


class Favorite(models.Model):
    """User favorites/saved listings"""

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='favorites'
    )
    listing = models.ForeignKey(
        Listing, on_delete=models.CASCADE, related_name='favorites'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ('user', 'listing')

    def __str__(self):
        return f"{self.user.username} favorites {self.listing.title}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Update the favorite count on the listing
        self.listing.update_favorite_count()


class Comment(BaseModel):
    """Comments on listings"""

    listing = models.ForeignKey(
        Listing, on_delete=models.CASCADE, related_name='comments'
    )
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='comments'
    )
    content = models.TextField()
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='replies',
    )
    is_approved = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Comment by {self.user.username} on {self.listing.title}"


class Rating(BaseModel):
    """User ratings for listings"""

    listing = models.ForeignKey(
        Listing, on_delete=models.CASCADE, related_name='ratings'
    )
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='ratings'
    )
    value = models.PositiveSmallIntegerField(
        choices=[(i, i) for i in range(1, 6)]
    )  # 1-5 stars
    review = models.TextField(blank=True, null=True)
    is_approved = models.BooleanField(default=True)

    class Meta:
        unique_together = ('user', 'listing')

    def __str__(self):
        return f"{self.user.username} rated {self.listing.title}: \
            {self.value} stars"


class Report(BaseModel):
    """User reports for listings or users"""

    REPORT_REASONS = [
        ('prohibited', 'Prohibited Item'),
        ('counterfeit', 'Counterfeit Item'),
        ('inappropriate', 'Inappropriate Content'),
        ('misleading', 'Misleading Information'),
        ('spam', 'Spam or Scam'),
        ('other', 'Other'),
    ]

    REPORT_STATUS = [
        ('pending', 'Pending Review'),
        ('investigating', 'Under Investigation'),
        ('resolved', 'Resolved'),
        ('rejected', 'Rejected'),
    ]

    reported_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='reports_filed'
    )
    listing = models.ForeignKey(
        Listing,
        on_delete=models.CASCADE,
        related_name='reports',
        null=True,
        blank=True,
    )
    reported_user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='reports_against',
        null=True,
        blank=True,
    )
    reason = models.CharField(max_length=20, choices=REPORT_REASONS)
    details = models.TextField()
    status = models.CharField(
        max_length=20, choices=REPORT_STATUS, default='pending'
    )
    admin_notes = models.TextField(blank=True, null=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_reports',
    )

    def __str__(self):
        if self.listing:
            return f"Report on listing {self.listing.title}"
        return f"Report on user {self.reported_user.username}"


class SearchQuery(models.Model):
    """Track user search queries"""

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='search_queries',
    )
    query_text = models.TextField()
    category = models.ForeignKey(
        Category, on_delete=models.SET_NULL, null=True, blank=True
    )

    # Filter data
    filters = models.JSONField(default=dict, blank=True)

    # Location data
    location_text = models.CharField(max_length=255, blank=True, null=True)
    coordinates = PointField(null=True, blank=True)
    radius = models.FloatField(null=True, blank=True)

    # Results
    result_count = models.IntegerField(default=0)

    # Session info
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    session_id = models.CharField(max_length=255, blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['query_text']),
        ]

    def __str__(self):
        return f"Search: {self.query_text[:50]}"


class SavedSearch(BaseModel):
    """User-saved searches for alerts"""

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='saved_searches'
    )
    search_query = models.ForeignKey(
        SearchQuery, on_delete=models.CASCADE, related_name='saved_by'
    )
    name = models.CharField(max_length=255)

    # Alert settings
    alert_enabled = models.BooleanField(default=True)
    alert_frequency = models.CharField(
        max_length=20,
        choices=[
            ('instant', 'Instant'),
            ('daily', 'Daily'),
            ('weekly', 'Weekly'),
        ],
        default='daily',
    )

    # Last alert info
    last_alert_sent_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} - {self.user.username}"


class RecommendedListing(models.Model):
    """AI-generated listing recommendations for users"""

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='recommended_listings'
    )
    listing = models.ForeignKey(
        Listing, on_delete=models.CASCADE, related_name='recommendations'
    )

    # Recommendation details
    score = models.FloatField(default=0)  # Higher means more relevant
    reason = models.CharField(max_length=255, blank=True, null=True)

    # Status
    is_viewed = models.BooleanField(default=False)
    is_clicked = models.BooleanField(default=False)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    viewed_at = models.DateTimeField(null=True, blank=True)
    clicked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('user', 'listing')
        ordering = ['-score', '-created_at']

    def __str__(self):
        return f"Recommendation for {self.user.username}: {self.listing.title}"

    def mark_viewed(self):
        """Mark recommendation as viewed"""
        if not self.is_viewed:
            self.is_viewed = True
            self.viewed_at = timezone.now()
            self.save(update_fields=['is_viewed', 'viewed_at'])

    def mark_clicked(self):
        """Mark recommendation as clicked"""
        if not self.is_clicked:
            self.is_clicked = True
            self.clicked_at = timezone.now()
            self.save(update_fields=['is_clicked', 'clicked_at'])
