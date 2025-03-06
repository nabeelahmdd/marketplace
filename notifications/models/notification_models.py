from django.db import models
from django.utils import timezone

from listings.models import Listing
from messaging.models import Conversation
from users.models import User


class Notification(models.Model):
    """User notifications for various events"""

    NOTIFICATION_TYPES = [
        ('message', 'New Message'),
        ('comment', 'New Comment'),
        ('favorite', 'New Favorite'),
        ('rating', 'New Rating'),
        ('offer', 'New Offer'),
        ('listing_update', 'Listing Update'),
        ('listing_expiring', 'Listing Expiring'),
        ('account', 'Account Notification'),
        ('promotion', 'Promotion'),
        ('system', 'System Notification'),
    ]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='notifications'
    )
    type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=255)
    content = models.TextField()
    image_url = models.URLField(blank=True, null=True)

    # Related objects
    listing = models.ForeignKey(
        Listing,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='notifications',
    )
    conversation = models.ForeignKey(
        Conversation, on_delete=models.SET_NULL, null=True, blank=True
    )
    sender = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='sent_notifications',
    )

    # Status
    is_read = models.BooleanField(default=False)
    is_email_sent = models.BooleanField(default=False)
    is_push_sent = models.BooleanField(default=False)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_read', 'created_at']),
        ]

    def __str__(self):
        return f"{self.get_type_display()} for {self.user.username}"

    def mark_as_read(self):
        """Mark notification as read"""
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=['is_read', 'read_at'])
