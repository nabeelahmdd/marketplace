from django.db import models
from django.utils import timezone

from core.models import BaseModel
from listings.models import Category
from users.models import User


class FAQ(models.Model):
    """Frequently asked questions"""

    question = models.CharField(max_length=255)
    answer = models.TextField()
    category = models.CharField(max_length=50, blank=True, null=True)
    order = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['order', 'category']
        verbose_name = 'FAQ'
        verbose_name_plural = 'FAQs'

    def __str__(self):
        return self.question


class Page(BaseModel):
    """Static pages like About, Terms, Privacy Policy"""

    title = models.CharField(max_length=255)
    slug = models.SlugField(unique=True)
    content = models.TextField()
    is_published = models.BooleanField(default=True)
    meta_title = models.CharField(max_length=255, blank=True, null=True)
    meta_description = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['title']

    def __str__(self):
        return self.title


class Banner(models.Model):
    """Promotional banners for homepage and category pages"""

    title = models.CharField(max_length=255)
    subtitle = models.CharField(max_length=255, blank=True, null=True)
    image = models.ImageField(upload_to='banners/')
    url = models.URLField(blank=True, null=True)

    # Display settings
    location = models.CharField(
        max_length=50,
        choices=[
            ('homepage', 'Homepage'),
            ('category', 'Category Page'),
            ('search', 'Search Results'),
            ('sidebar', 'Sidebar'),
        ],
    )
    category = models.ForeignKey(
        Category,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='banners',
    )
    order = models.PositiveIntegerField(default=0)

    # Scheduling
    start_date = models.DateTimeField(default=timezone.now)
    end_date = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    # Tracking
    view_count = models.PositiveIntegerField(default=0)
    click_count = models.PositiveIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['order', '-start_date']

    def __str__(self):
        return self.title

    @property
    def is_scheduled(self):
        """Check if banner is currently scheduled to display"""
        now = timezone.now()
        return (
            self.is_active
            and self.start_date <= now
            and (self.end_date is None or self.end_date >= now)
        )


class ContactMessage(models.Model):
    """Contact form submissions"""

    name = models.CharField(max_length=255)
    email = models.EmailField()
    subject = models.CharField(max_length=255)
    message = models.TextField()
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='contact_messages',
    )

    # Status
    is_read = models.BooleanField(default=False)
    is_replied = models.BooleanField(default=False)

    # Meta data
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)
    replied_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Contact from {self.name}: {self.subject}"

    def mark_as_read(self):
        """Mark message as read"""
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=['is_read', 'read_at'])

    def mark_as_replied(self):
        """Mark message as replied"""
        if not self.is_replied:
            self.is_replied = True
            self.replied_at = timezone.now()
            self.save(update_fields=['is_replied', 'replied_at'])
