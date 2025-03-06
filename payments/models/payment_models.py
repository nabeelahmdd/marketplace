import random
import time

from django.db import models
from django.utils import timezone

from core.models import BaseModel
from listings.models import Listing
from users.models import User


class Wallet(BaseModel):
    """User wallet for marketplace transactions"""

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='wallet'
    )
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    currency = models.CharField(max_length=3, default='USD')
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username}'s wallet ({self.currency})"


class Transaction(BaseModel):
    """Financial transactions"""

    TRANSACTION_TYPES = [
        ('deposit', 'Deposit'),
        ('withdrawal', 'Withdrawal'),
        ('payment', 'Payment'),
        ('refund', 'Refund'),
        ('commission', 'Commission'),
        ('subscription', 'Subscription'),
        ('promotion', 'Promotion'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
        ('refunded', 'Refunded'),
    ]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='transactions'
    )
    wallet = models.ForeignKey(
        Wallet,
        on_delete=models.CASCADE,
        related_name='transactions',
        null=True,
        blank=True,
    )
    listing = models.ForeignKey(
        Listing,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='transactions',
    )

    transaction_type = models.CharField(
        max_length=20, choices=TRANSACTION_TYPES
    )
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='pending'
    )

    # Payment details
    payment_method = models.CharField(max_length=50, blank=True, null=True)
    payment_id = models.CharField(max_length=255, blank=True, null=True)

    # Additional info
    description = models.TextField(blank=True, null=True)
    meta_data = models.JSONField(blank=True, null=True)

    # Status tracking
    completed_at = models.DateTimeField(null=True, blank=True)
    failed_reason = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'transaction_type', 'status']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.get_transaction_type_display()} - {self.amount} \
            {self.currency} ({self.get_status_display()})"

    def complete_transaction(self):
        """Mark transaction as completed and update wallet balance"""
        if self.status != 'completed':
            self.status = 'completed'
            self.completed_at = timezone.now()

            # Update wallet balance if relevant
            if self.wallet:
                if self.transaction_type in ['deposit', 'refund']:
                    self.wallet.balance += self.amount
                elif self.transaction_type in [
                    'withdrawal',
                    'payment',
                    'subscription',
                    'promotion',
                ]:
                    self.wallet.balance -= self.amount
                self.wallet.save()

            self.save()


class Invoice(BaseModel):
    """Invoices for marketplace transactions"""

    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('issued', 'Issued'),
        ('paid', 'Paid'),
        ('overdue', 'Overdue'),
        ('cancelled', 'Cancelled'),
    ]

    invoice_number = models.CharField(max_length=50, unique=True)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='invoices'
    )
    transaction = models.OneToOneField(
        Transaction,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='invoice',
    )

    amount = models.DecimalField(max_digits=12, decimal_places=2)
    tax_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')

    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='draft'
    )
    description = models.TextField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)

    issue_date = models.DateField(null=True, blank=True)
    due_date = models.DateField(null=True, blank=True)
    paid_date = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Invoice #{self.invoice_number} - {self.user.username}"

    def save(self, *args, **kwargs):
        # Generate invoice number if not provided
        if not self.invoice_number:
            timestamp = int(time.time())
            random_digits = ''.join(
                [str(random.randint(0, 9)) for _ in range(4)]
            )
            self.invoice_number = f"INV-{timestamp}-{random_digits}"

        # Calculate total amount
        self.total_amount = self.amount + self.tax_amount

        super().save(*args, **kwargs)


class SubscriptionPlan(models.Model):
    """Subscription plans for marketplace users"""

    name = models.CharField(max_length=100)
    code = models.SlugField(unique=True)
    description = models.TextField()
    features = models.JSONField(default=dict)

    price = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    duration_days = models.PositiveIntegerField()

    # Limits
    max_listings = models.PositiveIntegerField(default=10)
    max_featured_listings = models.PositiveIntegerField(default=0)
    max_images_per_listing = models.PositiveIntegerField(default=5)

    # Status
    is_active = models.BooleanField(default=True)
    rank_order = models.PositiveIntegerField(default=0)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['rank_order', 'price']

    def __str__(self):
        return f"{self.name} Plan - {self.price} {self.currency}"


class Subscription(BaseModel):
    """User subscriptions to plans"""

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('cancelled', 'Cancelled'),
        ('pending', 'Pending'),
    ]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='subscriptions'
    )
    plan = models.ForeignKey(
        SubscriptionPlan, on_delete=models.PROTECT, related_name='subscriptions'
    )

    # Status
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='pending'
    )

    # Dates
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    cancelled_at = models.DateTimeField(null=True, blank=True)

    # Payment
    price_paid = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    transaction = models.ForeignKey(
        Transaction,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='subscription',
    )

    # Auto renewal
    auto_renew = models.BooleanField(default=False)

    class Meta:
        ordering = ['-start_date']

    def __str__(self):
        return f"{self.user.username} - {self.plan.name} \
            ({self.get_status_display()})"

    def save(self, *args, **kwargs):
        # Calculate end date if not provided
        if not self.end_date and self.start_date and self.plan:
            self.end_date = self.start_date + timezone.timedelta(
                days=self.plan.duration_days
            )

        super().save(*args, **kwargs)

    @property
    def is_active(self):
        """Check if subscription is currently active"""
        now = timezone.now()
        return (
            self.status == 'active'
            and self.start_date <= now
            and self.end_date >= now
        )


class Promotion(BaseModel):
    """Promotion campaigns for listings"""

    PROMOTION_TYPES = [
        ('featured', 'Featured Listing'),
        ('urgent', 'Urgent Tag'),
        ('highlighted', 'Highlighted'),
        ('top_page', 'Top of Page'),
        ('homepage', 'Homepage'),
        ('category_top', 'Category Top'),
    ]

    listing = models.ForeignKey(
        Listing, on_delete=models.CASCADE, related_name='promotions'
    )
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='promotions'
    )

    # Promotion details
    promotion_type = models.CharField(max_length=20, choices=PROMOTION_TYPES)

    # Dates
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()

    # Status
    is_active = models.BooleanField(default=True)

    # Payment
    price = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    transaction = models.ForeignKey(
        Transaction,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='promotion',
    )

    class Meta:
        ordering = ['-start_date']

    def __str__(self):
        return f"{self.get_promotion_type_display()} for {self.listing.title}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

        # Update the listing's promotion flags
        if (
            self.is_active
            and self.start_date <= timezone.now() <= self.end_date
        ):
            if self.promotion_type == 'featured':
                self.listing.is_featured = True
            elif self.promotion_type == 'urgent':
                self.listing.is_urgent = True
            elif self.promotion_type == 'highlighted':
                self.listing.is_highlighted = True
            self.listing.save(
                update_fields=[
                    'is_featured',
                    'is_urgent',
                    'is_highlighted',
                    'updated_at',
                ]
            )
