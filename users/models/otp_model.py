import random
from datetime import timedelta

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class OTP(models.Model):
    """Model to store OTP codes and track verification attempts.

    This model manages OTP generation, verification, and expiration for
    both phone-based and email-based OTPs.
    """

    TYPE_CHOICES = (
        ('PHONE', _('Phone')),
        ('EMAIL', _('Email')),
    )

    PURPOSE_CHOICES = (
        ('REGISTER', _('Registration')),
        ('LOGIN', _('Login')),
        ('RESET_PASSWORD', _('Reset Password')),
        ('VERIFY_NEW_PHONE', _('Verify New Phone')),
    )

    identifier = models.CharField(
        _('Identifier'),
        max_length=100,
        help_text=_("Phone number or email for which OTP is generated"),
    )
    type = models.CharField(
        _('OTP Type'),
        max_length=10,
        choices=TYPE_CHOICES,
        help_text=_("Whether OTP is sent to phone or email"),
    )
    purpose = models.CharField(
        _('OTP Purpose'),
        max_length=20,
        choices=PURPOSE_CHOICES,
        help_text=_("Purpose for which OTP is generated"),
    )
    otp = models.CharField(
        _('OTP Code'), max_length=6, help_text=_("Generated OTP code")
    )
    is_verified = models.BooleanField(
        _('Is Verified'),
        default=False,
        help_text=_("Whether the OTP has been verified"),
    )
    attempts = models.PositiveSmallIntegerField(
        _('Verification Attempts'),
        default=0,
        help_text=_("Number of verification attempts"),
    )
    max_attempts = models.PositiveSmallIntegerField(
        _('Max Attempts'),
        default=3,
        help_text=_("Maximum allowed verification attempts"),
    )
    created_at = models.DateTimeField(
        _('Created At'),
        auto_now_add=True,
        help_text=_("When the OTP was generated"),
    )
    expires_at = models.DateTimeField(
        _('Expires At'), help_text=_("When the OTP expires")
    )

    class Meta:
        verbose_name = _('OTP')
        verbose_name_plural = _('OTPs')
        indexes = [
            models.Index(fields=['identifier'], name='otp_identifier_idx'),
            models.Index(fields=['created_at'], name='otp_created_idx'),
        ]

    def __str__(self):
        return f"{self.identifier} - {self.purpose} ({self.otp})"

    @classmethod
    def generate_otp(
        cls, identifier, type, purpose, expiry_minutes=10, otp_length=6
    ):
        """Generate a new OTP for the given identifier and purpose.

        Args:
        ----
            identifier: Phone number or email
            type: Type of OTP (PHONE/EMAIL)
            purpose: Purpose of OTP (REGISTER/LOGIN/etc)
            expiry_minutes: Minutes until OTP expires
            otp_length: Length of OTP code

        Returns:
        -------
            Generated OTP instance
        """
        # Invalidate any existing active OTPs for this identifier and purpose
        cls.objects.filter(
            identifier=identifier,
            purpose=purpose,
            is_verified=False,
            expires_at__gt=timezone.now(),
        ).update(expires_at=timezone.now())

        # Generate random OTP
        otp_code = ''.join(
            random.choice('0123456789') for _ in range(otp_length)
        )

        # Create new OTP record
        otp = cls.objects.create(
            identifier=identifier,
            type=type,
            purpose=purpose,
            otp=otp_code,
            expires_at=timezone.now() + timedelta(minutes=expiry_minutes),
        )

        return otp

    def is_valid(self):
        """Check if the OTP is still valid (not expired, not verified, attempts
        not exceeded).

        Returns
        -------
            bool: True if OTP is valid, False otherwise
        """
        if self.is_verified:
            return False

        if timezone.now() > self.expires_at:
            return False

        if self.attempts >= self.max_attempts:
            return False

        return True

    def verify(self, otp_code):
        """Verify the provided OTP code against this OTP record.

        Args:
        ----
            otp_code: The OTP code to verify

        Returns:
        -------
            bool: True if verification successful, False otherwise
        """
        # Increment attempt counter
        self.attempts += 1

        # Check if OTP is valid
        if not self.is_valid():
            self.save()
            return False

        # Check if OTP code matches
        if self.otp != otp_code:
            self.save()
            return False

        # OTP verification successful
        self.is_verified = True
        self.save()
        return True
