import logging

from django.conf import settings

logger = logging.getLogger(__name__)


def send_otp_via_sms(phone_number, otp_code, purpose):
    """Send OTP code via SMS.

    This function integrates with an SMS gateway service to send OTP codes.

    Args:
    ----
        phone_number: Recipient phone number with country code
        otp_code: OTP code to send
        purpose: Purpose of the OTP (used for message customization)

    Returns:
    -------
        bool: True if SMS sent successfully, False otherwise
    """
    try:
        # In production, replace this with actual SMS sending code
        # Example with Twilio:
        # from twilio.rest import Client
        # client = Client(settings.TWILIO_ACCOUNT_SID,
        # settings.TWILIO_AUTH_TOKEN)
        # message = client.messages.create(
        #     body=f"Your {purpose} OTP is: {otp_code}. Valid for 10 minutes.",
        #     from_=settings.TWILIO_PHONE_NUMBER,
        #     to=phone_number
        # )

        # For demonstration and testing, just log the OTP
        logger.info(f"SMS OTP for {purpose} to {phone_number}: {otp_code}")

        # In development mode, always return success
        if settings.DEBUG:
            return True

        # In production, you'd return based on SMS API response
        # return message.sid is not None
        return True

    except Exception as e:
        logger.error(f"Error sending OTP via SMS: {str(e)}")
        return False


def send_otp_via_email(email, otp_code, purpose):
    """Send OTP code via email.

    Args:
    ----
        email: Recipient email address
        otp_code: OTP code to send
        purpose: Purpose of the OTP (used for message customization)

    Returns:
    -------
        bool: True if email sent successfully, False otherwise
    """
    try:
        # In production, integrate with your email sending system
        # Example:
        from django.core.mail import send_mail

        subject = f"Your {purpose} OTP"
        message = f"Your OTP is: {otp_code}. Valid for 10 minutes."
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )

        # For demonstration, just log the OTP
        logger.info(f"Email OTP for {purpose} to {email}: {otp_code}")

        # In development mode, always return success
        if settings.DEBUG:
            return True

        # In production, you'd return based on email API response
        # return sent > 0
        return True

    except Exception as e:
        logger.error(f"Error sending OTP via email: {str(e)}")
        return False


def format_purpose_for_message(purpose):
    """Format the purpose code for user-friendly messages.

    Args:
    ----
        purpose: Purpose code from OTP.PURPOSE_CHOICES

    Returns:
    -------
        str: User-friendly purpose description
    """
    purpose_map = {
        'REGISTER': 'account registration',
        'LOGIN': 'login',
        'RESET_PASSWORD': 'password reset',
        'VERIFY_NEW_PHONE': 'phone verification',
    }

    return purpose_map.get(purpose, purpose.lower().replace('_', ' '))
