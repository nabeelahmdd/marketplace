import logging
import socket
import time

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)


def send_email(subject, recipient, template_name, context):
    """Generic email sending function with comprehensive error handling.

    Args:
    ----
        subject (str): Email subject
        recipient (str): Recipient email address
        template_name (str): Template name (without extension)
        context (dict): Context for template rendering

    Returns:
    -------
        bool: True if email sent successfully, False otherwise
    """
    # Validate inputs
    if not recipient or not template_name:
        logger.error("Missing required email parameters")
        return False

    # Add some default context values
    full_context = {
        'site_name': getattr(settings, 'SITE_NAME', 'Our Website'),
        'site_url': getattr(settings, 'FRONTEND_URL', '#'),
        'support_email': getattr(
            settings, 'SUPPORT_EMAIL', settings.DEFAULT_FROM_EMAIL
        ),
        **context,
    }

    # Maximum retry attempts for transient errors
    max_retries = 3
    retry_count = 0

    while retry_count < max_retries:
        try:
            # Render HTML content
            try:
                html_content = render_to_string(
                    f'emails/{template_name}.html', full_context
                )
            except Exception as template_error:
                logger.error(f"Template rendering error: {str(template_error)}")
                return False

            # Create plain text version
            text_content = strip_tags(html_content)

            # Create email
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[recipient],
            )
            email.attach_alternative(html_content, "text/html")

            # Send email
            email.send()
            logger.info(f"Email sent successfully to {recipient}: {subject}")
            return True

        except socket.gaierror as e:
            # DNS resolution error - temporary network issue
            logger.warning(
                f"Network error sending email to {recipient}: {str(e)}"
            )
            retry_count += 1
            if retry_count < max_retries:
                time.sleep(2)  # Wait before retrying
            else:
                logger.error(
                    f"Failed to send email after {max_retries} \
                        attempts: Network error"
                )
                return False

        except ConnectionRefusedError as e:
            # SMTP server connection refused
            logger.error(f"SMTP connection refused: {str(e)}")
            return False  # No retry for connection refused

        except Exception as e:
            # Other unexpected errors
            logger.error(
                f"Failed to send email to {recipient}: {str(e)}", exc_info=True
            )
            retry_count += 1
            if retry_count < max_retries and isinstance(
                e, (TimeoutError, ConnectionError)
            ):
                # Only retry for specific transient errors
                time.sleep(2)  # Wait before retrying
            else:
                return False


def send_password_reset_email(email, reset_url):
    """Send password reset email with reset link.

    Args:
    ----
        email (str): User's email address
        reset_url (str): Password reset URL

    Returns:
    -------
        bool: True if email sent successfully, False otherwise
    """
    try:
        if not email or not reset_url:
            logger.error("Missing email or reset URL for password reset email")
            return False

        subject = "Password Reset Requested"
        context = {
            'reset_url': reset_url,
            'expiry_hours': getattr(
                settings, 'PASSWORD_RESET_TIMEOUT_HOURS', 24
            ),
            'recipient_email': email,
            'date_sent': time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        return send_email(subject, email, 'password_reset', context)

    except Exception as e:
        logger.error(
            f"Error in password reset email process: {str(e)}", exc_info=True
        )
        return False


def send_account_activation_email(email, activation_url):
    """Send account activation email with activation link.

    Args:
    ----
        email (str): User's email address
        activation_url (str): Account activation URL

    Returns:
    -------
        bool: True if email sent successfully, False otherwise
    """
    try:
        if not email or not activation_url:
            logger.error(
                "Missing email or activation URL for account activation email"
            )
            return False

        subject = "Activate Your Account"
        context = {
            'activation_url': activation_url,
            'expiry_hours': getattr(
                settings, 'ACCOUNT_ACTIVATION_TIMEOUT_HOURS', 48
            ),
            'recipient_email': email,
            'date_sent': time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        return send_email(subject, email, 'account_activation', context)

    except Exception as e:
        logger.error(
            f"Error in account activation email process: {str(e)}",
            exc_info=True,
        )
        return False
