import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class ModernPasswordStrengthValidator:
    """Validates password strength by checking:
    - Minimum length (default: 8 characters)
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    - Disallows passwords from a blacklist
    """

    def __init__(self, min_length=8):
        self.min_length = min_length
        self.special_characters = r'[()[\]{}|\\`~!@#$%^&*_\-+=;:\'",<>./?]'
        self.blacklist = ["password", "123456", "qwerty", "abc123", "letmein"]

    def validate(self, password, user=None):
        errors = []

        if len(password) < self.min_length:
            errors.append(
                _(
                    "The password must be at least %(min_length)d \
                  characters long."
                )
                % {"min_length": self.min_length}
            )

        if not re.search(r'[A-Z]', password):
            errors.append(
                _("The password must contain at least 1 uppercase letter.")
            )

        if not re.search(r'[a-z]', password):
            errors.append(
                _("The password must contain at least 1 lowercase letter.")
            )

        if not re.search(r'\d', password):
            errors.append(_("The password must contain at least 1 digit."))

        if not re.search(self.special_characters, password):
            errors.append(
                _(
                    "The password must contain at least 1 special \
                  character: %(special)s."
                )
                % {"special": "()[]{}|\\`~!@#$%^&*_-+=;:'\",<>./?"}
            )

        if any(
            blacklisted in password.lower() for blacklisted in self.blacklist
        ):
            errors.append(
                _(
                    "The password contains a disallowed word or  \
                sequence."
                )
            )

        if errors:
            raise ValidationError(errors, code='password_strength')

    def get_help_text(self):
        return _(
            "Your password must contain:\n"
            "- At least 8 characters\n"
            "- At least 1 uppercase letter\n"
            "- At least 1 lowercase letter\n"
            "- At least 1 digit\n"
            "- At least 1 special character\n"
            "Avoid common words or sequences like 'password', '123456', etc."
        )


def validate_postal_code(value):
    """Validates a postal/ZIP code.
    Ensures it is between 4-10 characters and contains only numbers, letters,
    spaces, or hyphens.
    """
    if not re.match(r'^[0-9a-zA-Z\s-]{4,10}$', value):
        raise ValidationError(
            f"{value} is not a valid postal code. It should be 4-10 characters \
                  long and may contain numbers, letters, spaces, or hyphens."
        )


def validate_phone_number(value: str) -> None:
    """Validates a phone number (without country code).

    Ensures phone number follows these rules:
    - Contains only digits (after removing spaces/hyphens)
    - Length between 8-15 digits
    - No special characters

    Args:
    ----
        value: Phone number string to validate (without country code)

    Raises:
    ------
        ValidationError: If phone number format is invalid

    Examples:
    --------
        Valid formats:
        - 1234567890
        - 123 456 7890
        - 123-456-7890
    """
    if not value:
        raise ValidationError(_("Phone number is required"))

    # Remove all spaces and hyphens
    cleaned = re.sub(r'[\s\-]', '', value)

    # Check for any invalid characters
    if not cleaned.isdigit():
        raise ValidationError(_("Phone number can only contain digits"))

    # Length check
    if not 8 <= len(cleaned) <= 15:
        raise ValidationError(_("Phone number must be between 8 and 15 digits"))


def validate_country_code(value: str) -> None:
    """Validates a country code.

    Ensures country code follows these rules:
    - Starts with '+'
    - Contains 1-4 digits after '+'
    - No other special characters

    Args:
    ----
        value: Country code string to validate

    Raises:
    ------
        ValidationError: If country code format is invalid

    Examples:
    --------
        Valid formats:
        - +1
        - +91
        - +971
    """
    if not value:
        raise ValidationError(_("Country code is required"))

    # Remove spaces
    cleaned = value.strip()

    # Must start with +
    if not cleaned.startswith('+'):
        raise ValidationError(_("Country code must start with '+'"))

    # Check remaining digits
    digits = cleaned[1:]
    if not digits.isdigit():
        raise ValidationError(
            _("Country code can only contain digits after '+'")
        )

    # Length check (1-4 digits after +)
    if not 1 <= len(digits) <= 4:
        raise ValidationError(_("Country code must have 1-4 digits after '+'"))
