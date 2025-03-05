from django.contrib.auth.backends import ModelBackend

from users.models import User


class EmailOrMobileAuthBackend(ModelBackend):
    """Custom authentication backend that supports both email and mobile login.

    This backend allows users to authenticate with either email or mobile number
    along with their password.
    """

    def authenticate(
        self, request, email=None, mobile=None, password=None, **kwargs
    ):
        """Authenticate a user using either email or mobile with password.
        kwargs:
        ----
            request: The request object
            email: Email for authentication (optional)
            mobile: Mobile number for authentication (optional)
            password: User's password

        Returns
        -------
            User: The authenticated user if credentials are valid,
            None otherwise
        """
        if email is None and mobile is None:
            return None

        try:
            # Build the query based on what was provided
            if email:
                user = User.objects.get(email=email)
            elif mobile:
                user = User.objects.get(mobile=mobile)

            # Check the password
            if user.check_password(password):
                return user
            return None
        except User.DoesNotExist:
            # Run the default password hasher once to reduce timing
            # attacks targeting whether or not a user exists
            User().set_password(password)
