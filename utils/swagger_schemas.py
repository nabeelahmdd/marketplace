from typing import Any, Dict

from drf_yasg import openapi


class SwaggerSchemas:
    """Centralized Swagger schema definitions for API documentation."""

    def error_schema(example_message: str = "Error message") -> Dict[str, Any]:
        """Generate a standard error response schema.

        Args:
        ----
            example_message: Example error message for documentation

        Returns:
        -------
            Swagger schema for error response
        """
        return {
            "schema": openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(
                        type=openapi.TYPE_STRING, example=example_message
                    )
                },
                required=['error'],
            )
        }

    def validation_error_schema() -> Dict[str, Any]:
        """Generate a validation error response schema.

        Returns
        -------
            Swagger schema for validation error response
        """
        return {
            "schema": openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'field_name': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(type=openapi.TYPE_STRING),
                        example=["This field is required."],
                    )
                },
            )
        }

    def otp_response_schema() -> Dict[str, Any]:
        """Generate OTP success response schema.

        Returns
        -------
            Swagger schema for OTP success response
        """
        return {
            "schema": openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        example="OTP sent successfully",
                    ),
                    'identifier': openapi.Schema(
                        type=openapi.TYPE_STRING, example="user@example.com"
                    ),
                },
                required=['message', 'identifier'],
            )
        }

    def auth_tokens_schema() -> Dict[str, Any]:
        """Generate authentication tokens response schema.

        Returns
        -------
            Swagger schema for authentication tokens response
        """
        return {
            "schema": openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(
                        type=openapi.TYPE_STRING, example="Login successful"
                    ),
                    'access': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1...",
                    ),
                    'refresh': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1...",
                    ),
                },
                required=['message', 'access', 'refresh'],
            )
        }

    # Common response schemas
    STANDARD_RESPONSES = {
        200: openapi.Response(
            description="Success",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(
                        type=openapi.TYPE_STRING, example="Operation successful"
                    )
                },
            ),
        ),
        400: openapi.Response(
            description="Bad Request",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(
                        type=openapi.TYPE_STRING, example="Invalid input"
                    )
                },
            ),
        ),
        401: openapi.Response(
            description="Unauthorized",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        example="Authentication failed",
                    )
                },
            ),
        ),
        404: openapi.Response(
            description="Not Found",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(
                        type=openapi.TYPE_STRING, example="Resource not found"
                    )
                },
            ),
        ),
        500: openapi.Response(
            description="Server Error",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        example="Internal server error",
                    )
                },
            ),
        ),
    }

    # Authentication specific responses
    AUTH_RESPONSES = {
        200: openapi.Response(description="Success", **auth_tokens_schema()),
        400: openapi.Response(
            description="Bad Request", **error_schema("Invalid credentials")
        ),
        401: openapi.Response(
            description="Unauthorized", **error_schema("Authentication failed")
        ),
        404: openapi.Response(
            description="Not Found", **error_schema("User not found")
        ),
    }

    # OTP specific responses
    OTP_RESPONSES = {
        200: openapi.Response(description="Success", **otp_response_schema()),
        400: openapi.Response(
            description="Bad Request", **validation_error_schema()
        ),
        404: openapi.Response(
            description="Not Found", **error_schema("User not found")
        ),
    }
