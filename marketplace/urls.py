# urls.py with compatible drf-yasg configuration

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

# Basic schema view without newer parameters
schema_view = get_schema_view(
    openapi.Info(
        title="Your API",
        default_version='v1',
        description="API Documentation",
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    path('admin/', admin.site.urls),
    # Schema URLs
    path(
        'swagger.json',
        schema_view.without_ui(cache_timeout=0),
        name='schema-json',
    ),
    path(
        'swagger.yaml',
        schema_view.without_ui(cache_timeout=0),
        name='schema-yaml',
    ),
    path(
        'swagger/',
        schema_view.with_ui('swagger', cache_timeout=0),
        name='schema-swagger-ui',
    ),
    path(
        'redoc/',
        schema_view.with_ui('redoc', cache_timeout=0),
        name='schema-redoc',
    ),
    path('api/users/', include('users.urls')),
    path('api/shop/', include('shop.urls')),
]

# Add static handling
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
