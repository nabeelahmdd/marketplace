from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import CategoryListView, ListingImageViewSet, ListingViewSet

router = DefaultRouter()
router.register(r'listings', ListingViewSet, basename='listing')
router.register(
    r'listing-images', ListingImageViewSet, basename='listing-images'
)

urlpatterns = [
    path('categories/', CategoryListView.as_view(), name='category-list'),
    path('', include(router.urls)),
]
