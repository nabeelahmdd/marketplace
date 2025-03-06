from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    CategoryListView,
    CommentListCreateView,
    FavoriteListingView,
    GenerateRecommendationsView,
    ListingDetailView,
    ListingImageViewSet,
    ListingViewSet,
    MarkRecommendationClickedView,
    PublicListingListView,
    RecommendationsView,
    SavedSearchDetailView,
    SavedSearchListView,
    SaveSearchView,
    UnfavoriteListingView,
)

router = DefaultRouter()
router.register(r'listings', ListingViewSet, basename='listing')
router.register(
    r'listing-images', ListingImageViewSet, basename='listing-images'
)

urlpatterns = [
    path('categories/', CategoryListView.as_view(), name='category-list'),
    path('', include(router.urls)),
    path('api/listings/', PublicListingListView.as_view(), name='listing-list'),
    path(
        'api/listings/<slug:slug>/',
        ListingDetailView.as_view(),
        name='listing-detail',
    ),
    # Favorite endpoints
    path(
        'api/listings/<slug:slug>/favorite/',
        FavoriteListingView.as_view(),
        name='favorite-listing',
    ),
    path(
        'api/listings/<slug:slug>/unfavorite/',
        UnfavoriteListingView.as_view(),
        name='unfavorite-listing',
    ),
    # Comment endpoints
    path(
        'api/listings/<slug:listing_slug>/comments/',
        CommentListCreateView.as_view(),
        name='comment-list-create',
    ),
    # SavedSearch endpoints
    path('api/save-search/', SaveSearchView.as_view(), name='save-search'),
    path(
        'api/saved-searches/',
        SavedSearchListView.as_view(),
        name='saved-search-list',
    ),
    path(
        'api/saved-searches/<int:pk>/',
        SavedSearchDetailView.as_view(),
        name='saved-search-detail',
    ),
    # Recommendation endpoints
    path(
        'api/recommendations/',
        RecommendationsView.as_view(),
        name='recommendations',
    ),
    path(
        'api/recommendations/<int:pk>/click/',
        MarkRecommendationClickedView.as_view(),
        name='recommendation-click',
    ),
    path(
        'api/admin/generate-recommendations/',
        GenerateRecommendationsView.as_view(),
        name='generate-recommendations',
    ),
]
