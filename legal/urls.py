from django.urls import path
from .views import TermsView, PrivacyView

app_name = 'legal'

urlpatterns = [
    path('terms/', TermsView.as_view(), name='terms'),
    path('privacy/', PrivacyView.as_view(), name='privacy'),
]
