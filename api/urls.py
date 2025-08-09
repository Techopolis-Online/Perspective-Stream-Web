from django.urls import path
from .views import livekit_token

app_name = "api"

urlpatterns = [
    path("livekit/token/", livekit_token, name="livekit_token"),
]
