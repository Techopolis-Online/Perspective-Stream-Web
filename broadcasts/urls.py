from django.urls import path
from .views import broadcast_list, broadcast_create

urlpatterns = [
    path('', broadcast_list, name='broadcast_list'),
    path('create/', broadcast_create, name='broadcast_create'),
]
