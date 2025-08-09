app_name = 'broadcasts'
from django.urls import path
from .views import broadcast_list, broadcast_create, broadcast_studio

urlpatterns = [
    path('', broadcast_list, name='broadcast_list'),
    path('create/', broadcast_create, name='broadcast_create'),
    path('<int:pk>/studio/', broadcast_studio, name='broadcast_studio'),
]
