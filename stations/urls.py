from django.urls import path
from .views import station_list, station_create

urlpatterns = [
    path('', station_list, name='station_list'),
    path('create/', station_create, name='station_create'),
]
