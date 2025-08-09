app_name = 'stations'
from django.urls import path
from .views import station_list, station_create, station_test

urlpatterns = [
    path('', station_list, name='station_list'),
    path('create/', station_create, name='station_create'),
    path('test/', station_test, name='station_test'),
]
