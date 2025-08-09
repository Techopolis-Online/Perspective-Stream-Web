
from django.contrib import admin
from .models import Station

@admin.register(Station)
class StationAdmin(admin.ModelAdmin):
	list_display = ('name', 'user', 'url', 'mount', 'enabled')
	search_fields = ('name', 'url', 'mount')
	list_filter = ('enabled',)
