
from django.contrib import admin
from .models import Broadcast

@admin.register(Broadcast)
class BroadcastAdmin(admin.ModelAdmin):
	list_display = ('title', 'user', 'start_time', 'privacy', 'is_live')
	search_fields = ('title', 'description', 'category', 'tags')
	list_filter = ('privacy', 'is_live', 'start_time')
