from django.db import models
from django.conf import settings


class YouTubeChannel(models.Model):
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="youtube_channels")
	channel_id = models.CharField(max_length=128)
	title = models.CharField(max_length=255)
	# Optionally store thumbnails or default stream key meta later
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		unique_together = ("user", "channel_id")

	def __str__(self) -> str:
		return f"{self.title} ({self.channel_id})"
