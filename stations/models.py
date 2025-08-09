
from django.db import models
from django.conf import settings


class Station(models.Model):
	"""A streaming station configuration (Icecast/SHOUTcast/custom)."""
	# Ownership
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='stations')

	# Basic identity
	name = models.CharField(max_length=100)

	# If provided, this is the full public stream URL (e.g., https://example.com:8443/mount)
	# If left blank, we'll build it from protocol + host + port + mount.
	url = models.URLField(blank=True)

	# Server connection pieces (for Icecast/SHOUTcast)
	protocol = models.CharField(max_length=5, choices=(('http', 'http'), ('https', 'https')), default='http')
	host = models.CharField(max_length=255, blank=True, help_text="Hostname or IP of your streaming server")
	port = models.PositiveIntegerField(default=8000, help_text="Server port")
	mount = models.CharField(max_length=100, blank=True, help_text="Mountpoint (e.g., /stream) for Icecast or path segment")
	username = models.CharField(max_length=100, blank=True, help_text="Optional username if your stream requires HTTP auth")
	password = models.CharField(max_length=255, blank=True, help_text="Optional password if your stream requires HTTP auth")

	# Stream metadata (optional, informational)
	format = models.CharField(max_length=10, blank=True, choices=(
		('mp3', 'MP3'),
		('aac', 'AAC/AAC+'),
		('ogg', 'Ogg Vorbis'),
	), help_text="Audio format (optional)")
	bitrate = models.PositiveIntegerField(null=True, blank=True, help_text="Bitrate in kbps (optional)")

	# Status and flags
	enabled = models.BooleanField(default=True)
	last_tested_at = models.DateTimeField(null=True, blank=True)
	connection_status = models.CharField(
		max_length=20,
		choices=(
			('unknown', 'Unknown'),
			('ok', 'OK'),
			('unauthorized', 'Unauthorized'),
			('unreachable', 'Unreachable'),
			('error', 'Error'),
		),
		default='unknown',
	)

	# Timestamps
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	def __str__(self):
		return self.name

	def build_stream_url(self) -> str:
		"""Return a full stream URL from fields.
		Order of precedence: explicit url field; otherwise build from protocol+host+port+mount.
		"""
		if self.url:
			return self.url
		# Ensure mount starts with a slash if provided
		mount = self.mount or ''
		if mount and not mount.startswith('/'):
			mount = f'/{mount}'
		host = (self.host or '').strip()
		if not host:
			return ''
		return f"{self.protocol}://{host}:{self.port}{mount}"

	@property
	def stream_url(self) -> str:
		"""Template-friendly accessor for the resolved stream URL."""
		return self.build_stream_url()
