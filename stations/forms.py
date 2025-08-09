from django import forms
from .models import Station


class StationForm(forms.ModelForm):
    class Meta:
        model = Station
        fields = [
            "name",
            "url",
            "protocol",
            "host",
            "port",
            "mount",
            "username",
            "password",
            "format",
            "bitrate",
            "enabled",
        ]
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "Station Name"}),
            "url": forms.URLInput(attrs={"placeholder": "Optional full stream URL (overrides fields below)"}),
            "host": forms.TextInput(attrs={"placeholder": "stream.example.com"}),
            "port": forms.NumberInput(attrs={"min": 1, "max": 65535}),
            "mount": forms.TextInput(attrs={"placeholder": "/stream"}),
            "username": forms.TextInput(attrs={"placeholder": "Optional"}),
            "password": forms.PasswordInput(render_value=False, attrs={"placeholder": "Optional"}),
        }
    
    def clean(self):
        data = super().clean()
        # If url is blank, require host
        url = data.get('url')
        host = data.get('host')
        if not url and not host:
            self.add_error('host', 'Provide a host or a full stream URL.')
        return data
