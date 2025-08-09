from django import forms
from .models import Broadcast


class BroadcastForm(forms.ModelForm):
    start_time = forms.DateTimeField(
        widget=forms.DateTimeInput(attrs={"type": "datetime-local"}),
        help_text="Schedule start time (your local time)",
    )
    go_live_now = forms.BooleanField(
        required=False,
        help_text="Start immediately without scheduling",
        initial=False,
    )
    enable_radio = forms.BooleanField(
        required=False,
        help_text="Stream to your radio station(s)",
        initial=False,
        label="Radio",
    )
    enable_youtube = forms.BooleanField(
        required=False,
        help_text="Stream to YouTube",
        initial=False,
        label="YouTube",
    )

    class Meta:
        model = Broadcast
        fields = [
            "title",
            "description",
            "category",
            "tags",
            "start_time",
            "privacy",
            "enable_radio",
            "enable_youtube",
            # go_live_now is an extra form field, not in model
        ]
        widgets = {
            "title": forms.TextInput(attrs={"placeholder": "Broadcast title"}),
            "description": forms.Textarea(attrs={"rows": 4, "placeholder": "Describe your stream"}),
            "category": forms.TextInput(attrs={"placeholder": "Category (e.g. News)"}),
            "tags": forms.TextInput(attrs={"placeholder": "Comma-separated tags"}),
            "privacy": forms.Select(),
        }

    def clean(self):
        cleaned = super().clean()
        go_now = cleaned.get("go_live_now")
        start_time = cleaned.get("start_time")
        if not go_now and not start_time:
            self.add_error("start_time", "Provide a start time or choose Go Live Now.")
        return cleaned
