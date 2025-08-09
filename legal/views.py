from django.shortcuts import render
from django.views import View

class TermsView(View):
    def get(self, request):
        return render(request, 'legal/terms.html')

class PrivacyView(View):
    def get(self, request):
        return render(request, 'legal/privacy.html')
