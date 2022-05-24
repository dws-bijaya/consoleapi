from django.http import HttpResponse, HttpRequest
from django.template import loader, Context
import time
from django.shortcuts import render
from django.conf import settings


class google_indexing_api:
    def bulk_submit(request):
        context = {
            'meta_title': "Free and fast tools provides a convenient UI for sending a batch request of a bulk of URLs to Google's Indexing API."}
        context['og_url'] = 'https://consoleapi.com/google-indexing-api.html'
        context['meta_description'] = "Free and fast tools provides a convenient UI for sending a batch request of a bulk of URLs to Google's Indexing API. "
        return render(request, 'google_indexapi/ConvertPpkToPem.html', context)

    def DNSLookup(request):
        template = loader.get_template('network_tools/DNSLookup.html')
        return HttpResponse(template.render())
        pass
