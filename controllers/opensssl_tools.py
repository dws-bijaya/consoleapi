from django.http import HttpResponse, HttpRequest
from django.template import loader, Context
import time
from django.shortcuts import render
from django.conf import settings


class opensssl_tools:
	def ConvertPpkToPem(request):
		context = {'meta_title': "Convert PPK file to PEM File format online."}
		context['og_url'] = 'https://consoleapi.com/convert-ppk-to-pem.html'
		context['meta_description'] = "Free fast tools to convert PPK file format to PEM File online without installing PuttGen command."

		return render(request, 'opensssl_tools/ConvertPpkToPem.html', context)

	def DNSLookup(request):
		template = loader.get_template('network_tools/DNSLookup.html')
		return HttpResponse(template.render())
		pass