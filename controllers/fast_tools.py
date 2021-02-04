from django.http import HttpResponse, HttpRequest
from django.template import loader, Context
from django.shortcuts import render


class fast_tools:
	def HTTPServerHeaderTest(request):
		IPAddress = '127.0.0.1'  # get_ip_address_from_request(request)
		context = {}
		return render(request, 'fast_tools/HTTPServerHeaderTest.html', context)
