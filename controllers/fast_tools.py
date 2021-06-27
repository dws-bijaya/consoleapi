from django.http import HttpResponse, HttpRequest
from django.template import loader, Context
from django.shortcuts import render


class fast_tools:
	def HTTPServerHeaderTest(request):
		IPAddress = '127.0.0.1'  # get_ip_address_from_request(request)
		User_Agent = request.META['HTTP_USER_AGENT']
		context = {'User_Agent': User_Agent, 'url': request.GET.get('url', '')}
		return render(request, 'fast_tools/HTTPServerHeaderTest.html', context)

	def EmailSmtpTest(request):
		IPAddress = '127.0.0.1'  # get_ip_address_from_request(request)
		User_Agent = request.META['HTTP_USER_AGENT']
		context = {'User_Agent': User_Agent}
		return render(request, 'fast_tools/EmailSmtpTest.html', context)

	def WhatsappDirect(request):
		IPAddress = '127.0.0.1'  # get_ip_address_from_request(request)
		User_Agent = request.META['HTTP_USER_AGENT']
		context = {'User_Agent': User_Agent}
		return render(request, 'fast_tools/WhatsappDirect.html', context)