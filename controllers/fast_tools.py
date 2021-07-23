from django.http import HttpResponse, HttpRequest
from django.template import loader, Context
from django.shortcuts import render


class fast_tools:
	def WebpageMalwareScanner(request):
		context = {'meta_title': "Webpage Malware Scanner"}
		context['meta_description'] = "Free fast tools to scan your webpage for malware, malicious redirects, malicious scripts, spam hacks and other bad stuff."
		return render(request, 'fast_tools/WebpageMalwareScanner.html', context)

	def HTTPServerHeaderTest(request):
		IPAddress = '127.0.0.1'  # get_ip_address_from_request(request)
		User_Agent = request.META['HTTP_USER_AGENT']
		context = {'User_Agent': User_Agent, 'url': request.GET.get('url', '')}
		return render(request, 'fast_tools/HTTPServerHeaderTest.html', context)

	def EmailSmtpTest(request):
		IPAddress = '127.0.0.1'  # get_ip_address_from_request(request)
		User_Agent = request.META['HTTP_USER_AGENT']
		context = {'User_Agent': User_Agent, 'meta_title': 'Free Fast tools for testing SMTP email sending'}
		return render(request, 'fast_tools/EmailSmtpTest.html', context)

	def WhatsappDirect(request):
		IPAddress = '127.0.0.1'  # get_ip_address_from_request(request)
		User_Agent = request.META['HTTP_USER_AGENT']
		context = {'User_Agent': User_Agent}
		context = {'meta_title': "Generate WhatsAapp Link and Send Messages Directly"}
		context['meta_description'] = "Send WhatsApp messages to any nonsaved contact numbers directly and also Create a personalised WhatsApp link with a pre-defined message in seconds and share it with your audience on social media!"

		return render(request, 'fast_tools/WhatsappDirect.html', context)