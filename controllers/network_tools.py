from django.http import HttpResponse, HttpRequest
from django.template import loader, Context
from api_network_tools import ip_detail
from easy_timezones.utils import is_local_ip, get_ip_address_from_request
import time
from django.shortcuts import render
import ipaddress
from django.conf import settings


class network_tools:
	def WhatIsMyIP(request):
		IPAddress = get_ip_address_from_request(request)
		context = ip_detail(IPAddress)
		return render(request, 'network_tools/WhatIsMyIP.html', context)

	def DNSLookup(request):
		template = loader.get_template('network_tools/DNSLookup.html')
		return HttpResponse(template.render())
		pass