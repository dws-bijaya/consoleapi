from django.http import HttpResponse, HttpRequest
from django.template import loader, Context
from api_network_tools import get_ip_address_from_request
from easy_timezones.utils import is_local_ip
import time
from django.shortcuts import render


class network_tools:
	def WhatIsMyIP(request):
		IPAddress = get_ip_address_from_request(request)
		template = loader.get_template('network_tools/WhatIsMyIP.html')
		context = {"IPAddress": IPAddress}
		is_local = "Yes" if is_local_ip(IPAddress) else "False"
		context['is_local'] = is_local
		return render(request, 'network_tools/WhatIsMyIP.html', context)

	def DNSLookup(request):
		template = loader.get_template('network_tools/DNSLookup.html')
		return HttpResponse(template.render())
		pass