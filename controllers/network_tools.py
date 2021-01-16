from django.http import HttpResponse, HttpRequest
from django.template import loader, Context
from api_network_tools import get_ip_address_from_request
from easy_timezones.utils import is_local_ip
import time
from django.shortcuts import render
import ipaddress
from django.conf import settings


class network_tools:
	def WhatIsMyIP(request):
		IPAddress = get_ip_address_from_request(request)
		bIPAddress = '.'.join([bin(int(x) + 256)[3:] for x in IPAddress.split('.')])
		o = [int(item) for item in IPAddress.split('.')]
		iIPAddress = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]

		country_flag = "\u0939\u093f\u0928\u094d\u0926\u0940".encode('utf-16', 'surrogatepass').decode('utf-16')

		#
		reverse_pointer = ipaddress.ip_address(IPAddress).reverse_pointer

		template = loader.get_template('network_tools/WhatIsMyIP.html')
		context = {"IPAddress": IPAddress}
		is_local = "Yes" if is_local_ip(IPAddress) else "False"
		context['is_local'] = is_local
		context['bIPAddress'] = bIPAddress
		context['iIPAddress'] = iIPAddress
		context['reverse_pointer'] = reverse_pointer

		context['lang_01_code'] = 'hi'
		context['lang_01_name'] = 'Hindi'
		context['lang_01_native'] = "\u0939\u093f\u0928\u094d\u0926\u0940"
		context['lang_02_code'] = 'en'
		context['lang_02_name'] = 'English'
		context['lang_02_native'] = "English"

		context['country_flag'] = country_flag
		context['country_flag_emoji'] = "\ud83c\uddee\ud83c\uddf3"
		context['calling_code'] = "91"
		context['is_eu'] = False
		context['state'] = None

		#
		return render(request, 'network_tools/WhatIsMyIP.html', context)

	def DNSLookup(request):
		template = loader.get_template('network_tools/DNSLookup.html')
		return HttpResponse(template.render())
		pass