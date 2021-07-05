"""django_project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
import sys
from django.contrib import admin
from django.urls import path

#from . import views

from .controllers.default import default
from .controllers.network_tools import network_tools
from .controllers.fast_tools import fast_tools
from .controllers.ajaxify import ajaxify
# path('admin/', admin.site.urls)
urlpatterns = [
    path('', default.index, name='indexs'),
    path('test-dns-lookup.html', network_tools.DNSLookup, name='network_tools:DNSLookup'),
    path('what-is-my-ip-address.html', network_tools.WhatIsMyIP, name='network_tools:whatismyip'),
    path('fast-tools/http-server-header-test.html', fast_tools.HTTPServerHeaderTest, name='fast_tools.HTTPServerHeaderTest'),
    path('fast-tools/email-smtp-test.html', fast_tools.EmailSmtpTest, name='fast_tools.EmailSmtpTest'),
    path('ajaxify/email-smtp-response.json', ajaxify.email_smtp_response, name='ajaxify.EmailSmtpTest'),
    path('fast-tools/whatsapp-direct.html', fast_tools.WhatsappDirect, name='fast_tools.WhatsappDirect'),
    path('ajaxify/fetch_header_response.json', ajaxify.fetch_header_response, name='ajaxify_fetch_header_response'),
    path('ajaxify/whatsapp-direct-response.json', ajaxify.whatsapp_direct_response, name='ajaxify_fetch_header_response'),
]
