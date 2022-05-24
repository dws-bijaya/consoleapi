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
from .controllers.opensssl_tools import opensssl_tools
from .controllers.google_api import google_indexing_api


# path('admin/', admin.site.urls)
urlpatterns = [
    path('', default.index, name='indexs'),
    path('test-dns-lookup.html', network_tools.DNSLookup,
         name='network_tools:DNSLookup'),
    path('what-is-my-ip-address.html', network_tools.WhatIsMyIP,
         name='network_tools:whatismyip'),

    path('convert-ppk-to-pem.html', opensssl_tools.ConvertPpkToPem,
         name='opensssl_tools:ConvertPpkToPem'),
    path('ajaxify/convert-ppk-to-pem.json', ajaxify.convert_ppk_to_pem,
         name='ajaxify.convert_ppk_to_pem'),

    path('google-indexing-api.html', google_indexing_api.bulk_submit,
         name='opensssl_tools:bulk_submit'),
    path('ajaxify/google-indexing-api.json', ajaxify.google_indexing_api,
         name='ajaxify.convert_ppk_to_pem'),



    path('fast-tools/http-server-header-test.html',
         fast_tools.HTTPServerHeaderTest, name='fast_tools.HTTPServerHeaderTest'),


    path('fast-tools/email-smtp-test.html',
         fast_tools.EmailSmtpTest, name='fast_tools.EmailSmtpTest'),

    path('fast-tools/webpage-malware-scanner.html',
         fast_tools.WebpageMalwareScanner, name='fast_tools.WebpageMalwareScanner'),

    path('ajaxify/webpage-malware-scanner.json',
         ajaxify.webpage_malware_scanner_response, name='ajaxify.WebpageMalwareScanner'),

    path('test-domain-ssl-certificate.html',
         fast_tools.CheckDomainSSLCert, name='fast_tools.CheckDomainSSLCert'),
    path('ajaxify/fast-tools/domain-ssl-certificate.json',
         ajaxify.checker_ssl_cert, name='ajaxify:checker_ssl_cert'),



    path('check-blacklist-domain-ip.html',
         fast_tools.CheckBlacklistDomainIp, name='fast_tools.CheckBlacklistDomainIp'),
    path('ajaxify/blacklist-checker/get-servers.json',
         ajaxify.blacklist_checker_get_servers, name='ajaxify:blacklist_checker_get_servers'),
    path('ajaxify/blacklist-checker/get-status.json',
         ajaxify.blacklist_checker_get_status, name='ajaxify:blacklist_checker_get_status'),


    path('ajaxify/email-smtp-response.json',
         ajaxify.email_smtp_response, name='ajaxify.EmailSmtpTest'),
    path('fast-tools/whatsapp-direct.html',
         fast_tools.WhatsappDirect, name='fast_tools.WhatsappDirect'),
    path('ajaxify/fetch_header_response.json',
         ajaxify.fetch_header_response, name='ajaxify_fetch_header_response'),
    path('ajaxify/whatsapp-direct-response.json',
         ajaxify.whatsapp_direct_response, name='ajaxify_fetch_header_response'),
]
