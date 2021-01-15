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

# path('admin/', admin.site.urls)
urlpatterns = [
    path('', default.index, name='indexs'),
    path('test-dns-lookup.html', network_tools.DNSLookup, name='network_tools:DNSLookup'),
    path('what-is-my-ip-address.html', network_tools.WhatIsMyIP, name='network_tools:whatismyip'),
]
