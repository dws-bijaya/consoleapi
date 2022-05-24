from django.http import HttpResponse, HttpRequest
from django.template import loader, Context
from django.shortcuts import render


class fast_tools:
    def CheckDomainSSLCert(request):
        domain_ip = request.GET.get("domain_ip", '')
        port = request.GET.get("port", '443')
        resolve_ip = request.GET.get("resolve_ip", '')

        context = {
            'domain_ip': domain_ip,
            'port': port,
            'resolve_ip': resolve_ip,
            'meta_title': "Test domain's SSL Certificate: Quickly check domain's SSL has valid certificate or not."}
        context['meta_description'] = "Free and fast tools to check domain's SSL has valid certificate or not and view information like comman name, issuer etc."
        return render(request, 'fast_tools/CheckDomainSSLCert.html', context)

    def CheckBlacklistDomainIp(request):
        context = {
            'meta_title': "Email blacklist tools: check now your email domain & email server IP is blacklisted or not."}
        context['meta_description'] = "Free and fast tools to check your email domain or mail server sender IP is blacklisted or not against more that 250+ DNS servers to keep a healthy sender score and maximize your inbox placement."
        return render(request, 'fast_tools/CheckBlacklistDomainIp.html', context)

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
        context = {'User_Agent': User_Agent,
                   'meta_title': 'Free Fast tools for testing SMTP email sending'}
        return render(request, 'fast_tools/EmailSmtpTest.html', context)

    def WhatsappDirect(request):
        IPAddress = '127.0.0.1'  # get_ip_address_from_request(request)
        User_Agent = request.META['HTTP_USER_AGENT']
        context = {'User_Agent': User_Agent}
        context = {
            'meta_title': "Generate WhatsAapp Link and Send Messages Directly"}
        context['meta_description'] = "Send WhatsApp messages to any nonsaved contact numbers directly and also Create a personalised WhatsApp link with a pre-defined message in seconds and share it with your audience on social media!"

        return render(request, 'fast_tools/WhatsappDirect.html', context)
