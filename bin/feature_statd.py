from datetime import datetime


class feature_statd:

    @classmethod
    def remote_ip(self, request):
        ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get(
            'REMOTE_ADDR', '')).split(',')[0].strip()
        return ip

    @classmethod
    def write(self, wfile, ip, data):
        format = "%Y-%m-%d %H:%M:%S %z"
        now_utc = datetime.now()
        with open(wfile, 'a+') as p:
            p.write("{time},{ip},{data}\n".format(
                time=now_utc.strftime(format), ip=ip, data=data))
        # ajaxify.checker_ssl_cert

    @classmethod
    def record2(self, request, data):
        wfile = '/tmp/record2.csv'
        ip = self.remote_ip(request)
        self.write(wfile, ip, data)

    # blacklist_checker_get_servers

    @classmethod
    def record1(self, request, data):
        wfile = '/tmp/record1.csv'
        ip = self.remote_ip(request)
        self.write(wfile, ip, data)
