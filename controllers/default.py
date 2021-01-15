from django.http import HttpResponse, HttpRequest
from django.template import loader


class default:
	def index(request):
		template = loader.get_template('default/index.html')
		return HttpResponse(template.render())
		pass