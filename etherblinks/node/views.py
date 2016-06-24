from ethjsonrpc import EthJsonRpc
from django.http import HttpResponse

def index(request):
    return HttpResponse("Hello, world")
