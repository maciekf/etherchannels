import requests

from apps import deferred_task

from django.contrib.auth.models import User
from django.conf import settings

from ethereum import channel

from models import Location, MicropaymentsChannel, UserAddress

from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response


@api_view(['POST'])
def register(request):
    new_user_info = request.data

    user = User.objects.create_user(new_user_info['name'], new_user_info['email'], new_user_info['password'])
    user.full_clean()

    user_address = UserAddress.create(user, new_user_info['address'])
    user_address.full_clean()

    user.save()
    user_address.save()

    return Response()


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def create_channel(request):
    cid = request.data["cid"]
    to_address = request.data["to"]
    from_address = request.user.useraddress.address
    owner = request.user
    co_owner_hostname = request.data["co_owner_hostname"]
    co_owner_port = request.data["co_owner_port"]

    channel.create_channel(from_address,
                           cid,
                           from_address,
                           to_address)
    _deferred_save_channel(cid, owner, from_address, to_address, co_owner_hostname, co_owner_port)
    _deferred_call_co_owner_save_channel(cid, from_address, to_address, co_owner_hostname, co_owner_port)
    return Response()


@api_view(['GET'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def list_channels(request):
    channel_ids = [user_channel.channel_id for user_channel in MicropaymentsChannel.objects.filter(owner=request.user)]
    return Response(channel_ids)


@api_view(['POST'])
def save_channel(request):
    cid = request.data["cid"]
    from_address = request.data["from"]
    to_address = request.data["to"]
    owner = UserAddress.objects.get(address=request.data["owner"]).user
    co_owner_hostname = request.data["co_owner_hostname"]
    co_owner_port = request.data["co_owner_port"]

    _save_channel(cid, owner, from_address, to_address, co_owner_hostname, co_owner_port)
    return Response()


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def open_channel(request, cid):
    cid = int(cid)
    from_address = request.user.useraddress.address
    balance = request.data["balance"]

    channel.open_channel(from_address, cid, balance)
    return Response()


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def confirm_channel(request, cid):
    cid = int(cid)
    balance = request.data["balance"]
    to_address = request.user.useraddress.address

    channel.confirm_channel(to_address, cid, balance)
    return Response()


def _save_channel(cid, owner, from_address, to_address, co_owner_hostname, co_owner_port):
    _validate_channel(cid, from_address, to_address)

    co_owner_location = Location.objects.get_or_create(hostname=co_owner_hostname, port=co_owner_port)
    micropayments_channel = MicropaymentsChannel.create(cid, owner, co_owner_location)
    micropayments_channel.save()


@deferred_task
def _deferred_save_channel(cid, owner, from_address, to_address, co_owner_hostname, co_owner_port):
    _save_channel(cid, owner, from_address, to_address, co_owner_hostname, co_owner_port)


def _validate_channel(cid, from_address, to_address):
    if channel.get_from(cid) != from_address:
        raise ValidationError("Channel from address is different on the blockchain")
    if channel.get_to(cid) != to_address:
        raise ValidationError("Channel to address is different on the blockchain")


@deferred_task
def _deferred_call_co_owner_save_channel(cid, from_address, to_address, co_owner_hostname, co_owner_port):
    requests.post("http://%s:%s/node/channels/save/" % (co_owner_hostname, co_owner_port), {
        "cid": cid,
        "from": from_address,
        "to": to_address,
        "owner": to_address,
        "co_owner_hostname": settings.SERVER_HOSTNAME,
        "co_owner_port": settings.SERVER_PORT})
