from apps import deferred_task

from django.contrib.auth.models import User

from ethereum import channel

from models import MicropaymentsChannel, UserAddress

from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response


@api_view(['PUT'])
def register(request):
    new_user_info = request.data

    user = User.objects.create_user(new_user_info['name'], new_user_info['email'], new_user_info['password'])
    user.full_clean()

    user_address = UserAddress.create(user, new_user_info['address'])
    user_address.full_clean()

    user.save()
    user_address.save()

    return Response()


@api_view(['PUT'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def create_channel(request):
    cid = request.data["cid"]
    to_address = request.data["to"]
    from_address = request.user.useraddress.address
    if not channel.is_available(cid):
        raise ValidationError("Channel id is not available")

    channel.create_channel(from_address,
                           cid,
                           from_address,
                           to_address)
    deferred_save_channel(from_address, cid)
    return Response()


@api_view(['POST'])
def register_created_channel(request):
    cid = request.data["cid"]
    owner = UserAddress.objects.get(address=channel.get_to(cid)).user

    micropayments_channel = MicropaymentsChannel.create(cid, owner)
    micropayments_channel.save()
    return Response()


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def open_channel(request):
    cid = request.data["cid"]
    balance = request.data["balance"]
    if request.user.useraddress.address != channel.get_from(cid):
        raise ValidationError("User is not from recipient of the channel")
    if channel.get_stage(cid) != channel.ChannelStage.EMPTY:
        raise ValidationError("Channel is in invalid stage")

    channel.open_channel(request.user.useraddress.address, cid, balance)
    return Response()


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def confirm_channel(request):
    cid = request.data["cid"]
    balance = request.data["balance"]
    if request.user.useraddress.address != channel.get_to(cid):
        raise ValidationError("User is not from recipient of the channel")
    if channel.get_stage(cid) != channel.ChannelStage.PARTIALLY_CONFIRMED:
        raise ValidationError("Channel is in invalid stage")

    channel.confirm_channel(request.user.useraddress.address, cid, balance)
    return Response()


@deferred_task
def deferred_save_channel(useraddress, cid):
    if channel.get_from(cid) != useraddress.address:
        raise ValueError("Channel does not exist on the blockchain")

    micropayments_channel = MicropaymentsChannel.create(cid, useraddress.user)
    micropayments_channel.save()
