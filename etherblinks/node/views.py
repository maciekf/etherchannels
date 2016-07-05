from ethereum import channel

from apps import deferred_task

from django.contrib.auth.models import User

from models import UserAddress

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
    new_channel_info = request.data
    if not channel.is_available(new_channel_info["cid"]):
        raise ValidationError("Channel id is not available")

    channel.create_channel(new_channel_info["from"],
                           new_channel_info["cid"],
                           new_channel_info["from"],
                           new_channel_info["to"])
    deferred_save_channel(new_channel_info["cid"])
    return Response()


@deferred_task
def deferred_save_channel(cid):
    print("sth")
