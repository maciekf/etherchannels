from ethereum import channel

from rest_framework.decorators import api_view
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response


@api_view(['POST'])
def create_channel(request):
    new_channel_info = request.data
    if not channel.is_available(new_channel_info["cid"]):
        raise ValidationError("Channel id is not available")

    channel.create_channel(new_channel_info["from"],
                           new_channel_info["cid"],
                           new_channel_info["from"],
                           new_channel_info["to"])
    return Response()
