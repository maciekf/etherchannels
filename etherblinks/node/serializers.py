from rest_framework import serializers


class NewChannelSerializer(serializers.Serializer):
    channel_id = serializers.CharField(max_length=70)
    from_address = serializers.CharField(max_length=70)
    to_address = serializers.CharField(max_length=70)