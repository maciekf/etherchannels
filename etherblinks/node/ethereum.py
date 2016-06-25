from django.conf import settings
from ethjsonrpc import EthJsonRpc

ethereum_client = EthJsonRpc(settings.ETHEREUM_HOSTNAME, settings.ETHEREUM_PORT)


def create_channel(owner, from_address, to_address, channel_id):
    ethereum_client.call_with_transaction(
        owner,
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'registerChannel(address,address,uint)', [from_address, to_address, channel_id])


def get_channel_address(from_address, to_address, channel_id):
    ethereum_client.call(
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'getChannel(address,address,uint)', [from_address, to_address, channel_id])
