from django.conf import settings
from jsonrpc import EthJsonRpc


ethereum_client = EthJsonRpc(settings.ETHEREUM_HOSTNAME, settings.ETHEREUM_PORT)


def create_channel(owner, from_address, to_address, channel_id):
    ethereum_client.call_with_transaction(
        owner,
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'registerChannel(address,address,uint256)', [from_address, to_address, channel_id],
        gas=4700000)


def get_channel(channel_id):
    return ethereum_client.call(
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'getChannel(uint256)', [channel_id], ['address'])
