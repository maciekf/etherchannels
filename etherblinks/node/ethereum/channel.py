import binascii
import random

from django.conf import settings
from jsonrpc import EthJsonRpc


ethereum_client = EthJsonRpc(settings.ETHEREUM_HOSTNAME, settings.ETHEREUM_PORT)


class ChannelStage(object):
    EMPTY = 0
    PARTIALLY_CONFIRMED = 1
    CONFIRMED = 2
    CLOSING = 3
    CLOSED = 4


def is_available(cid):
    return ethereum_client.call(
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'isAvailable(uint256)',
        [cid],
        ['bool'])[0]


def create_channel(sender, cid, from_address, to_address):
    ethereum_client.call_with_transaction(
        sender,
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'createChannel(uint256,address,address)',
        [cid, from_address, to_address])


def get_stage(cid):
    return ethereum_client.call(
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'getStage(uint256)',
        [cid],
        ['uint8'])[0]


def get_from(cid):
    return ethereum_client.call(
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'getFrom(uint256)',
        [cid],
        ['address'])[0]


def get_from_balance(cid):
    return ethereum_client.call(
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'getFromBalance(uint256)',
        [cid],
        ['uint256'])[0]


def get_to(cid):
    return ethereum_client.call(
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'getTo(uint256)',
        [cid],
        ['address'])[0]


def get_to_balance(cid):
    return ethereum_client.call(
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'getToBalance(uint256)',
        [cid],
        ['uint256'])[0]


def get_balance_timestamp(cid):
    return ethereum_client.call(
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'getBalanceTimestamp(uint256)',
        [cid],
        ['uint256'])[0]


def get_closing_block_number(cid):
    return ethereum_client.call(
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'getClosingBlockNumber(uint256)',
        [cid],
        ['uint256'])[0]


def get_htlc_random_data():
    return binascii.hexlify(bytearray(random.getrandbits(8) for _ in xrange(32)))


def get_hash(data):
    data = binascii.unhexlify(data)
    hash_bytes = ethereum_client.call(
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'getHash(bytes32)',
        [data],
        ['bytes32'])
    return binascii.hexlify(hash_bytes[0])


def get_update_hash(cid, balance_timestamp, from_balance, to_balance):
    hash_bytes = ethereum_client.call(
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'getUpdateHash(uint256,uint256,uint256,uint256)',
        [cid, balance_timestamp, from_balance, to_balance],
        ['bytes32'])
    return binascii.hexlify(hash_bytes[0])


def get_update_signature(signer, cid, balance_timestamp, from_balance, to_balance):
    update_hash = get_update_hash(cid, balance_timestamp, from_balance, to_balance)
    return ethereum_client.eth_sign(signer, update_hash)[2:]


def get_htlc_hash(cid, balance_timestamp, timeout, contract_hash, from_to_delta):
    contract_hash = binascii.unhexlify(contract_hash)
    hash_bytes = ethereum_client.call(
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'getHTLCHash(uint256,uint256,uint256,bytes32,int256)',
        [cid, balance_timestamp, timeout, contract_hash, from_to_delta],
        ['bytes32'])
    return binascii.hexlify(hash_bytes[0])


def get_htlc_signature(signer, cid, balance_timestamp, timeout, contract_hash, from_to_delta):
    htlc_hash = get_htlc_hash(cid, balance_timestamp, timeout, contract_hash, from_to_delta)
    return ethereum_client.eth_sign(signer, htlc_hash)[2:]


def get_signer(signed_hash, signature):
    signed_hash = binascii.unhexlify(signed_hash)
    sig_v, sig_r, sig_s = _unpack_signature(signature)
    return ethereum_client.call(
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'getSigner(bytes32,uint8,bytes32,bytes32)',
        [signed_hash, sig_v, sig_r, sig_s],
        ['address'])[0]


def open_channel(sender, cid, balance):
    ethereum_client.call_with_transaction(
        sender,
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'openChannel(uint256)',
        [cid],
        value=balance)


def confirm_channel(sender, cid, balance):
    ethereum_client.call_with_transaction(
        sender,
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'confirmChannel(uint256)',
        [cid],
        value=balance)


def request_closing_channel(sender, cid):
    ethereum_client.call_with_transaction(
        sender,
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'requestClosingChannel(uint256)',
        [cid])


def close_channel(sender, cid):
    ethereum_client.call_with_transaction(
        sender,
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'closeChannel(uint256)',
        [cid])


def withdraw_from_channel(sender, cid):
    ethereum_client.call_with_transaction(
        sender,
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'withdrawFrom(uint256)',
        [cid])


def withdraw_to_channel(sender, cid):
    ethereum_client.call_with_transaction(
        sender,
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'withdrawTo(uint256)',
        [cid])


def update_channel_state(sender, cid, balance_timestamp, from_balance, to_balance, signature):
    sig_v, sig_r, sig_s = _unpack_signature(signature)
    ethereum_client.call_with_transaction(
        sender,
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'updateChannelState(uint256,uint256,uint256,uint256,uint8,bytes32,bytes32)',
        [cid, balance_timestamp, from_balance, to_balance, sig_v, sig_r, sig_s])


def resolve_htlc(sender, cid, balance_timestamp, timeout, contract_hash, from_to_delta, data, signature):
    contract_hash = binascii.unhexlify(contract_hash)
    data = binascii.unhexlify(data)
    sig_v, sig_r, sig_s = _unpack_signature(signature)
    ethereum_client.call_with_transaction(
        sender,
        settings.MICROPAYMENTS_NETWORK_ADDRESS,
        'resolveHTLC(uint256,uint256,uint256,bytes32,int256,bytes32,uint8,bytes32,bytes32)',
        [cid, balance_timestamp, timeout, contract_hash, from_to_delta, data, sig_v, sig_r, sig_s])


def _unpack_signature(signature):
    sig_v = int(signature[128:130]) + 27
    sig_r = binascii.unhexlify(signature[0:64])
    sig_s = binascii.unhexlify(signature[64:128])
    return sig_v, sig_r, sig_s
