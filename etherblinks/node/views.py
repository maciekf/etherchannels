import requests

from apps import deferred_task, monitor_channel

from django.contrib.auth.models import User
from django.conf import settings

from ethereum import channel

from models import ChannelState, HashedTimelockContract, Location, MicropaymentsChannel, UserAddress

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

    return Response({})


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def create_channel(request):
    cid = request.data["cid"]
    to_address = request.data["to"]
    from_address = request.user.useraddress.address
    owner = request.user
    co_owner_hostname = request.data["to_hostname"]
    co_owner_port = request.data["to_port"]

    channel.create_channel(from_address,
                           cid,
                           from_address,
                           to_address)
    _deferred_save_channel(cid, owner, from_address, to_address, co_owner_hostname, co_owner_port)
    _deferred_call_co_owner_save_channel(cid, from_address, to_address, co_owner_hostname, co_owner_port)
    return Response({})


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
    return Response({})


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def open_channel(request, cid):
    cid = int(cid)
    from_address = request.user.useraddress.address
    balance = request.data["balance"]

    channel.open_channel(from_address, cid, balance)
    return Response({})


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def confirm_channel(request, cid):
    cid = int(cid)
    balance = request.data["balance"]
    to_address = request.user.useraddress.address

    channel.confirm_channel(to_address, cid, balance)
    return Response({})


@api_view(['GET'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def get_channel(request, cid):
    cid = int(cid)
    owner = request.user
    micropayments_channel = MicropaymentsChannel.get(cid, owner)

    channel_info = {
        "stage": channel.get_stage(cid),
        "from": channel.get_from(cid),
        "from_balance": channel.get_from_balance(cid),
        "to": channel.get_to(cid),
        "to_balance": channel.get_to_balance(cid),
        "balance_timestamp": channel.get_balance_timestamp(cid),
        "closing_block_number": channel.get_closing_block_number(cid),
        "offline_state": _get_offline_channel_info(micropayments_channel)
    }

    return Response(channel_info)


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def send_htlc(request, cid):
    cid = int(cid)
    owner = request.user
    micropayments_channel = MicropaymentsChannel.get(cid, owner)
    value = request.data["value"]
    timeout = request.data["timeout"]

    _assert_owns_channel(cid, micropayments_channel.get_owner_address())
    _assert_channel_confirmed(cid)
    _assert_no_transaction_in_progress(micropayments_channel)

    _, _, balance_timestamp = _get_channel_state(micropayments_channel)
    from_to_delta = _get_from_to_delta(micropayments_channel, value)

    _assert_sufficient_funds_in_channel(micropayments_channel, from_to_delta)

    contract_data = channel.get_htlc_random_data()
    contract_hash = channel.get_hash(contract_data)

    htlc_signature = channel.get_htlc_signature(micropayments_channel.get_owner_address(),
                                                cid,
                                                balance_timestamp,
                                                timeout,
                                                contract_hash,
                                                from_to_delta)

    htlc = HashedTimelockContract.create(micropayments_channel,
                                         balance_timestamp,
                                         timeout,
                                         contract_hash,
                                         from_to_delta,
                                         contract_data,
                                         htlc_signature)
    htlc.save()

    _send_co_owner_htlc(htlc)

    return Response({"data": contract_data, "hash": contract_hash})


@api_view(['POST'])
def accept_htlc(request, cid):
    cid = int(cid)

    htlc = _parse_htlc(cid, request.data)
    htlc.save()

    return Response({})


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def claim_htlc_offline(request, cid):
    cid = int(cid)
    owner = request.user
    micropayments_channel = MicropaymentsChannel.get(cid, owner)
    contract_data = request.data["data"]
    contract_hash = request.data["hash"]

    _assert_owns_channel(cid, micropayments_channel.get_owner_address())
    _assert_channel_confirmed(cid)
    _assert_no_transaction_in_progress(micropayments_channel)
    _assert_data(contract_data, contract_hash)

    htlc = HashedTimelockContract.objects.get(channel=micropayments_channel,
                                              contract_hash=contract_hash,
                                              resolved=False)

    htlc.data = contract_data
    htlc.save()

    _update_channel(micropayments_channel, htlc)

    return Response({})


@api_view(['POST'])
def resolve_htlc_offline(request, cid):
    cid = int(cid)

    channel_state = _parse_channel_state(cid, request.data["channel_state"])

    micropayments_channel = channel_state.get_channel()
    htlc = HashedTimelockContract.objects.get(channel=micropayments_channel,
                                              data=request.data["htlc"]["data"],
                                              contract_hash=request.data["htlc"]["hash"],
                                              resolved=False)

    _assert_update_value(channel_state, htlc.get_from_to_delta())

    channel_state.save()

    try:
        invalidating_htlc = _parse_htlc(cid,
                                        {
                                            "balance_timestamp": channel_state.get_balance_timestamp(),
                                            "timeout": htlc.get_timeout(),
                                            "hash": htlc.get_hash(),
                                            "from_to_delta": -1 * htlc.get_from_to_delta(),
                                            "signature": request.data["invalidating_htlc_signature"]
                                        },
                                        False)
        invalidating_htlc.resolved = True
        invalidating_htlc.save()
    except ValidationError:
        channel_state.delete()
        raise

    htlc.resolved = True
    htlc.save()

    signature = channel.get_update_signature(micropayments_channel.get_owner_address(),
                                             cid,
                                             channel_state.get_balance_timestamp(),
                                             channel_state.get_from_balance(),
                                             channel_state.get_to_balance())
    channel_state.signature = signature
    channel_state.save()

    return Response({"signature": channel_state.get_signature()})


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def commit_update_channel(request, cid):
    cid = int(cid)
    owner = request.user
    owner_address = owner.useraddress.address

    _assert_owns_channel(cid, owner_address)

    updated_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=owner)
    channel_states = ChannelState.objects.filter(channel=updated_channel)

    if len(channel_states) == 1:
        channel_state = channel_states[0]
        channel.update_channel_state(owner_address,
                                     cid,
                                     int(channel_state.balance_timestamp),
                                     int(channel_state.from_balance),
                                     int(channel_state.to_balance),
                                     int(channel_state.second_signature))

    return Response({})


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def commit_htlc(request, cid):
    cid = int(cid)
    owner = request.user
    owner_address = owner.useraddress.address
    contract_hash = request.data["hash"]

    _assert_owns_channel(cid, owner_address)
    _, _, balance_timestamp = _get_channel_state(cid, owner)

    micropayments_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=owner)
    htlc = HashedTimelockContract.objects.filter(channel=micropayments_channel,
                                                 contract_hash=contract_hash)

    channel.resolve_htlc(owner_address,
                         cid,
                         balance_timestamp,
                         int(htlc.timeout),
                         contract_hash,
                         int(htlc.from_to_delta),
                         htlc.data,
                         htlc.second_signature)

    return Response({})


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def request_closing_channel(request, cid):
    cid = int(cid)
    owner = request.user
    owner_address = owner.useraddress.address

    channel.request_closing_channel(owner_address, cid)

    return Response({})


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def close_channel(request, cid):
    cid = int(cid)
    owner = request.user
    owner_address = owner.useraddress.address

    channel.close_channel(owner_address, cid)

    return Response({})


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def withdraw_from_channel(request, cid):
    cid = int(cid)
    owner = request.user
    owner_address = owner.useraddress.address

    if owner_address == channel.get_from(cid):
        channel.withdraw_from_channel(owner_address, cid)
    else:
        channel.withdraw_to_channel(owner_address, cid)

    return Response({})


def _parse_htlc(cid, htlc_data, atomic=True):
    balance_timestamp = htlc_data["balance_timestamp"]
    timeout = htlc_data["timeout"]
    contract_hash = htlc_data["hash"]
    from_to_delta = htlc_data["from_to_delta"]
    signature = htlc_data["signature"]

    htlc_hash = channel.get_htlc_hash(cid, balance_timestamp, timeout, contract_hash, from_to_delta)
    sender_address = channel.get_signer(htlc_hash, signature)

    receiver_address = _get_second_owner_address(cid, sender_address)
    receiver = UserAddress.objects.get(address=receiver_address).user
    micropayments_channel = MicropaymentsChannel.get(cid, receiver)

    _assert_owns_channel(cid, sender_address)
    _assert_channel_confirmed(cid)
    if atomic:
        _assert_no_transaction_in_progress(micropayments_channel)
    _assert_balance_timestamp(micropayments_channel, balance_timestamp)
    _assert_htlc_value(micropayments_channel, from_to_delta)
    _assert_sufficient_funds_in_channel(micropayments_channel, from_to_delta)

    return HashedTimelockContract.create(micropayments_channel,
                                         balance_timestamp,
                                         timeout,
                                         contract_hash,
                                         from_to_delta,
                                         "",
                                         signature)


def _parse_channel_state(cid, channel_state_data):
    balance_timestamp = channel_state_data["balance_timestamp"]
    from_balance = channel_state_data["from_balance"]
    to_balance = channel_state_data["to_balance"]
    second_signature = channel_state_data["signature"]
    update_hash = channel.get_update_hash(cid, balance_timestamp, from_balance, to_balance)
    sender_address = channel.get_signer(update_hash, second_signature)

    receiver_address = _get_second_owner_address(cid, sender_address)
    receiver = UserAddress.objects.get(address=receiver_address).user
    micropayments_channel = MicropaymentsChannel.get(cid, receiver)

    _assert_owns_channel(cid, sender_address)
    _assert_channel_confirmed(cid)
    _assert_no_transaction_in_progress(micropayments_channel)
    _assert_newer_balance_timestamp(micropayments_channel, balance_timestamp)

    return ChannelState.create(micropayments_channel,
                               balance_timestamp,
                               from_balance,
                               to_balance,
                               "",
                               second_signature)


def _update_channel(micropayments_channel, htlc):
    cid = micropayments_channel.get_cid()
    owner_address = micropayments_channel.get_owner_address()
    from_balance, to_balance, balance_timestamp = _get_channel_state(micropayments_channel)

    from_balance -= htlc.get_from_to_delta()
    to_balance += htlc.get_from_to_delta()
    balance_timestamp += 1

    update_signature = channel.get_update_signature(owner_address, cid, balance_timestamp, from_balance, to_balance)

    channel_state = ChannelState.create(micropayments_channel,
                                        balance_timestamp,
                                        from_balance,
                                        to_balance,
                                        update_signature,
                                        "")
    channel_state.save()

    reversed_htlc_signature = channel.get_htlc_signature(micropayments_channel.get_owner_address(),
                                                         cid,
                                                         balance_timestamp,
                                                         htlc.get_timeout(),
                                                         htlc.get_hash(),
                                                         -1 * htlc.get_from_to_delta())

    update_confirmation = _send_co_owner_update_channel(micropayments_channel,
                                                        channel_state,
                                                        htlc,
                                                        reversed_htlc_signature)

    update_hash = channel.get_update_hash(cid, balance_timestamp, from_balance, to_balance)
    _assert_both_owners(cid, owner_address, channel.get_signer(update_hash, update_confirmation["signature"]))

    channel_state.second_signature = update_confirmation["signature"]
    channel_state.save()

    htlc.resolved = True
    htlc.save()


def _assert_owns_channel(cid, address):
    if address != channel.get_from(cid) and address != channel.get_to(cid):
        raise ValidationError("User has to be an owner of the channel")


def _assert_both_owners(cid, address1, address2):
    if address1 == channel.get_from(cid) and address2 == channel.get_to(cid):
        return
    if address1 == channel.get_to(cid) and address2 == channel.get_from(cid):
        return
    raise ValidationError("Payment signature is invalid")


def _assert_no_transaction_in_progress(micropayments_channel):
    stored_states = ChannelState.objects.filter(channel=micropayments_channel)
    if len(stored_states) == 0:
        return
    if len(stored_states) == 1 and \
            stored_states[0].get_second_signature() != "" and \
            stored_states[0].get_signature() != "":
        return

    raise ValidationError("Previous transaction has been not accepted yet")


def _assert_htlc_value(micropayments_channel, from_to_delta):
    cid = micropayments_channel.get_cid()
    if (micropayments_channel.get_owner_address() == channel.get_from(cid) and from_to_delta > 0) or \
            (micropayments_channel.get_owner_address() == channel.get_to(cid) and from_to_delta < 0):
        raise ValidationError("Negative payment")


def _assert_update_value(channel_state, from_to_delta):
    micropayments_channel = channel_state.get_channel()
    current_from_balance, current_to_balance, _ = _get_channel_state(micropayments_channel)

    if current_from_balance - from_to_delta != channel_state.get_from_balance() or \
            current_to_balance + from_to_delta != channel_state.get_to_balance():
        raise ValidationError("Update balances are not valid")


def _assert_balance_timestamp(micropayments_channel, balance_timestamp):
    _, _, current_balance_timestamp = _get_channel_state(micropayments_channel)
    if current_balance_timestamp < balance_timestamp:
        raise ValidationError("Balance timestamp is invalid")


def _assert_newer_balance_timestamp(micropayments_channel, balance_timestamp):
    _, _, current_balance_timestamp = _get_channel_state(micropayments_channel)
    if balance_timestamp != current_balance_timestamp + 1:
        raise ValidationError("Balance timestamp is invalid")


def _assert_data(contract_data, contract_hash):
    if channel.get_hash(contract_data) != contract_hash:
        raise ValidationError("Data does not match hash")


def _assert_sufficient_funds_in_channel(micropayments_channel, from_to_delta):
    from_balance, to_balance, balance_timestamp = _get_channel_state(micropayments_channel)
    from_locked, to_locked = _get_locked_by_htlc(micropayments_channel)

    if from_balance - from_locked - from_to_delta < 0 or to_balance - to_locked + from_to_delta < 0:
            raise ValidationError("Not sufficient funds to perform this operation")


def _assert_channel_confirmed(cid):
    if channel.get_stage(cid) != channel.ChannelStage.CONFIRMED:
        raise ValidationError("Channel is not confirmed yet")


def _validate_channel(cid, owner, from_address, to_address):
    if owner.useraddress.address != from_address and owner.useraddress.address != to_address:
        raise ValidationError("User is not a participant in this channel")
    if channel.get_from(cid) != from_address:
        raise ValidationError("Channel from address is different on the blockchain")
    if channel.get_to(cid) != to_address:
        raise ValidationError("Channel to address is different on the blockchain")


def _save_channel(cid, owner, from_address, to_address, co_owner_hostname, co_owner_port):
    _validate_channel(cid, owner, from_address, to_address)

    co_owner_location, created = Location.objects.get_or_create(hostname=co_owner_hostname, port=co_owner_port)
    micropayments_channel = MicropaymentsChannel.create(cid, owner, co_owner_location)
    micropayments_channel.save()
    monitor_channel(micropayments_channel)


@deferred_task
def _deferred_save_channel(cid, owner, from_address, to_address, co_owner_hostname, co_owner_port):
    _save_channel(cid, owner, from_address, to_address, co_owner_hostname, co_owner_port)


def _call_co_owner_save_channel(cid, from_address, to_address, co_owner_hostname, co_owner_port):
    url = "http://%s:%s/node/channels/save/" % (co_owner_hostname, co_owner_port)
    requests.post(url,
                  json={
                      "cid": cid,
                      "from": from_address,
                      "to": to_address,
                      "owner": to_address,
                      "co_owner_hostname": settings.SERVER_HOSTNAME,
                      "co_owner_port": settings.SERVER_PORT
                  })


@deferred_task
def _deferred_call_co_owner_save_channel(cid, from_address, to_address, co_owner_hostname, co_owner_port):
    _call_co_owner_save_channel(cid, from_address, to_address, co_owner_hostname, co_owner_port)


def _send_co_owner_update_channel(micropayments_channel, channel_state, htlc, invalidating_htlc_signature):
    url = "/node/channels/%s/htlc/resolve/" % micropayments_channel.get_cid()
    data = {
        "channel_state": channel_state.to_request_dict(),
        "htlc": {
            "data": htlc.get_data(),
            "hash": htlc.get_hash()
        },
        "invalidating_htlc_signature": invalidating_htlc_signature
    }
    return _send_to_co_owner(micropayments_channel, url, data)


def _send_co_owner_htlc(htlc):
    url = "/node/channels/%s/htlc/accept/" % htlc.get_cid()
    return _send_to_co_owner(MicropaymentsChannel.get(htlc.get_cid(), htlc.get_owner()), url, htlc.to_request_dict())


def _send_to_co_owner(micropayments_channel, url, data):
    co_owner_location = micropayments_channel.get_co_owner_location()
    url = "http://%s:%s%s" % (co_owner_location.get_hostname(), co_owner_location.get_port(), url)
    response = requests.post(url, json=data)
    if response.status_code != 200:
        raise ValidationError("Co-owner did not respond correctly")

    return response.json()


def _get_second_owner_address(cid, owner):
    if owner == channel.get_from(cid):
        return channel.get_to(cid)
    else:
        return channel.get_from(cid)


def _get_channel_state(micropayments_channel):
    stored_states = ChannelState.objects.filter(channel=micropayments_channel)
    if len(stored_states) == 0:
        return channel.get_from_balance(micropayments_channel.get_cid()),\
               channel.get_to_balance(micropayments_channel.get_cid()),\
               channel.get_balance_timestamp(micropayments_channel.get_cid())
    else:
        return stored_states[0].get_from_balance(),\
               stored_states[0].get_to_balance(),\
               stored_states[0].get_balance_timestamp()


def _get_offline_channel_info(micropayments_channel):
    channel_states = ChannelState.objects.filter(channel=micropayments_channel)
    htlcs = HashedTimelockContract.objects.filter(channel=micropayments_channel,
                                                  resolved=False)
    htlcs_info = []
    for htlc in htlcs:
        htlc_info = {
            "from_to_delta": htlc.get_from_to_delta(),
            "timeout": htlc.get_timeout(),
            "data": htlc.get_data(),
            "hash": htlc.get_hash()
        }
        htlcs_info.append(htlc_info)

    offline_channel_info = {"htlcs": htlcs_info}

    if len(channel_states) == 1:
        channel_state = channel_states[0]
        offline_channel_info.update({
            "from_balance": channel_state.get_from_balance(),
            "to_balance": channel_state.get_to_balance(),
            "balance_timestamp": channel_state.get_balance_timestamp()
        })

    return offline_channel_info


def _get_from_to_delta(micropayments_channel, value):
    print(value)
    sender_address = micropayments_channel.get_owner_address()
    print(sender_address)
    if sender_address == channel.get_from(micropayments_channel.get_cid()):
        return value
    else:
        return -1 * value


def _get_locked_by_htlc(micropayments_channel):
    htlcs = HashedTimelockContract.objects.filter(channel=micropayments_channel,
                                                  resolved=False)

    from_locked, to_locked = 0, 0
    for htlc in htlcs:
        locked = htlc.get_from_to_delta()
        if locked > 0:
            from_locked += locked
        else:
            to_locked += locked

    return from_locked, to_locked
