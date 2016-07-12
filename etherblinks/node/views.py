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

    return Response()


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


@api_view(['GET'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def get_channel(request, cid):
    cid = int(cid)
    owner = request.user

    channel_info = {
        "stage": channel.get_stage(cid),
        "from": channel.get_from(cid),
        "from_balance": channel.get_from_balance(cid),
        "to": channel.get_to(cid),
        "to_balance": channel.get_to_balance(cid),
        "balance_timestamp": channel.get_balance_timestamp(cid),
        "closing_block_number": channel.get_closing_block_number(cid),
        "offline_state": _get_offline_channel_info(cid, owner)
    }

    return Response(channel_info)


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def send_htlc(request, cid):
    cid = int(cid)
    sender = request.user
    sender_address = sender.useraddress.address
    value = request.data["value"]
    timeout = request.data["timeout"]

    _assert_owns_channel(sender_address, cid)
    _assert_channel_confirmed(cid)

    _, _, balance_timestamp = _get_channel_state(cid, sender)
    from_to_delta = _get_from_to_delta(cid, sender, value)
    contract_data = channel.get_htlc_random_data()
    contract_hash = channel.get_hash(contract_data)

    micropayments_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=sender)
    htlc = HashedTimelockContract.create(micropayments_channel,
                                         balance_timestamp,
                                         timeout,
                                         contract_hash,
                                         from_to_delta,
                                         contract_data,
                                         "")
    htlc.save()

    htlc_signature = channel.get_htlc_signature(sender_address,
                                                cid,
                                                balance_timestamp,
                                                timeout,
                                                contract_hash,
                                                from_to_delta)

    _send_co_owner_htlc(cid, sender, balance_timestamp, timeout, contract_hash, from_to_delta, htlc_signature)

    return Response({"data": contract_data})


@api_view(['POST'])
def accept_htlc(request, cid):
    cid = int(cid)
    receiver_address = request.data["receiver"]
    receiver = UserAddress.objects.get(address=receiver_address).user
    balance_timestamp = request.data["balance_timestamp"]
    timeout = request.data["timeout"]
    contract_hash = request.data["contract_hash"]
    from_to_delta = request.data["from_to_delta"]
    second_signature = request.data["second_signature"]

    htlc_hash = channel.get_htlc_hash(cid, balance_timestamp, timeout, contract_hash, from_to_delta)
    sender_address = channel.get_signer(htlc_hash, second_signature)

    _assert_owns_channel(receiver_address, cid)
    _assert_channel_confirmed(cid)
    _assert_equal_balance_timestamp(cid, receiver, balance_timestamp)
    _assert_htlc_value(cid, receiver_address, from_to_delta)
    _assert_sufficient_funds_in_channel(cid, receiver, from_to_delta)
    _assert_both_owners(cid, sender_address, receiver_address)

    micropayments_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=receiver)
    htlc = HashedTimelockContract.create(micropayments_channel,
                                         balance_timestamp,
                                         timeout,
                                         contract_hash,
                                         from_to_delta,
                                         "",
                                         second_signature)
    htlc.save()

    return Response()


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def resolve_htlc_offline(request, cid):
    cid = int(cid)
    receiver = request.user
    receiver_address = receiver.useraddress.address
    contract_data = request.data["contract_data"]
    contract_hash = request.data["contract_hash"]

    _assert_owns_channel(receiver_address, cid)
    _assert_channel_confirmed(cid)
    _assert_data(contract_data, contract_hash)

    from_balance, to_balance, balance_timestamp = _get_channel_state(cid, receiver)
    micropayments_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=receiver)
    htlc = HashedTimelockContract.objects.get(channel=micropayments_channel,
                                              balance_timestamp=balance_timestamp,
                                              contract_hash=contract_hash)
    htlc.data = contract_data
    htlc.save()

    _update_htlcs(cid, receiver)
    _send_co_owner_htlc_data(cid, receiver, balance_timestamp, contract_data, contract_hash)

    return Response()


@api_view(['POST'])
def accept_htlc_data(request, cid):
    cid = int(cid)
    sender_address = request.data["sender"]
    sender = UserAddress.objects.get(address=sender_address).user
    balance_timestamp = request.data["balance_timestamp"]
    contract_data = request.data["contract_data"]
    contract_hash = request.data["contract_hash"]

    _assert_owns_channel(sender_address, cid)
    _assert_channel_confirmed(cid)
    _assert_equal_balance_timestamp(cid, sender, balance_timestamp)
    _assert_data(contract_data, contract_hash)
    _assert_all_htlcs_updated(cid, sender)

    from_balance, to_balance, balance_timestamp = _get_channel_state(cid, sender)
    micropayments_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=sender)
    htlc = HashedTimelockContract.objects.get(channel=micropayments_channel,
                                              balance_timestamp=balance_timestamp,
                                              contract_hash=contract_hash)

    from_to_delta = int(htlc.from_to_delta)
    from_balance -= from_to_delta
    to_balance += from_to_delta

    htlc.resolved = True
    htlc.save()

    _update_htlcs(cid, sender)
    _update_channel(cid, sender, from_balance, to_balance)

    return Response()


@api_view(['POST'])
def accept_htlc_update(request, cid):
    cid = int(cid)
    receiver_address = request.data["receiver"]
    receiver = UserAddress.objects.get(address=receiver_address).user
    balance_timestamp = request.data["balance_timestamp"]
    contract_hash = request.data["contract_hash"]
    second_signature = request.data["second_signature"]

    micropayments_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=receiver)
    htlc = HashedTimelockContract.objects.get(channel=micropayments_channel,
                                              balance_timestamp=balance_timestamp-1,
                                              contract_hash=contract_hash)

    htlc_hash = channel.get_htlc_hash(cid, balance_timestamp, int(htlc.timeout), contract_hash, int(htlc.from_to_delta))
    sender_address = channel.get_signer(htlc_hash, second_signature)

    _assert_owns_channel(receiver_address, cid)
    _assert_channel_confirmed(cid)
    _assert_balance_timestamp(cid, receiver, balance_timestamp)
    _assert_both_owners(cid, sender_address, receiver_address)

    htlc.pk = None
    htlc.balance_timestamp = balance_timestamp
    htlc.second_signature = second_signature
    htlc.save()

    return Response()


@api_view(['POST'])
def accept_update_channel(request, cid):
    cid = int(cid)
    receiver_address = request.data["receiver"]
    receiver = UserAddress.objects.get(address=receiver_address).user
    balance_timestamp = request.data["balance_timestamp"]
    from_balance = request.data["from_balance"]
    to_balance = request.data["to_balance"]
    second_signature = request.data["second_signature"]
    update_hash = channel.get_update_hash(cid, balance_timestamp, from_balance, to_balance)
    sender_address = channel.get_signer(update_hash, second_signature)

    _assert_owns_channel(receiver_address, cid)
    _assert_channel_confirmed(cid)
    _assert_balance_timestamp(cid, receiver, balance_timestamp)
    _assert_both_owners(cid, sender_address, receiver_address)
    _assert_all_htlcs_updated(cid, receiver)
    _assert_update_value(cid, receiver, balance_timestamp, from_balance, to_balance)

    updated_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=receiver)
    ChannelState.objects.filter(channel=updated_channel).delete()
    channel_state = ChannelState.create(updated_channel, balance_timestamp, from_balance, to_balance, second_signature)
    channel_state.save()

    update_signature = channel.get_update_signature(receiver_address, cid, balance_timestamp, from_balance, to_balance)

    _send_co_owner_accept_update_channel(cid, receiver, balance_timestamp, update_signature)
    return Response()


@api_view(['POST'])
def confirm_update_channel(request, cid):
    cid = int(cid)
    sender_address = request.data["sender"]
    sender = UserAddress.objects.get(address=sender_address).user
    second_signature = request.data["second_signature"]
    balance_timestamp = request.data["balance_timestamp"]

    updated_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=sender)
    channel_state = ChannelState.objects.get(channel=updated_channel, balance_timestamp=balance_timestamp)

    update_hash = channel.get_update_hash(cid,
                                          balance_timestamp,
                                          int(channel_state.from_balance),
                                          int(channel_state.to_balance))
    receiver_address = channel.get_signer(update_hash, second_signature)

    _assert_owns_channel(sender_address, cid)
    _assert_both_owners(cid, sender_address, receiver_address)

    ChannelState.objects.filter(channel=updated_channel).delete()
    channel_state.second_signature = second_signature
    channel_state.save()

    return Response()


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def commit_update_channel(request, cid):
    cid = int(cid)
    owner = request.user
    owner_address = owner.useraddress.address

    _assert_owns_channel(owner_address, cid)

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

    return Response()


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def request_closing_channel(request, cid):
    cid = int(cid)
    owner = request.user
    owner_address = owner.useraddress.address

    channel.request_closing_channel(owner_address, cid)

    return Response()


@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def close_channel(request, cid):
    cid = int(cid)
    owner = request.user
    owner_address = owner.useraddress.address

    channel.close_channel(owner_address, cid)

    return Response()


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

    return Response()


def _assert_owns_channel(address, cid):
    if address != channel.get_from(cid) and address != channel.get_to(cid):
        raise ValidationError("User has to be an owner of the channel")


def _assert_both_owners(cid, address1, address2):
    if address1 == channel.get_from(cid) and address2 == channel.get_to(cid):
        return
    if address1 == channel.get_to(cid) and address2 == channel.get_from(cid):
        return
    raise ValidationError("Payment signature is invalid")


def _assert_htlc_value(cid, receiver_address, from_to_delta):
    if (receiver_address == channel.get_from(cid) and from_to_delta > 0) or \
            (receiver_address == channel.get_to(cid) and from_to_delta < 0):
        raise ValidationError("Negative payment")


def _assert_update_value(cid, owner, balance_timestamp, from_balance, to_balance):
    current_from_balance, current_to_balance, = _get_channel_state(cid, owner)
    micropayments_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=owner)
    htlcs = HashedTimelockContract.objects.filter(channel=micropayments_channel,
                                                  balance_timestamp=balance_timestamp - 1).exclude(
                                                  second_signature='').exclude(
                                                  data='')
    if len(htlcs) != 1:
        raise ValidationError("Invalid number of htlcs to resolve")
    htlc = htlcs[0]

    from_to_delta = int(htlc.from_to_delta)
    current_from_balance -= from_to_delta
    current_to_balance += from_to_delta

    if current_from_balance != from_balance or current_to_balance != to_balance:
        raise ValidationError("Update balances are not valid")


def _assert_balance_timestamp(cid, owner, balance_timestamp):
    _, _, current_balance_timestamp = _get_channel_state(cid, owner)
    if balance_timestamp != current_balance_timestamp + 1:
        raise ValidationError("Balance timestamp is invalid")


def _assert_equal_balance_timestamp(cid, owner, balance_timestamp):
    _, _, current_balance_timestamp = _get_channel_state(cid, owner)
    if balance_timestamp != current_balance_timestamp:
        raise ValidationError("Balance timestamp is invalid")


def _assert_data(contract_data, contract_hash):
    if channel.get_hash(contract_data) != contract_hash:
        raise ValidationError("Data does not match hash")


def _assert_sufficient_funds_in_channel(cid, receiver, from_to_delta):
        receiver_address = receiver.useraddress.address
        from_balance, to_balance, balance_timestamp = _get_channel_state(cid, receiver)
        sender_locked_balance = _get_balance_received_by_htlc(cid, receiver, balance_timestamp)

        if receiver_address == channel.get_from(cid):
            if to_balance - sender_locked_balance < -from_to_delta:
                raise ValidationError("Not sufficient funds to perform this operation")
        elif receiver_address != channel.get_to(cid):
            if from_balance - sender_locked_balance < from_to_delta:
                raise ValidationError("Not sufficient funds to perform this operation")


def _assert_all_htlcs_updated(cid, owner):
    pass


def _assert_channel_confirmed(cid):
    if channel.get_stage(cid) != channel.ChannelStage.CONFIRMED:
        raise ValidationError("Channel is not confirmed yet")


def _save_channel(cid, owner, from_address, to_address, co_owner_hostname, co_owner_port):
    _validate_channel(cid, owner, from_address, to_address)

    co_owner_location, created = Location.objects.get_or_create(hostname=co_owner_hostname, port=co_owner_port)
    micropayments_channel = MicropaymentsChannel.create(cid, owner, co_owner_location)
    micropayments_channel.save()
    monitor_channel(micropayments_channel)


@deferred_task
def _deferred_save_channel(cid, owner, from_address, to_address, co_owner_hostname, co_owner_port):
    _save_channel(cid, owner, from_address, to_address, co_owner_hostname, co_owner_port)


def _validate_channel(cid, owner, from_address, to_address):
    if owner.useraddress.address != from_address and owner.useraddress.address != to_address:
        raise ValidationError("User is not a participant in this channel")
    if channel.get_from(cid) != from_address:
        raise ValidationError("Channel from address is different on the blockchain")
    if channel.get_to(cid) != to_address:
        raise ValidationError("Channel to address is different on the blockchain")


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


def _update_channel(cid, owner, from_balance, to_balance):
    owner_address = owner.useraddress.address
    _, _, balance_timestamp = _get_channel_state(cid, owner)
    update_signature = channel.get_update_signature(owner_address, cid, balance_timestamp, from_balance, to_balance)

    updated_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=owner)
    channel_state = ChannelState.create(updated_channel, balance_timestamp, from_balance, to_balance, "")
    channel_state.save()

    _send_co_owner_update_channel(cid, owner, balance_timestamp, from_balance, to_balance, update_signature)

    return Response()


def _get_channel_state(cid, owner):
    stored_states = ChannelState.objects.filter(channel=MicropaymentsChannel.objects.get(channel_id=cid, owner=owner))
    if len(stored_states) == 0:
        return channel.get_from_balance(cid),\
               channel.get_to_balance(cid),\
               channel.get_balance_timestamp(cid)
    elif len(stored_states) == 1 and stored_states[0].second_signature != "":
        return int(stored_states[0].from_balance),\
               int(stored_states[0].to_balance),\
               int(stored_states[0].balance_timestamp)
    else:
        raise ValidationError("Previous transaction has been not accepted yet")


def _get_offline_channel_info(cid, owner):
    updated_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=owner)
    channel_states = ChannelState.objects.filter(channel=updated_channel)
    if len(channel_states) == 1:
        channel_state = channel_states[0]
        return {
            "from_balance": int(channel_state.from_balance),
            "to_balance": int(channel_state.to_balance),
            "balance_timestamp": int(channel_state.balance_timestamp),
        }


def _get_updated_channel_state(cid, sender, to_send):
    from_balance, to_balance, balance_timestamp = _get_channel_state(cid, sender)
    sender_address = sender.useraddress.address

    if sender_address == channel.get_from(cid):
        from_balance = from_balance - to_send
        to_balance = to_balance + to_send
    else:
        to_balance = from_balance - to_send
        from_balance = from_balance + to_send

    if from_balance < 0 or to_balance < 0:
        raise ValidationError("Not sufficient funds to perform this operation")

    return from_balance, to_balance, balance_timestamp + 1


def _update_htlcs(cid, owner):
    _, _, balance_timestamp = _get_channel_state(cid, owner)
    micropayments_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=owner)
    htlcs = HashedTimelockContract.objects.filter(channel=micropayments_channel,
                                                  balance_timestamp=balance_timestamp,
                                                  resolved=False,
                                                  second_signature='')
    for htlc in htlcs:
        htlc.pk = None
        htlc.balance_timestamp = int(htlc.balance_timestamp) + 1
        htlc.save()

        htlc_signature = channel.get_htlc_signature(owner.useraddress.address,
                                                    cid,
                                                    balance_timestamp,
                                                    int(htlc.timeout),
                                                    htlc.contract_hash,
                                                    int(htlc.from_to_delta))
        _send_co_owner_htlc_update(cid, owner, int(htlc.balance_timestamp), htlc.contract_hash, htlc_signature)


def _update_channel(cid, owner, from_balance, to_balance):
    owner_address = owner.useraddress.address
    _, _, balance_timestamp = _get_channel_state(cid, owner)
    update_signature = channel.get_update_signature(owner_address, cid, balance_timestamp, from_balance, to_balance)

    updated_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=owner)
    channel_state = ChannelState.create(updated_channel, balance_timestamp, from_balance, to_balance, "")
    channel_state.save()

    _send_co_owner_update_channel(cid, owner, balance_timestamp, from_balance, to_balance, update_signature)


def _send_co_owner_htlc_data(cid, owner, balance_timestamp, contract_data, contract_hash):
    url = "/node/channels/%s/htlc/resolve/" % cid
    co_owner = channel.get_from(cid) if channel.get_from(cid) != owner.useraddress.address else channel.get_to(cid)
    data = {
        "sender": co_owner,
        "balance_timestamp": balance_timestamp,
        "contract_data": contract_data,
        "contract_hash": contract_hash
    }
    _send_to_co_owner(cid, owner, url, data)


def _send_co_owner_update_channel(cid, owner, balance_timestamp, from_balance, to_balance, update_signature):
    url = "/node/channels/%s/payment/accept/" % cid
    co_owner = channel.get_from(cid) if channel.get_from(cid) != owner.useraddress.address else channel.get_to(cid)
    data = {
        "receiver": co_owner,
        "balance_timestamp": balance_timestamp,
        "from_balance": from_balance,
        "to_balance": to_balance,
        "second_signature": update_signature
    }
    _send_to_co_owner(cid, owner, url, data)


def _send_co_owner_accept_update_channel(cid, owner, balance_timestamp, update_signature):
    url = "/node/channels/%s/payment/confirm/" % cid
    co_owner = channel.get_from(cid) if channel.get_from(cid) != owner.useraddress.address else channel.get_to(cid)
    data = {
        "sender": co_owner,
        "balance_timestamp": balance_timestamp,
        "second_signature": update_signature
    }
    _send_to_co_owner(cid, owner, url, data)


def _send_co_owner_htlc(cid, owner, balance_timestamp, timeout, contract_hash, from_to_delta, htlc_signature):
    url = "/node/channels/%s/htlc/accept/" % cid
    co_owner = channel.get_from(cid) if channel.get_from(cid) != owner.useraddress.address else channel.get_to(cid)
    data = {
        "receiver": co_owner,
        "balance_timestamp": balance_timestamp,
        "timeout": timeout,
        "contract_hash": contract_hash,
        "from_to_delta": from_to_delta,
        "second_signature": htlc_signature
    }
    _send_to_co_owner(cid, owner, url, data)


def _send_co_owner_htlc_update(cid, owner, balance_timestamp, contract_hash, htlc_signature):
    url = "/node/channels/%s/htlc/update/accept/" % cid
    co_owner = channel.get_from(cid) if channel.get_from(cid) != owner.useraddress.address else channel.get_to(cid)
    data = {
        "receiver": co_owner,
        "balance_timestamp": balance_timestamp,
        "contract_hash": contract_hash,
        "second_signature": htlc_signature
    }
    _send_to_co_owner(cid, owner, url, data)


def _send_to_co_owner(cid, owner, url, data):
    co_owner_location = MicropaymentsChannel.objects.get(channel_id=cid, owner=owner).co_owner_location
    url = "http://%s:%s%s" % (co_owner_location.hostname, co_owner_location.port, url)
    requests.post(url, json=data)


def _get_from_to_delta(cid, sender, value):
    sender_address = sender.useraddress.address
    from_balance, to_balance, balance_timestamp = _get_channel_state(cid, sender)
    sender_locked_balance = _get_balance_locked_by_htlc(cid, sender, balance_timestamp)

    if sender_address == channel.get_from(cid):
        if from_balance - sender_locked_balance < value:
            raise ValidationError("Not sufficient funds to perform this operation")
        return value
    elif sender_address != channel.get_to(cid):
        if to_balance - sender_locked_balance < value:
            raise ValidationError("Not sufficient funds to perform this operation")
        return -value


def _get_balance_locked_by_htlc(cid, owner, balance_timestamp):
    micropayments_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=owner)
    htlcs = HashedTimelockContract.objects.filter(channel=micropayments_channel,
                                                  balance_timestamp=balance_timestamp,
                                                  second_signature='')

    from_to_delta = 0
    for htlc in htlcs:
        from_to_delta += int(htlc.from_to_delta)

    return from_to_delta


def _get_balance_received_by_htlc(cid, owner, balance_timestamp):
    micropayments_channel = MicropaymentsChannel.objects.get(channel_id=cid, owner=owner)
    htlcs = HashedTimelockContract.objects.filter(channel=micropayments_channel,
                                                  balance_timestamp=balance_timestamp
                                                  ).exclude(second_signature='')

    from_to_delta = 0
    for htlc in htlcs:
        from_to_delta += int(htlc.from_to_delta)

    return from_to_delta
