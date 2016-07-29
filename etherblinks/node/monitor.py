from ethereum import channel

from models import ChannelState, HashedTimelockContract


def check_channel(micropayments_channel):
    if _check_channel_state(micropayments_channel) or _check_htlcs(micropayments_channel):
        push_update_channel(micropayments_channel)
        push_htlcs(micropayments_channel)


def withdraw_if_closed(micropayments_channel):
    cid = micropayments_channel.get_cid()
    channel_stage = channel.get_stage(cid)
    if channel_stage == channel.ChannelStage.CLOSING and \
            channel.get_block_number() < channel.get_closing_block_number(cid):
        channel.close_channel(micropayments_channel.get_owner_address(), cid)
    elif channel_stage == channel.ChannelStage.CLOSED:
        _withdraw_nonzero(micropayments_channel)


def push_update_channel(channel_to_close):
    channel_states = ChannelState.objects.filter(channel=channel_to_close).exclude(second_signature="")

    if len(channel_states) == 1:
        channel_state = channel_states[0]
        channel.update_channel_state(channel_to_close.get_owner_address(),
                                     channel_to_close.get_cid(),
                                     channel_state.get_balance_timestamp(),
                                     channel_state.get_from_balance(),
                                     channel_state.get_to_balance(),
                                     channel_state.get_second_signature())


def push_htlcs(channel_to_close):
    htlcs = HashedTimelockContract.objects.filter(channel=channel_to_close).exclude(resolved=True)
    for htlc in htlcs:
        if not htlc.get_data() or not htlc.get_signature():
            continue

        channel.resolve_htlc(htlc.get_owner_address(),
                             htlc.get_cid(),
                             htlc.get_balance_timestamp(),
                             htlc.get_timeout(),
                             htlc.get_hash(),
                             htlc.get_from_to_delta(),
                             htlc.get_data(),
                             htlc.get_signature())


def _check_channel_state(micropayments_channel):
    channel_stage = channel.get_stage(micropayments_channel.channel_id)
    if channel_stage != channel.ChannelStage.CLOSING:
        return False

    channel_states = ChannelState.objects.filter(channel=micropayments_channel).exclude(second_signature="")
    if len(channel_states) == 1 and _should_commit_update_channel(micropayments_channel.get_cid(), channel_states[0]):
        return True
    return False


def _should_commit_update_channel(cid, channel_state):
    if channel.get_balance_timestamp(cid) < channel_state.get_balance_timestamp():
        return True
    return False


def _check_htlcs(micropayments_channel):
    htlcs = HashedTimelockContract.objects.filter(channel=micropayments_channel).exclude(resolved=True)
    for htlc in htlcs:
        if _exists_sibling_htlcs(htlc) and _check_sibling_htlcs_data(htlc):
            return True
        if htlc.get_data() and htlc.get_timeout() < channel.get_timestamp_in_seconds() + 60:
            return True
    return False


def _exists_sibling_htlcs(htlc):
    return 0 < len(_get_sibling_htlcs(htlc))


def _check_sibling_htlcs_data(htlc):
    for sibling in _get_sibling_htlcs(htlc):
        data = channel.get_htlc_published_data(sibling.get_cid(), sibling.get_from_to_delta(), sibling.get_hash())
        if data:
            return data


def _get_sibling_htlcs(htlc):
    return HashedTimelockContract.objects.filter(contract_hash=htlc.get_hash()).exclude(channel=htlc.get_channel())


def _withdraw_nonzero(micropayments_channel):
    cid = micropayments_channel.get_cid()
    owner_address = micropayments_channel.get_owner_address()
    if channel.get_from(cid) == owner_address and channel.get_from_balance(cid) != 0:
        channel.withdraw_from_channel(owner_address, cid)
    if channel.get_to(cid) == owner_address and channel.get_to_balance(cid) != 0:
        channel.withdraw_to_channel(owner_address, cid)