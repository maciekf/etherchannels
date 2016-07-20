from ethereum import channel

from models import ChannelState


def check_channel(micropayments_channel):
    _check_channel_state(micropayments_channel)
    _check_sent_htlcs(micropayments_channel)
    _check_received_htlcs(micropayments_channel)


def push_update_channel(updated_channel):
    channel_states = ChannelState.objects.filter(channel=updated_channel).exclude(second_signature="")

    if len(channel_states) == 1:
        channel_state = channel_states[0]
        channel.update_channel_state(updated_channel.get_owner_address(),
                                     updated_channel.get_cid(),
                                     channel_state.get_balance_timestamp(),
                                     channel_state.get_from_balance(),
                                     channel_state.get_to_balance(),
                                     channel_state.get_second_signature())


def _check_channel_state(micropayments_channel):
    channel_stage = channel.get_stage(micropayments_channel.channel_id)
    if channel_stage != channel.ChannelStage.CLOSING:
        return

    channel_states = ChannelState.objects.filter(channel=micropayments_channel).exclude(second_signature="")
    if len(channel_states) == 1 and _should_commit_update_channel(micropayments_channel.get_cid(), channel_states[0]):
        push_update_channel(micropayments_channel)


def _should_commit_update_channel(cid, channel_state):
    if channel.get_balance_timestamp(cid) < channel_state.get_balance_timestamp():
        return True
    return False


def _check_sent_htlcs(micropayments_channel):
    pass


def _check_received_htlcs(micropayments_channel):
    pass
