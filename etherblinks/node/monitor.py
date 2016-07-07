from ethereum import channel

from models import ChannelState


def check_channel(micropayments_channel):
    channel_stage = channel.get_stage(micropayments_channel.channel_id)
    if channel_stage != channel.ChannelStage.CLOSING:
        return

    channel_states = ChannelState.objects.filter(channel=micropayments_channel)
    if len(channel_states) == 1:
        channel_state = channel_states[0]
        if _should_commit_update_channel(micropayments_channel.channel_id, channel_state):
            channel.update_channel_state(micropayments_channel.owner.useraddress.address,
                                         micropayments_channel.channel_id,
                                         int(channel_state.balance_timestamp),
                                         int(channel_state.from_balance),
                                         int(channel_state.to_balance),
                                         int(channel_state.second_signature))


def _should_commit_update_channel(cid, channel_state):
    if channel_state.second_signature != "":
        return False
    if channel.get_balance_timestamp(cid) < int(channel_state.balance_timestamp):
        return False
    return True
