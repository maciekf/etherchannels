contract MicropaymentsChannel {
    
    enum ChannelStage
    {
        Empty,
        PartiallyConfirmed,
        Confirmed
    }

    struct Channel
    {
        ChannelStage stage;
        uint fromBalance;
        uint toBalance;
    }

    mapping(address => mapping(address => Channel)) channels;

    function openChannel(address _to)
    {
        address _from = msg.sender;
        if (channels[_from][_to].stage != ChannelStage.Empty) throw;
        channels[_from][_to].stage = ChannelStage.PartiallyConfirmed;
        channels[_from][_to].fromBalance = msg.value;
    }
    
    function confirmChannel(address _from)
    {
        address _to = msg.sender;
        if (channels[_from][_to].stage != ChannelStage.PartiallyConfirmed) throw;
        channels[_from][_to].stage = ChannelStage.Confirmed;
        channels[_from][_to].toBalance = msg.value;
    }
    
    function requestClosingChannel(address _to) {
        address _from = msg.sender;
        if (channels[_from][_to].stage == ChannelStage.Empty) throw;
        if (channels[_from][_to].stage == ChannelStage.PartiallyConfirmed) {
            _from.send(channels[_from][_to].fromBalance);
        }
        if (channels[_from][_to].stage == ChannelStage.Confirmed) {
            _from.send(channels[_from][_to].fromBalance);
            _to.send(channels[_from][_to].toBalance);
        }
        delete channels[_from][_to];
    }
}
