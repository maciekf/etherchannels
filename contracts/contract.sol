contract MicropaymentsChannel {
    enum ChannelStage {
        Empty,
        PartiallyConfirmed,
        Confirmed,
        Closing
    }

    struct Channel {
        ChannelStage stage;
        uint closingBlockNumber;
        uint id;
        uint balanceAge;
        uint fromBalance;
        uint toBalance;
    }

    uint idGen;
    uint closingBlockDelay;
    mapping(address => mapping(address => Channel)) channels;

    function MicropaymentsChannel() {
        idGen = 1;
        closingBlockDelay = 10;
    }

    function openChannel(address _to) {
        address _from = msg.sender;
        if (channels[_from][_to].stage != ChannelStage.Empty) throw;
        channels[_from][_to].stage = ChannelStage.PartiallyConfirmed;
        channels[_from][_to].id = idGen++;
        channels[_from][_to].fromBalance = msg.value;
    }
    
    function confirmChannel(address _from) {
        address _to = msg.sender;
        if (channels[_from][_to].stage != ChannelStage.PartiallyConfirmed) throw;
        channels[_from][_to].stage = ChannelStage.Confirmed;
        channels[_from][_to].toBalance = msg.value;
    }
    
    function requestClosingChannel(address _from, address _to) {
        if ((msg.sender != _from) && (msg.sender != _to)) throw;
        if (channels[_from][_to].stage != ChannelStage.PartiallyConfirmed) {
            _from.send(channels[_from][_to].fromBalance);
            delete channels[_from][_to];
        } else if (channels[_from][_to].stage != ChannelStage.Confirmed) {
            channels[_from][_to].stage = ChannelStage.Closing;
            channels[_from][_to].closingBlockNumber = block.number + closingBlockDelay;
        } else {
            throw;
        }
    }
    
    function closeChannel(address _from, address _to) {
        if ((msg.sender != _from) && (msg.sender != _to)) throw;
        if ((channels[_from][_to].stage != ChannelStage.Closing) || 
            (block.number < channels[_from][_to].closingBlockNumber)) throw;
        _from.send(channels[_from][_to].fromBalance);
        _to.send(channels[_from][_to].toBalance);
        delete channels[_from][_to];
    }
    
    function updateChannelState(
        address _from,
        address _to,
        uint _balanceAge,
        uint _fromBalance,
        uint _toBalance,
        bytes32 _sigHash,
        uint8 _sigV,
        bytes32 _sigR,
        bytes32 _sigS
        ) {
        if ((msg.sender != _from) && (msg.sender != _to)) throw;
        if ((channels[_from][_to].stage != ChannelStage.Confirmed) || 
            (channels[_from][_to].stage != ChannelStage.Closing)) throw;
        if (_balanceAge < channels[_from][_to].balanceAge) throw;
        bytes32 updateHash = sha3(channels[_from][_to].id,
                                  _balanceAge,
                                  _fromBalance,
                                  _toBalance);
        if (_sigHash != updateHash) throw;
        address receiver = ecrecover(_sigHash, _sigV, _sigR, _sigS);
        if (!(((_from == msg.sender) && (_to == receiver)) || ((_from == receiver) && (_to == msg.sender)))) throw;
        
        channels[_from][_to].balanceAge = _balanceAge;
        channels[_from][_to].fromBalance = _fromBalance;
        channels[_from][_to].toBalance = _toBalance;
    }
}