contract MicropaymentsChannel {
    enum Stage {
        Empty,
        PartiallyConfirmed,
        Confirmed,
        Closing
    }

    uint constant closingBlockDelay = 10;

    Stage stage;
    uint id;
    address from;
    uint fromBalance;
    address to;
    uint toBalance;
    uint balanceTimestamp;

    uint closingBlockNumber;

    function MicropaymentsChannel(address _from, address _to, uint _id) {
        stage = Stage.Empty;
        id  = _id;
        from = _from;
        fromBalance = 0;
        _to = to;
        toBalance = 0;
        balanceTimestamp = 0;
    }

    modifier onlyFrom {
        if (msg.sender != from) {
            throw;
        }
        _
    }

   modifier onlyTo {
        if (msg.sender != to) {
            throw;
        }
        _
    }

    modifier onlyParticipants {
        if ((msg.sender != from) || (msg.sender != to)) {
            throw;
        }
        _
    }

    modifier atStage(Stage _stage) {
        if (stage != _stage) {
            throw;
        }
        _
    }

    modifier atOneOfStages(Stage _stage1, Stage _stage2) {
        if ((stage != _stage1) && (stage != _stage2)) {
            throw;
        }
        _
    }

    modifier readyToClose() {
        if (block.number < closingBlockNumber) {
            throw;
        }
        _
    }

    modifier withYoungerBalance(uint _balanceTimestamp) {
        if (balanceTimestamp < _balanceTimestamp) {
            throw;
        }
        _
    }

    modifier withSaneBalance(uint _fromBalance, uint _toBalance) {
        if (fromBalance + toBalance < _fromBalance + _toBalance) {
            throw;
        }
        _
    }

    modifier withMessageHash(bytes32 _expected, bytes32 _sigHash) {
        if (_expected != _sigHash) {
            throw;
        }
        _
    }

    modifier signedByBoth(bytes32 _sigHash, uint8 _sigV, bytes32 _sigR, bytes32 _sigS) {
        address receiver = ecrecover(_sigHash, _sigV, _sigR, _sigS);
        if (!(((from == msg.sender) && (to == receiver)) || 
              ((from == receiver) && (to == msg.sender)))) {
            throw;
        }
        _
    }

    function openChannel()
        onlyFrom
        atStage(Stage.Empty) 
    {
        stage = Stage.PartiallyConfirmed;
        channels[_from][_to].fromBalance = msg.value;
    }
    
    function confirmChannel() 
        onlyTo
        atStage(Stage.PartiallyConfirmed)
    {
        stage = Stage.Confirmed;
        toBalance = msg.value;
    }
    
    function requestClosingChannel()
        onlyParticipants
        atOneOfStages(Stage.PartiallyConfirmed, Stage.Confirmed)
    {
        if (stage == Stage.PartiallyConfirmed) {
            suicide(from);
        } else {
            stage = Stage.Closing;
            closingBlockNumber = block.number + closingBlockDelay;
        }
    }
    
    function closeChannel() 
        onlyParticipants
        atStage(Stage.Closing)
        readyToClose
    {
        from.send(fromBalance);
        suicide(to);
    }
    
    function updateChannelState(
        uint _balanceTimestamp,
        uint _fromBalance,
        uint _toBalance,
        bytes32 _sigHash,
        uint8 _sigV,
        bytes32 _sigR,
        bytes32 _sigS
    )
        onlyParticipants
        atOneOfStages(Stage.Confirmed, Stage.Closing)
        withYoungerBalance(_balanceTimestamp)
        withSaneBalance(_fromBalance, _toBalance)
        withMessageHash(sha3(id, _balanceTimestamp, _fromBalance, _toBalance), _sigHash)
        signedByBoth(_sigHash, _sigV, _sigR, _sigS))
    {   
        balanceTimestamp = _balanceTimestamp;
        fromBalance = _fromBalance;
        toBalance = _toBalance;
    }
}