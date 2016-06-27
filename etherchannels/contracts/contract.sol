contract MicropaymentsChannel {
    enum Stage {
        Empty,
        PartiallyConfirmed,
        Confirmed,
        Closing,
        Closed
    }

    uint public constant closingBlockDelay = 10;

    Stage public stage;
    uint public id;
    address public from;
    uint public fromBalance;
    address public to;
    uint public toBalance;
    uint public balanceTimestamp;

    uint public closingBlockNumber;

    function MicropaymentsChannel(address _from, address _to, uint _id) {
        if (_id == 0) {
            throw;
        }
        stage = Stage.Empty;
        id  = _id;
        from = _from;
        fromBalance = 0;
        to = _to;
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
        if ((msg.sender != from) && (msg.sender != to)) {
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

    modifier readyToClose {
        if (block.number < closingBlockNumber) {
            throw;
        }
        _
    }

    function assertYoungerBalance(uint _balanceTimestamp) internal {
        if (_balanceTimestamp <= balanceTimestamp) {
            throw;
        }
    }

    function assertSaneBalance(uint _fromBalance, uint _toBalance) internal {
        if (fromBalance + toBalance < _fromBalance + _toBalance) {
            throw;
        }
    }

    function assertMessageHash(bytes32 _expected, bytes32 _sigHash) internal {
        if (_expected != _sigHash) {
            throw;
        }
    }

    function assertSignedByBoth(
        bytes32 _sigHash,
        uint8 _sigV,
        bytes32 _sigR,
        bytes32 _sigS
    ) internal {
        address signer = getSigner(_sigHash, _sigV, _sigR, _sigS);
        if (!(((from == msg.sender) && (to == signer)) || 
              ((from == signer) && (to == msg.sender)))) {
            throw;
        }
    }

    function getUpdateHash(
        uint _balanceTimestamp,
        uint _fromBalance,
        uint _toBalance
    ) constant returns(bytes32) {
        return sha3(id, _balanceTimestamp, _fromBalance, _toBalance);
    }

    function getSigner(
        bytes32 _sigHash,
        uint8 _sigV,
        bytes32 _sigR,
        bytes32 _sigS
    ) constant returns(address) {
        return ecrecover(_sigHash, _sigV, _sigR, _sigS);
    }

    function openChannel()
        onlyFrom
        atStage(Stage.Empty) 
    {
        stage = Stage.PartiallyConfirmed;
        fromBalance = msg.value;
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
            stage = Stage.Closed;
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
        stage = Stage.Closed;
    }

    function withdrawFrom()
        onlyFrom
        atStage(Stage.Closed)
    {
        uint balance = fromBalance;
        fromBalance = 0;
        from.send(balance);
    }

    function withdrawTo()
        onlyTo
        atStage(Stage.Closed)
    {
        uint balance = toBalance;
        toBalance = 0;
        to.send(balance);
    }

    function updateChannelState(
        uint _balanceTimestamp,
        uint _fromBalance,
        uint _toBalance,
        uint8 _sigV,
        bytes32 _sigR,
        bytes32 _sigS
    )
        onlyParticipants
        atOneOfStages(Stage.Confirmed, Stage.Closing)
    {
        assertYoungerBalance(_balanceTimestamp);
        assertSaneBalance(_fromBalance, _toBalance);
        assertSignedByBoth(getUpdateHash(_balanceTimestamp, _fromBalance, _toBalance), _sigV, _sigR, _sigS);
        balanceTimestamp = _balanceTimestamp;
        fromBalance = _fromBalance;
        toBalance = _toBalance;
    }
}

contract MicropaymentsNetwork {
    mapping(uint => MicropaymentsChannel) channels;
    mapping(uint => bool) reserved;
    
    function MicropaymentsNetwork() {
    }

    function assertAvailable(uint _id) internal {
        if (!isAvailable(_id)) {
            throw;
        }
    }

    function isAvailable(uint _id)
        constant
        returns (bool)
    {
        return !reserved[_id];
    }
    
    function registerChannel(address _from, address _to, uint _id) {
        assertAvailable(_id);
        reserved[_id] = true;
        channels[_id] = new MicropaymentsChannel(_from, _to, _id);
    }
    
    function getChannel(uint _id)
        constant
        returns (MicropaymentsChannel) 
    {
        return channels[_id];
    }
}