import 'dapple/test.sol'; // virtual "dapple" package imported when `dapple test` is run
import 'contract.sol';

// Deriving from `Test` marks the contract as a test and gives you access to various test helpers.
contract MicropaymentsChannelTest is Test {
    Tester toTester;
    MicropaymentsChannel channel;

    uint fromBalance = 10;
    uint toBalance = 20;

    // The function called "setUp" with no arguments is
    // called on a fresh instance of this contract before
    // each test.
    function setUp() {
        toTester = new Tester();
        channel = new MicropaymentsChannel(address(this), address(toTester), 42);
        toTester._target(channel);
    }

    function testInitialFromAddress() {
        assertEq(address(this), channel.from());
    }

    function testInitialToAddress() {
        assertEq(address(toTester), channel.to());
    }

    function testOpenChannelFrom() {
        channel.openChannel.value(fromBalance)();
        assertEq(fromBalance, channel.fromBalance());
    }

    function testFailOpenChannelTo() {
        MicropaymentsChannel(toTester).openChannel.value(fromBalance)();
    }

    function testFailOpenChannelFromTwice() {
        channel.openChannel.value(fromBalance)();
        channel.openChannel.value(fromBalance)();
    }

    function testConfirmChannelTo() {
        channel.openChannel.value(fromBalance)();
        MicropaymentsChannel(toTester).confirmChannel.value(toBalance)();
        assertEq(toBalance, channel.toBalance());
    }
}