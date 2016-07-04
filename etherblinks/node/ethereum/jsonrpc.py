import ethjsonrpc


class EthJsonRpc(ethjsonrpc.EthJsonRpc):

    DEFAULT_GAS_PER_TX = 300000

    def call_with_transaction(self, from_, address, sig, args, value=None, gas=None, gas_price=None):
        """
        Call a contract function by sending a transaction (useful for storing
        data)
        """
        gas = gas or self.DEFAULT_GAS_PER_TX
        gas_price = gas_price or self.DEFAULT_GAS_PRICE
        data = self._encode_function(sig, args)
        data_hex = data.encode('hex')
        return self.eth_sendTransaction(from_address=from_, to_address=address, data=data_hex, value=value,
                                        gas=gas, gas_price=gas_price)
