from web3 import Web3

def connect(provider_url="http://127.0.0.1:8545") -> Web3:
    return Web3(Web3.HTTPProvider(provider_url))
