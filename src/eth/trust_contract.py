def load_trust_contract(w3, contract_address, abi):
    return w3.eth.contract(address=contract_address, abi=abi)

def set_trust_status(contract, account, entity_addr, is_trusted):
    tx_hash = contract.functions.setTrustStatus(entity_addr, is_trusted).transact({'from': account})
    return tx_hash
