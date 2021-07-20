import json
import os
import web3

from utils import *
import ccf.clients
import provider
import ccf_network_config as config
import json
from loguru import logger as LOG
import subprocess
from eth_hash.auto import keccak as keccak_256

class EvmTestContract:
    def __init__(self, contract):
        self.contract = contract

    def get_sum(self, caller, test_a, test_b):
        return caller.call(self.contract.functions.getSum(test_a, test_b))


def read_evmtest_contract_from_file():
    env_name = "CONTRACTS_DIR"
    contracts_dir = os.getenv(env_name)
    if contracts_dir is None:
        raise RuntimeError(
            f"Cannot find contracts, please set env var '{env_name}'")
    file_path = os.path.join(
        contracts_dir, "eevmtests/EvmTest_combined.json")
    return read_contract_from_file(file_path, "EvmTest.sol:EvmTest")


def read_math_library_from_file():
    env_name = "CONTRACTS_DIR"
    contracts_dir = os.getenv(env_name)
    if contracts_dir is None:
        raise RuntimeError(
            f"Cannot find contracts, please set env var '{env_name}'")
    file_path = os.path.join(
        contracts_dir, "eevmtests/EvmTest_combined.json")
    return read_contract_from_file(file_path, "EvmTest.sol:Math")

def read_evmtest_policy_from_file():
    env_name = "CONTRACTS_DIR"
    contracts_dir = os.getenv(env_name)
    if contracts_dir is None:
        raise RuntimeError(
            f"Cannot find contracts, please set env var '{env_name}'")
    file_path = os.path.join(
        contracts_dir, "eevmtests/EvmTestPolicy.json")
    with open(file_path, mode='rb') as f:
        return web3.Web3.toHex(f.read())

def read_evmtest_params_from_file():
    env_name = "CONTRACTS_DIR"
    contracts_dir = os.getenv(env_name)
    if contracts_dir is None:
        raise RuntimeError(
            f"Cannot find contracts, please set env var '{env_name}'")
    file_path = os.path.join(
        contracts_dir, "eevmtests/mptParams.json")
    with open(file_path, mode='rb') as f:
        return web3.Web3.toHex(f.read())

def signMpt(private_key, frm, to, data, nonce=1):
    import rlp
    from_int = int(frm, 0)
    to_int = int(to, 0)
    params = rlp.encode([nonce, from_int, to_int, data])
    msg_hash = keccak_256(params)
    signed = web3.eth.Account.signHash(msg_hash, private_key=private_key)
    res = rlp.encode([nonce, from_int, to_int, data, signed.v, signed.r, signed.s]).hex()
    return res

def test_deploy(ccf_client):
    math_abi, math_bin = read_math_library_from_file()
    evmtest_abi, evmtest_bin = read_evmtest_contract_from_file()

    w3 = web3.Web3(provider.CCFProvider(ccf_client))

    owner = Caller(web3.Account.create(), w3)

    LOG.info("Library deployment")
    LOG.info(f"owner account:{owner.account.address}")
    math_spec = w3.eth.contract(abi=math_abi, bytecode=math_bin)

    # deploy_receipt = owner.sendPrivacyPolicy(math_spec.constructor(), evmtest_policy)

    deploy_receipt = owner.send_signed(math_spec.constructor())
    ccf_client.math_library_address = deploy_receipt.contractAddress
    LOG.info("math_library_address: " + ccf_client.math_library_address)

    _ph = w3.toHex(w3.sha3(text="EvmTest.sol:Math"))

    LOG.info("math_library_placeholder: " + "__$"+_ph[2:36] + "$__")

    LOG.info("Contract deployment")

    evmtest_bin = evmtest_bin.replace(
        "__$"+_ph[2:36] + "$__", ccf_client.math_library_address[2:])

    evmtest_spec = w3.eth.contract(abi=evmtest_abi, bytecode=evmtest_bin)
    deploy_receipt = owner.send_signed(
        evmtest_spec.constructor(10000, [11, 12, 13]))

    # cf = w3.eth.call({"to": deploy_receipt.contractAddress, "data": "0x8e86b12500000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000005"})
    # print(f"HeY: {cf}")

    # evmtest_policy = read_evmtest_policy_from_file()
    # sppr = owner.sendPrivacyPolicy(owner.account.address, deploy_receipt.contractAddress, "", evmtest_policy)
    # mpt_data = read_evmtest_params_from_file()
    # mpt_params = signMpt(owner.account.key, owner.account.address, deploy_receipt.contractAddress, mpt_data)
    # smptr = owner.sendMultiPartyTransaction(mpt_params)

    # ccf_client.evmtest_contract_address = deploy_receipt.contractAddress
    # print(deploy_receipt.contractAddress)
    # ccf_client.owner_account = owner.account

    return ccf_client


def test_get_sum(ccf_client):
    evmtest_abi, evmtest_bin = read_evmtest_contract_from_file()

    LOG.info(f"ccf_client: {ccf_client.name}")
    w3 = web3.Web3(provider.CCFProvider(ccf_client))

    evmtest_contract = EvmTestContract(
        w3.eth.contract(abi=evmtest_abi,
                        address=ccf_client.evmtest_contract_address)
    )

    owner = Caller(ccf_client.owner_account, w3)

    LOG.info("Call getSum of EvmTest")
    LOG.info(evmtest_contract.get_sum(owner, 11, 22))
    assert evmtest_contract.get_sum(owner, 11, 22) == 33

def get_balance(ccf_client):
    w3 = web3.Web3(provider.CCFProvider(ccf_client))
    owner = Caller(web3.Account.create(), w3)
    alice = Caller(web3.Account.create(), w3)
    balance = w3.eth.getBalance(owner.account.address)
    balance1 = w3.eth.getBalance(alice.account.address)
    print(balance)
    print(balance1)
    params = {}
    params['to'] = alice.account.address
    params['from'] = owner.account.address
    params['gas'] = 0
    params['value'] = w3.toWei(18, "ether")
    txhash = w3.eth.sendTransaction(params)
    balance1 = w3.eth.getBalance(alice.account.address)
    count = w3.eth.getTransactionCount('0x03901A8132E3Ac1a32e9eE9fC520A53152DF0A40')
    receipt = w3.eth.getTransactionReceipt(txhash.hex())
    # text = json.loads(receipt)
    # print(receipt)
    print(f"count:{count}")
    print(balance)
    chaind = w3.eth.estimateGas(params)
    print(chaind)


def read_income_mpt_data():
    text = """
    {
        "function": "set",
        "inputs" : [
            { "name": "_a", "value": "100"}
        ]
    }
    """
    print(json.loads(text))
    return web3.Web3.toHex(text=text)

def cloak_prepare(ccf_client: ccf.clients.CCFClient, cloak_service_addr: str):
    ccf_client.call("/app/cloak_prepare", {"cloak_service_addr": cloak_service_addr})

def test_mpt(ccf_client):
    compile_dir = os.environ["HOME"] + "/git/cloak-compiler/test/output/"
    w3 = web3.Web3(provider.CCFProvider(ccf_client))
    owner = Caller(web3.Account.create(), w3)
    print(f"owner:{owner.account.address}")
    file_path = compile_dir + "private_contract.sol"
    process = subprocess.Popen([
        os.environ["HOME"] + "/.solcx/solc-v0.6.12",
        "--combined-json", "abi,bin,bin-runtime,hashes", "--evm-version", "homestead", "--optimize",
        file_path
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    cj = json.loads(out)
    income = cj["contracts"][f"{file_path}:Income"]
    abi = income["abi"]
    bi = income["bin"]
    print(f"hashs:{income['hashes']}")
    codeHash = web3.Web3.keccak(open(file_path, 'rb').read())
    spec = w3.eth.contract(abi=abi, bytecode=bi)
    deployed_receipt = owner.send_signed(spec.constructor())
    print(f"deployed_addr:{deployed_receipt.contractAddress}")

    policy = None
    with open(compile_dir + "policy.json", mode='rb') as f:
        policy = web3.Web3.toHex(f.read())
    print(f"pt:{type(policy)}, ph:{web3.Web3.keccak(hexstr=policy).hex()}")
    res = owner.sendPrivacyPolicy(owner.account.address, deployed_receipt.contractAddress, codeHash.hex(),
            "0x43552b1518Cbcc4eB14b5600F596D4287975B2d0", policy, "0x912FB2881433F9EEA86073eec44D7F1648fdbf2B")
    print(f"res:{res}")

    # mpt
    mpt_data = read_income_mpt_data()
    mpt_params = signMpt(owner.account.key, owner.account.address, deployed_receipt.contractAddress, mpt_data)
    smptr = owner.sendMultiPartyTransaction(mpt_params)
    print(f"mpt res:{smptr}")


if __name__ == "__main__":

    ccf_client = ccf.clients.CCFClient(
        config.host, 
        config.port, 
        config.ca, 
        config.cert, 
        config.key
        )
    # prepare ccf
    # cloak_prepare(ccf_client, "0xb3B7074aB6D65BDbaB96424A76EB23495d3787B4")
    test_mpt(ccf_client)
    # test_test(ccf_client)
    # get_balance(ccf_client)
    # test_deploy(ccf_client)
    # test_get_sum(ccf_client)
