"""Real Web3 client for EvidenceLedger.

Points at the local Hardhat network by default (RPC_URL unset ->
http://127.0.0.1:8545, using Hardhat's well-known, PUBLICLY-KNOWN dev
account #0 -- safe only on a local/test chain, never fund this address on
anything real). To go live on Sepolia, set RPC_URL / PRIVATE_KEY /
CONTRACT_ADDRESS in .env to your own funded testnet wallet and re-run
`npm run deploy:sepolia` -- no code changes needed, only config.

If the RPC endpoint is unreachable at all (e.g. this repo checked out fresh,
before `npx hardhat node` has been started), calls raise BlockchainUnavailable
and the API layer surfaces a clearly labeled DEMO/SIMULATED response instead
of crashing the whole investigation flow.
"""
import json
import os
from pathlib import Path
from web3 import Web3

RPC_URL = os.environ.get("RPC_URL") or "http://127.0.0.1:8545"
PRIVATE_KEY = os.environ.get("PRIVATE_KEY") or "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # Hardhat dev account #0 -- public/insecure by design, local-chain only
NETWORK_LABEL = "Ethereum Sepolia (testnet)" if os.environ.get("RPC_URL") else "Local Hardhat Network (demo -- not a public chain)"

_ABI_PATH = Path(__file__).parent / "abi" / "EvidenceLedger.json"
_DEPLOYMENT_PATH = Path(__file__).parent / "deployment.json"


class BlockchainUnavailable(Exception):
    pass


def _load_contract():
    if not _ABI_PATH.exists() or not _DEPLOYMENT_PATH.exists():
        raise BlockchainUnavailable("Contract not deployed yet -- run `npm run deploy:local` (or deploy:sepolia).")

    w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 5}))
    if not w3.is_connected():
        raise BlockchainUnavailable(f"Cannot reach RPC at {RPC_URL}")

    abi = json.loads(_ABI_PATH.read_text())
    deployment = json.loads(_DEPLOYMENT_PATH.read_text())
    contract = w3.eth.contract(address=Web3.to_checksum_address(deployment["address"]), abi=abi)
    return w3, contract, deployment


def register_case(case_id: str, merkle_root_hex: str, report_hash_hex: str) -> dict:
    w3, contract, deployment = _load_contract()
    account = w3.eth.account.from_key(PRIVATE_KEY)

    tx = contract.functions.registerCase(
        case_id,
        bytes.fromhex(merkle_root_hex.replace("0x", "")),
        bytes.fromhex(report_hash_hex.replace("0x", "")),
    ).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 300000,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
    })
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)

    return {
        "transaction_hash": receipt.transactionHash.hex(),
        "contract_address": deployment["address"],
        "network": NETWORK_LABEL,
        "block_number": receipt.blockNumber,
        "status": "confirmed" if receipt.status == 1 else "failed",
    }


def get_case(case_id: str) -> dict:
    w3, contract, deployment = _load_contract()
    merkle_root, report_hash, timestamp, registered_by = contract.functions.getCase(case_id).call()
    return {
        "merkle_root": "0x" + merkle_root.hex(),
        "report_hash": "0x" + report_hash.hex(),
        "timestamp": timestamp,
        "registered_by": registered_by,
        "contract_address": deployment["address"],
        "network": NETWORK_LABEL,
    }
