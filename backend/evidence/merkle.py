"""Merkle tree over evidence content hashes.

Standard binary Merkle tree: pairs of hex hashes are concatenated (as raw
bytes) and re-hashed with SHA-256 layer by layer until one root remains. An
odd node at any layer is paired with itself (the common "duplicate last node"
convention), so the tree is well defined for any number of leaves >= 1.
"""
import hashlib
from typing import List


def _hash_pair(left: str, right: str) -> str:
    l = bytes.fromhex(left.replace("0x", ""))
    r = bytes.fromhex(right.replace("0x", ""))
    return "0x" + hashlib.sha256(l + r).hexdigest()


def build_merkle_tree(leaf_hashes: List[str]) -> dict:
    """Returns {"root": str, "layers": List[List[str]]} for a list of 0x.. hex hashes.

    layers[0] is the leaves (sorted for determinism regardless of evidence
    upload order); each subsequent layer is half the size, rounding up.
    """
    if not leaf_hashes:
        raise ValueError("Cannot build a Merkle tree with zero evidence items")

    leaves = sorted(leaf_hashes)
    layers = [leaves]
    current = leaves
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            nxt.append(_hash_pair(left, right))
        layers.append(nxt)
        current = nxt

    return {"root": current[0], "layers": layers}


def merkle_root(leaf_hashes: List[str]) -> str:
    return build_merkle_tree(leaf_hashes)["root"]
