import hashlib
from typing import List, Tuple, Optional

"""
Merkle Tree implementation for transaction aggregation.

=== WHY MERKLE TREES? ===

Merkle trees solve a key problem: How can a light client verify that a
transaction is included in a block without downloading all transactions?

Without Merkle trees:
- Must download ALL transactions in a block to verify one
- Full nodes must send entire blocks to light clients

With Merkle trees:
- Only need O(log n) hashes to prove inclusion
- Light clients can verify transactions with minimal data
- This enables SPV (Simplified Payment Verification)

=== STRUCTURE ===

For transactions [A, B, C, D]:

                 Root
                /    \
            H(AB)    H(CD)
            /  \      /  \
          H(A) H(B) H(C) H(D)
           |    |    |    |
           A    B    C    D

The root is stored in the block header. To prove C is in the block,
you only need: [H(D), H(AB)] - just 2 hashes instead of 4 transactions!

=== OUR APPROACH ===

We use double-SHA256 for Merkle hashing. If there's an odd number of
elements at any level, the missing right sibling is filled with zeros
(a 32-byte zero hash represented as 64 hex characters).
"""

# Zero hash used for padding when tree is unbalanced (32 bytes of zeros as hex)
ZERO_HASH = '0' * 64


def double_sha256(data: bytes) -> bytes:
    """
    Double SHA256 hash, as used in Bitcoin.
    This provides extra security against length extension attacks.
    """
    # TODO: Implement double SHA256
    # Hint: Apply SHA256 twice: sha256(sha256(data))
    # pass
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def merkle_parent(left: str, right: str) -> str:
    """
    Compute the parent hash of two child hashes.
    Concatenates left + right and applies double SHA256.

    Args:
        left: Left child hash (hex string)
        right: Right child hash (hex string)

    Returns:
        Parent hash as hex string
    """
    # TODO: Implement merkle_parent
    # Hint: Concatenate bytes, then double_sha256, then convert to hex
    # pass
    l=bytes.fromhex(left) 
    r=bytes.fromhex(right)
    return double_sha256(l+r).hex()

def build_merkle_tree(tx_hashes: List[str]) -> str:
    """
    Compute the Merkle root of a list of transaction hashes.

    Algorithm:
    1. If empty list, return hash of empty string
    2. If single element, return it (it's the root)
    3. If odd number of elements, pad with ZERO_HASH (not duplicate)
    4. Pair up elements and hash each pair
    5. Repeat until one hash remains (the root)

    Args:
        tx_hashes: List of transaction hashes (hex strings)

    Returns:
        The Merkle root as a hex string
    """
    # TODO: Implement build_merkle_tree
    # Hint: Use a while loop, processing pairs until only root remains
    # Hint: If odd number of elements, append ZERO_HASH (not duplicate last)
    # pass
    # used similar logic to the one given in learnmeabitcoin.com
    if len(tx_hashes) == 0:
        return double_sha256(b'').hex()
    if len(tx_hashes) == 1:
        return tx_hashes[0]
    result = []
    for i in range(0, len(tx_hashes), 2):
        left = tx_hashes[i]
        if i+1 < len(tx_hashes):
            right = tx_hashes[i + 1]
            concat=bytes.fromhex(left) + bytes.fromhex(right)
        else:
            concat = bytes.fromhex(left) + bytes.fromhex(ZERO_HASH)
        result.append(double_sha256(concat).hex())
    return build_merkle_tree(result)



def merkle_proof(tx_hashes: List[str], index: int) -> List[Tuple[str, str]]:
    """
    Generate a Merkle proof for a transaction at the given index.

    The proof is a list of (hash, position) tuples where position is
    'left' or 'right', indicating which side the sibling hash is on.

    Example: For tx at index 2 in [A, B, C, D]:
    - Level 0: C's sibling is D (on the right) -> ('H(D)', 'right')
    - Level 1: H(CD)'s sibling is H(AB) (on the left) -> ('H(AB)', 'left')
    - Proof: [('H(D)', 'right'), ('H(AB)', 'left')]

    Args:
        tx_hashes: List of all transaction hashes in the block
        index: Index of the transaction to prove

    Returns:
        List of (sibling_hash, position) tuples forming the proof path
    """
    # TODO: Implement merkle_proof
    # Hint: Track the index as you move up the tree (idx = idx // 2)
    # pass
    proof=[]
    level=tx_hashes.copy()

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(ZERO_HASH)
        if index % 2 == 0:
            sibling = level[index + 1]
            proof.append((sibling, 'right'))
        else:
            sibling = level[index - 1]
            proof.append((sibling, 'left'))
        next = []
        for i in range(0, len(level), 2):
            next.append(merkle_parent(level[i], level[i + 1]))
        level = next
        index = index // 2

    return proof


def verify_merkle_proof(tx_hash: str, proof: List[Tuple[str, str]], root: str) -> bool:
    """
    Verify a Merkle proof for a transaction.

    Starting from the transaction hash, combine with each sibling in the
    proof (respecting left/right position) until reaching the root.

    Args:
        tx_hash: The transaction hash to verify
        proof: The Merkle proof (list of (sibling_hash, position) tuples)
        root: The expected Merkle root

    Returns:
        True if the proof is valid, False otherwise
    """
    # TODO: Implement verify_merkle_proof
    # Hint: Walk up the proof, combining hashes based on position
    # pass
    h = tx_hash
    for pair, pos in proof:
        if pos == 'left':
            h = merkle_parent(pair, h)
        else:
            h = merkle_parent(h, pair)
    return h == root
