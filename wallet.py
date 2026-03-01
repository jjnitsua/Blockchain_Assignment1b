from typing import List, Optional
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

from script import Script, sha256_hash
from transaction import Input, Output, Transaction

"""
Wallet functionality for building and signing transactions.
"""


def build_transaction(inputs: List[Input], outputs: List[Output], signing_key: SigningKey) -> Optional[Transaction]:
    """
    Build and sign a transaction with the given inputs and outputs.

    This creates P2PKH unlocking scripts (scriptSig) for each input.
    Returns None if impossible to build a valid transaction.
    Does not verify that inputs are unspent.

    Validation checks:
    - Inputs and outputs must not be empty
    - All inputs must be spendable by the signing key (pub_key_hash matches)
    - Input values must equal output values
    - No duplicate inputs (same txid)

    Steps:
    1. Validate inputs and outputs
    2. Check that the signing key can spend all inputs
    3. Create an unsigned transaction (empty scriptSigs)
    4. Sign the transaction data
    5. Create scriptSig for each input with signature and public key
    6. Return the signed transaction
    """
    # TODO: Implement build_transaction
    # Hint: Use Script.p2pkh_unlocking_script(signature, pub_key) for scriptSig
    

    def build_transaction(inputs: List[Input], outputs: List[Output], signing_key: SigningKey) -> Optional[Transaction]:
        if not inputs or not outputs:
            return None
        
        
        input_sum = sum(inp.output.value for inp in inputs)
        output_sum = sum(out.value for out in outputs)
        if input_sum != output_sum:
            return None
        
        
        pubkey_bytes = signing_key.verify_key.encode(HexEncoder)
        pubkey_hash = sha256_hash(pubkey_bytes)
        for inp in inputs:
            if bytes.fromhex(inp.output.script_pubkey.elements[2]) != pubkey_hash:
                return None
        
        
        unsigned_inputs = []
        for inp in inputs:
            unsigned_inputs.append(Input(inp.output, inp.tx_hash, inp.output_index, Script([])))
        
        
        unsigned_tx = Transaction(unsigned_inputs, outputs)
        
        
        signed_inputs = []
        for orig_inp in inputs:
            
            tx_data = bytes.fromhex(unsigned_tx.bytes_to_sign())
            signature_bytes = signing_key.sign(tx_data, encoder=HexEncoder)
            signature_hex = signature_bytes.signature.hex()  
            
            pubkey_hex = pubkey_bytes.hex()
            script_sig = Script.p2pkh_unlocking_script(signature_hex, pubkey_hex)
            
            signed_inputs.append(Input(orig_inp.output, orig_inp.tx_hash, orig_inp.output_index, script_sig))
        
        
        return Transaction(signed_inputs, outputs)

