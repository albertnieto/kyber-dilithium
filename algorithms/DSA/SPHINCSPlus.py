def sphincs_plus_sign(message):
    """
    Signs a message using the SPHINCS+ algorithm.
    """
    import pyspx.shake256_128f as sphincs
    import os

    # Generate key pair
    seed = os.urandom(sphincs.crypto_sign_SEEDBYTES)
    public_key, secret_key = sphincs.generate_keypair(seed)

    # Sign the message
    signature = sphincs.sign(message.encode(), secret_key)

    return signature.hex(), public_key.hex()

def sphincs_plus_verify(message, signature_hex, public_key_hex):
    """
    Verifies a SPHINCS+ signature.
    """
    import pyspx.shake256_128f as sphincs
    from binascii import unhexlify

    signature = unhexlify(signature_hex)
    public_key = unhexlify(public_key_hex)

    try:
        sphincs.verify(message.encode(), signature, public_key)
        return True
    except sphincs.VerificationError:
        return False