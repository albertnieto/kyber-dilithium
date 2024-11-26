# algorithms/digital_signature.py

def demo_signature_algorithm(message):
    """
    Simulates a Digital Signature algorithm.
    For demonstration, uses SHA-256 hashing to 'sign' a message.
    """
    import hashlib

    signature = hashlib.sha256(message.encode('utf-8')).hexdigest()
    return signature
