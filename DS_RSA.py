from hashlib import sha256

def modinv(a, m):
    # Compute the modular inverse of a under modulo m
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def generate_keys():
    p = 11
    q = 13
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 7
    d = modinv(e, phi)
    return ((e, n), (d, n))

def sign_message(message, private_key):
    d, n = private_key
    message_hash = int.from_bytes(sha256(message.encode()).digest(), byteorder='big') % n
    signature = pow(message_hash, d, n)
    return signature

def verify_signature(message, signature, public_key):
    e, n = public_key
    message_hash = int.from_bytes(sha256(message.encode()).digest(), byteorder='big') % n
    hash_from_signature = pow(signature, e, n)
    return message_hash == hash_from_signature

if __name__ == "__main__":
    # Generate RSA keys
    public_key, private_key = generate_keys()
    print(f"Public Key: ({public_key[0]}, {public_key[1]})")
    print(f"Private Key: ({private_key[0]}, {private_key[1]})")

    # Message to be signed
    message = "hel"

    # Sign the message
    signature = sign_message(message, private_key)
    print(f"Signature: {signature}")

    # Verify the signature
    is_valid = verify_signature(message, signature, public_key)
    print(f"Signature valid: {is_valid}")
