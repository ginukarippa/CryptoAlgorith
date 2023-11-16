from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import sys

def verify_signature(message, signature, public_key_file):
    with open(public_key_file, "rb") as f:
        public_key = f.read()

    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python verify_signature.py <message> <signature_hex> <public_key_file>")
        sys.exit(1)

    message_to_verify = sys.argv[1]
    signature_to_verify_hex = sys.argv[2]
    signature_to_verify = bytes.fromhex(signature_to_verify_hex)
    public_key_file = sys.argv[3]

    is_valid = verify_signature(message_to_verify, signature_to_verify, public_key_file)

    if is_valid:
        print("Signature is valid.")
    else:
        print("Signature is not valid.")
