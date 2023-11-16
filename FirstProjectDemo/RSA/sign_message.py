from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import sys

def sign_message(message, private_key_file):
    with open(private_key_file, "rb") as f:
        private_key = f.read()

    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python sign_message.py <message> <private_key_file>")
        sys.exit(1)

    message_to_sign = sys.argv[1]
    private_key_file = sys.argv[2]

    signature = sign_message(message_to_sign, private_key_file)
    print(f"Signature (hex): {signature.hex()}")
