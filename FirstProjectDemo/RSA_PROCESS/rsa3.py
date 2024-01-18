from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Function to generate RSA keys for a given user
def generate_keys(user):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save public key to PEM file
    with open(f'{user}_public_key.pem', 'wb') as file:
        file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Save private key to PEM file (for demonstration purposes, consider security implications of storing private keys)
    with open(f'{user}_private_key.pem', 'wb') as file:
        file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return private_key, public_key

# Function to encrypt or decrypt a file using RSA
def encrypt_decrypt_file(file_path, key, output_file, sender, receiver, is_encrypt=True):
    with open(file_path, 'rb') as file:
        data = file.read()

    processed_data = key.encrypt(data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)) if is_encrypt else key.decrypt(data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    with open(output_file, 'wb') as file:
        file.write(processed_data)

    print(f"File {'encrypted' if is_encrypt else 'decrypted'} by {sender if is_encrypt else receiver} for {receiver if is_encrypt else sender}.")

# Function to sign or verify a file using RSA
def sign_verify_file(file_path, key, output_signature, sender, receiver, is_sign=True):
    with open(file_path, 'rb') as file:
        data = file.read()

    processed_data = key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()) if is_sign else None

    with open(output_signature, 'wb') as file:
        file.write(processed_data if is_sign else b'')

    if is_sign:
        print(f"Signature {'generated' if is_sign else 'verified'} by {sender} for {receiver}.")
    else:
        try:
            key.verify(processed_data, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            print(f"Signature is valid for the file sent by {sender} to {receiver}.")
        except:
            print(f"Signature is invalid for the file sent by {sender} to {receiver}.")
def verify_signature(file_path, signature_file, public_key, sender, receiver):
    with open(file_path, 'rb') as file:
        data = file.read()

    with open(signature_file, 'rb') as file:
        signature = file.read()

    try:
        public_key.verify(signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        print(f"Signature is valid for the file sent by {sender} to {receiver}. Verification successful.")
    except:
        print(f"Signature is invalid for the file sent by {sender} to {receiver}. Verification failed.")


def main():
    user_a_private_key, user_a_public_key = generate_keys('user_a')
    user_b_private_key, user_b_public_key = generate_keys('user_b')
    encrypt_decrypt_file('file_for_b.txt', user_b_public_key, 'encrypted_file_for_b.bin', 'user_a', 'user_b', True)
    encrypt_decrypt_file('encrypted_file_for_b.bin', user_b_private_key, 'decrypted_file_by_b.txt', 'user_a', 'user_b', False)
    encrypt_decrypt_file('file_for_a.txt', user_a_public_key, 'encrypted_file_for_a.bin', 'user_b', 'user_a', True)
    encrypt_decrypt_file('encrypted_file_for_a.bin', user_a_private_key, 'decrypted_file_by_a.txt', 'user_b', 'user_a', False)


    # Signing and Verifying for User A and User B
    sign_verify_file('file_for_b.txt', user_a_private_key, 'file_signature_by_a.bin', 'user_a', 'user_b')
    verify_signature('file_for_b.txt', 'file_signature_by_a.bin', user_a_public_key, 'user_a', 'user_b')

    sign_verify_file('file_for_a.txt', user_b_private_key, 'file_signature_by_b.bin', 'user_b', 'user_a')
    verify_signature('file_for_a.txt', 'file_signature_by_b.bin', user_b_public_key, 'user_b', 'user_a')

    


    # Signing and Verifying for User A and User B (same as before)

    # Calculate hash values for files
    actual_file_hash_a = calculate_hash('file_for_b.txt')
    encrypted_file_hash_a = calculate_hash('encrypted_file_for_b.bin')
    decrypted_file_hash_b = calculate_hash('decrypted_file_by_b.txt')

    actual_file_hash_b = calculate_hash('file_for_a.txt')
    encrypted_file_hash_b = calculate_hash('encrypted_file_for_a.bin')
    decrypted_file_hash_a = calculate_hash('decrypted_file_by_a.txt')

    # Display hash values
    print("Hash values for User A:")
    print(f"Actual File: {actual_file_hash_a.hex()}")
    print(f"Encrypted File: {encrypted_file_hash_a.hex()}")
    print(f"Decrypted File: {decrypted_file_hash_b.hex()}")

    print("\nHash values for User B:")
    print(f"Actual File: {actual_file_hash_b.hex()}")
    print(f"Encrypted File: {encrypted_file_hash_b.hex()}")
    print(f"Decrypted File: {decrypted_file_hash_a.hex()}")



def calculate_hash(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
        hash_value = hashes.Hash(hashes.SHA256())
        hash_value.update(data)
        return hash_value.finalize()


if __name__ == "__main__":
    main()