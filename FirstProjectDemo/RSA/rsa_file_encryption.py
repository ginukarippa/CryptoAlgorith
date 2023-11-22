from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import RSA.HashingFile
# Generate an RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Serialize the private key and write it to a file (usually kept secure)
with open('private_key.pem', 'wb') as f:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    f.write(pem)

# Get the public key
public_key = private_key.public_key()

# Serialize the public key and write it to a file
with open('public_key.pem', 'wb') as f:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    f.write(pem)

# Function to encrypt a file using the public key
def encrypt_file(file_path, public_key):
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    encrypted = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    with open(f"{file_path}.enc", 'wb') as f:
        f.write(encrypted)
    print(f"{file_path}.enc","File encrypted successfully!")

# Function to decrypt a file using the private key
def decrypt_file(file_path, private_key):
    with open(file_path, 'rb') as f:
        encrypted = f.read()
    
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    with open(f"{file_path[:-4]}.dec", 'wb') as f:
        f.write(decrypted)
   
    print(f"{file_path[:-4]}.dec","File decrypted successfully!")
    

# Example usage: Encrypt a file
encrypt_file('file_to_encrypt.txt', public_key)
# Example usage: Decrypt the encrypted file
decrypt_file('file_to_encrypt.txt.enc', private_key)

print("********Hash Values of the Files  *****************************")
print("Hash Value for the  Orginal File   :",RSA.HashingFile.hash_file('file_to_encrypt.txt'))
print("Hash Value for the  Encrypted File :",RSA.HashingFile.hash_file('file_to_encrypt.txt.enc'))
print("Hash Value for the  Decrypted File :",RSA.HashingFile.hash_file('file_to_encrypt.txt.dec'))