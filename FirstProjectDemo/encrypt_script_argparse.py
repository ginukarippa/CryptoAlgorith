import argparse
from  Cryptodome.Cipher import AES
from  Cryptodome.Random import get_random_bytes
from  Cryptodome.Util.Padding import pad
import os
def encrypt_file(filename):
   with open(filename, 'rb') as file:
     plain = file.read()
     aes_key = get_random_bytes(16) # Use 128-bit key
     aes_cipher = AES.new(aes_key, AES.MODE_ECB)
     cipher = aes_cipher.encrypt(pad(plain, AES.block_size))
     output_filename = filename + '.enc'
     with open(output_filename, 'wb') as output_file:
        output_file.write(cipher)
     print("Encryption completed. Key:", aes_key.hex())
def main():
  parser = argparse.ArgumentParser(description="Encrypt a file using AES-ECB mode.")
  parser.add_argument("filename", help="Input filename to encrypt")
  args = parser.parse_args()
  encrypt_file(args.filename)
if __name__ == "__main__":
  main()