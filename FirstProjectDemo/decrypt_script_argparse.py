import argparse
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import os
def decrypt_file(filename, key_hex):
  with open(filename, 'rb') as file:
   cipher = file.read()
  aes_key = bytes.fromhex(key_hex)
  aes_cipher = AES.new(aes_key, AES.MODE_ECB)
  decrypted_padded = aes_cipher.decrypt(cipher)
  decrypted = unpad(decrypted_padded, AES.block_size)
  output_filename = filename[:-4] + '.dec'
  with open(output_filename, 'wb') as output_file:
    output_file.write(decrypted)
    print("Decryption completed. Decrypted file saved as",
   output_filename)
def main():
  parser = argparse.ArgumentParser(description="Decrypt an encrypted file using AES-ECB mode.")
  parser.add_argument("filename", help="Encrypted filename to   decrypt")
  parser.add_argument("key", help="AES key in hexadecimal")
  args = parser.parse_args()
  decrypt_file(args.filename, args.key)
  if __name__ == "__main__":
    main()
