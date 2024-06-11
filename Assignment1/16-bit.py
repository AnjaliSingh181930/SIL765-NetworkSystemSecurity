# For 16-bit key
from random import randbytes
import pyaes

def brute_force():
    key = b"\x00" * 14
    plaintext = b'First Plaintextt'
    ciphertext =b'pR\xb0\xa3\xeb\xc0iI}\x99\x89\x13\xb9\x0e\xc2.'

    for i in range(2**16):  # Try all possibilities for the last 4 bytes
        last_two_bytes = i.to_bytes(2, byteorder='big')
        f_key = key + last_two_bytes
        aes = pyaes.AESModeOfOperationCTR(f_key)
        deciphered = aes.decrypt(ciphertext)

        if deciphered == plaintext:
            print("Key found:", f_key)
        
      
brute_force()