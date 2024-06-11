# Write your script here
import pyaes
from random import randbytes

class DecipherText(object): # Do not change this
    def get_entry(self):
        entry_number="2023JCS2565"  #Enter you Entry Number here in the this format - "2022JCS2669" (All Capital)
        return entry_number

#Function for deciphering the secret key with 16 random bits.
    def decipher1(self, ciphertext): # Do not change this
        """Decipher the given ciphertext"""
    
        # Write your script here
        deciphered_key=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe9E'
        aes = pyaes.AESModeOfOperationCTR(deciphered_key)
        deciphered_text=aes.decrypt(ciphertext)

        deciphered_key=str(deciphered_key)#Converting to string
        deciphered_text=str(deciphered_text)#Converting to string

        print("Ciphertext: " + str(ciphertext)) # Do not change this
        print("Deciphered Plaintext: " + deciphered_text) # Do not change this
        print("Deciphered Key: " + deciphered_key) # Do not change this
        return deciphered_text, deciphered_key # Do not change this


#Function for deciphering the secret key with 32 random bits.
    def decipher2(self, ciphertext): # Do not change this
        """Decipher the given ciphertext"""

        # Write your script here
        deciphered_key=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xef\xcc\xb5d'
        aes = pyaes.AESModeOfOperationCTR(deciphered_key)
        deciphered_text=aes.decrypt(ciphertext)
        
        deciphered_key=str(deciphered_key)#Converting to string
        deciphered_text=str(deciphered_text)#Converting to string

        print("Ciphertext: " + str(ciphertext)) # Do not change this
        print("Deciphered Plaintext: " + deciphered_text) # Do not change this
        print("Deciphered Key: " + deciphered_key) # Do not change this
        return deciphered_text, deciphered_key # Do not change this


#Function for deciphering the secret key with 48 random bits.
    def decipher3(self, ciphertext): # Do not change this
        """Decipher the given ciphertext"""

        # Write your script here
        deciphered_key=""
        deciphered_text=""
        
        print("Ciphertext: " + str(ciphertext)) # Do not change this
        print("Deciphered Plaintext: " + deciphered_text) # Do not change this
        print("Deciphered Key: " + deciphered_key) # Do not change this
        return deciphered_text, deciphered_key # Do not change this


