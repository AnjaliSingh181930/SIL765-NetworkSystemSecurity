# SIL765 - Assignment 2

## Submitted By:

`Name:`  Anjali Singh  
`Entry Number:`  2023JCS2565  

## Script Overview

## Prerequisites

- We need to install some python libraries to the run the python script.

  - cryptography: 
    - This library provides cryptographic recipes and primitives to Python developers. 
    - It offers high-level cryptographic APIs for performing various cryptographic operations, such as encryption, decryption, signing, and verification. 
    - It's widely used for secure communication and data protection.
    - `Installation:`
    ```bash
       pip install cryptography
    ```
  - pycryptodome(Crypto):
    - This library is a collection of cryptographic algorithms and protocols implemented in Python. 
    - It supports various encryption algorithms, hash functions, and cryptographic protocols. 
    - It's often used for implementing cryptographic features in Python applications. 
    - `Installation:`
    ```bash
       pip install pycryptodome
    ```
  - os
    - This is a standard Python library that provides functions for interacting with the operating system. 
    - It offers a portable way of using operating system-dependent functionality, such as file operations, environment variables, and process management.
    - `No Installation needed` 

  - time
    - Another standard Python library, the time module provides functions for working with time-related tasks, such as measuring time intervals, sleeping, and getting the current time.
    -`No Installation needed` 
    

## Code Segment
## Cryptographic Functionality Implementation

The Python code implements various cryptographic functionalities using the `cryptography` and `Crypto` libraries. Here's an overview of what the code accomplishes:
### Key Generation
The `generate_keys` method generates various cryptographic keys required for encryption, decryption, and signature generation. It generates symmetric keys, RSA key pairs for both sender and receiver, and elliptic curve cryptography (ECC) keys for the sender.

### Nonce Generation
The `generate_nonces` method generates nonces required for encryption and authentication in different cryptographic algorithms. It generates nonces for AES-128-CBC, AES-128-CTR, RSA-2048, AES-128-CMAC, SHA3-256-HMAC, RSA-2048-SHA3-256, ECDSA, and AES-128-GCM.

### Encryption
The `encrypt` method encrypts plaintext using various encryption algorithms such as AES-128-CBC, AES-128-CTR, and RSA-2048.

### Decryption
The `decrypt` method decrypts ciphertext using various decryption algorithms corresponding to the encryption algorithms used.

### Authentication Tag Generation
The `generate_auth_tag` method generates authentication tags for the given plaintext using algorithms such as AES-128-CMAC, SHA3-256-HMAC, RSA-2048-SHA3-256-SIG, and ECDSA-256-SHA3-256-SIG.

### Authentication Tag Verification
The `verify_auth_tag` method verifies the authenticity of the given plaintext by verifying the authentication tag using algorithms such as AES-128-CMAC-VRF, SHA3-256-HMAC-VRF, RSA-2048-SHA3-256-SIG-VRF, and ECDSA-256-SHA3-256-SIG-VRF.

### Encrypt and Generate Authentication Tag
The `encrypt_generate_auth` method encrypts plaintext and generates an authentication tag using the AES-128-GCM algorithm.

### Decrypt and Verify Authentication Tag
The `decrypt_verify_auth` method decrypts ciphertext and verifies the authentication tag using the AES-128-GCM-VRF algorithm.

## Cryptographic Algorithms Overview

### AES (Advanced Encryption Standard)

- **Description**: AES is a symmetric encryption algorithm used for encrypting and decrypting data.
- **Operation**: It operates on fixed-length blocks of data (128 bits in this case) and supports different block cipher modes such as CBC (Cipher Block Chaining) and CTR (Counter).
- **Key Length**: AES-128 refers to AES with a key length of 128 bits.

### RSA (Rivest-Shamir-Adleman)

- **Description**: RSA is an asymmetric encryption algorithm used for secure data transmission and digital signatures.
- **Key Pair**: It uses a public-private key pair, where the public key is used for encryption and the private key is used for decryption or signature generation.
- **Key Length**: RSA-2048 refers to RSA with a key length of 2048 bits.

### CMAC (Cipher-based Message Authentication Code)

- **Description**: CMAC is a cryptographic message authentication code algorithm based on a symmetric key block cipher (in this case, AES).
- **Functionality**: It provides integrity and authenticity of a message and is suitable for verifying the integrity of transmitted data.

### SHA3-256 (Secure Hash Algorithm 3)

- **Description**: SHA3-256 is a cryptographic hash function that produces a fixed-size output (256 bits) for an input of any size.
- **Usage**: It is used for computing a condensed representation of a message or data set, often called a hash or message digest.
- **Properties**: SHA3-256 provides collision resistance, meaning it is computationally infeasible to find two different inputs that produce the same hash output.

### ECDSA (Elliptic Curve Digital Signature Algorithm)

- **Description**: ECDSA is a variant of the Digital Signature Algorithm (DSA) that uses elliptic curve cryptography.
- **Functionality**: It provides digital signatures, which can be used to verify the authenticity and integrity of messages.
- **Key Length**: ECDSA-256 refers to ECDSA with a key length of 256 bits.

### GCM (Galois/Counter Mode)

- **Description**: GCM is a block cipher mode of operation used for authenticated encryption with associated data (AEAD).
- **Features**: It combines the Counter mode of encryption (CTR) with message authentication codes (MACs) for both confidentiality and authenticity.
- **Instance**: AES-128-GCM is a specific instance of GCM mode that uses AES with a 128-bit key for encryption.

## setup_env.sh

```sh
#!/usr/bin/env bash

# Install packages

pip install cryptography
pip install pycryptodome

```
## execute_text.py

```py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, utils, ec
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.cmac import CMAC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA3_256
from Crypto.Random import random
from Crypto.Protocol.KDF import CMAC
import os 
import time

class ExecuteCrypto(object): # Do not change this
    def generate_keys(self):
        """Generate keys"""

        # Write your script here
        symmetric_key=b'aLc9vPtusfQPeoy7'
        rsa_key_pair_sender = RSA.generate(2048)
        rsa_key_pair_receiver = RSA.generate(2048)
        public_key_sender_rsa = rsa_key_pair_sender.publickey().export_key()
        private_key_sender_rsa = rsa_key_pair_sender.export_key()
        public_key_receiver_rsa = rsa_key_pair_receiver.publickey().export_key()
        private_key_receiver_rsa = rsa_key_pair_receiver.export_key()
        private_key_sender_ecc = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key_sender_ecc=private_key_sender_ecc.public_key()

        
        print("Symmetric Key") # Do not change this
        print(symmetric_key) # Do not change this
        print("Sender's RSA Public Key") # Do not change this
        print(public_key_sender_rsa) # Do not change this
        print("Sender's RSA Private Key") # Do not change this
        print(private_key_sender_rsa) # Do not change this
        print("Receiver's RSA Public Key") # Do not change this
        print(public_key_receiver_rsa) # Do not change this
        print("Receiver's RSA Private Key") # Do not change this
        print(private_key_receiver_rsa) # Do not change this
        print("Sender's ECC Public Key") # Do not change this
        print(public_key_sender_ecc) # Do not change this
        print("Sender's ECC Private Key") # Do not change this
        print(private_key_sender_ecc) # Do not change this

        return symmetric_key, \
                public_key_sender_rsa, private_key_sender_rsa, \
                public_key_receiver_rsa, private_key_receiver_rsa, \
                public_key_sender_ecc, private_key_sender_ecc # Do not change this

    def generate_nonces(self):
        """Generate nonces"""

        # Write your script here
        nonce_aes_cbc = os.urandom(16)
        nonce_aes_ctr = os.urandom(16)
        nonce_encrypt_rsa = os.urandom(256)
        nonce_aes_cmac =os.urandom(16)
        nonce_hmac =os.urandom(32)
        nonce_tag_rsa =os.urandom(32)
        nonce_ecdsa =os.urandom(32)
        nonce_aes_gcm =os.urandom(16)

        print("Nonce for AES-128-CBC") # Do not change this
        print(nonce_aes_cbc) # Do not change this
        print("Nonce for AES-128-CTR") # Do not change this
        print(nonce_aes_ctr) # Do not change this
        print("NOnce for RSA-2048") # Do not change this
        print(nonce_encrypt_rsa) # Do not change this
        print("Nonce for AES-128-CMAC") # Do not change this
        print(nonce_aes_cmac) # Do not change this
        print("Nonce for SHA3-256-HMAC") # Do not change this
        print(nonce_hmac) # Do not change this
        print("Nonce for RSA-2048-SHA3-256")# Do not change this
        print(nonce_tag_rsa) # Do not change this
        print("Nonce for ECDSA") # Do not change this
        print(nonce_ecdsa) # Do not change this
        print("Nonce for AES-128-GCM") # Do not change this
        print(nonce_aes_gcm) # Do not change this

        return nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
                nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm # Do not change this

    def encrypt(self, algo, key, plaintext, nonce): # Do not change this
        """Encrypt the given plaintext"""

        # Write your script here
        # Record the start time
        start_time = time.time()
        
        if algo == 'AES-128-CBC-ENC': # Do not change this
            # Write your script here
            plaintext = plaintext.encode('utf-8')
            cipher = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            padded_plaintext = padder.update(plaintext) + padder.finalize()
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        elif algo == 'AES-128-CTR-ENC': # Do not change this
            # Write your script here
            plaintext = plaintext.encode('utf-8')
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
           
        elif algo == 'RSA-2048-ENC': # Do not change this
            # Write your script here
            rsa_key = RSA.import_key(key)
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            ciphertext = cipher_rsa.encrypt(plaintext)

        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here
        # Record the end time
        end_time = time.time()
        
        # Calculate the elapsed time
        elapsed_time = end_time - start_time

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Elapsed time:", elapsed_time, "seconds")

        return ciphertext # Do not change this

    def decrypt(self, algo, key, ciphertext, nonce): # Do not change this
        """Decrypt the given ciphertext"""
        # Write your script here
        # Record the start time
        start_time = time.time()
        
        if algo=='AES-128-CBC-DEC': # Do not change this
            # Write your script here
            cipher = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()
            plaintext = plaintext.decode('utf-8')
            
        elif algo == 'AES-128-CTR-DEC': # Do not change this
            # Write your script here
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = plaintext.decode('utf-8')
            
        elif algo == 'RSA-2048-DEC': # Do not change this
            # Write your script here
            rsa_key = RSA.import_key(key)
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            plaintext = cipher_rsa.decrypt(ciphertext)
               
        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here
        # Record the end time
        end_time = time.time()
        
        # Calculate the elapsed time
        elapsed_time = end_time - start_time

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Elapsed time:", elapsed_time, "seconds")
 
        return plaintext # Do not change this

    def generate_auth_tag(self, algo, key, plaintext, nonce): # Do not change this
        """Generate the authenticate tag for the given plaintext"""

        # Write your script here
        # Record the start time
        start_time = time.time()
        
        if algo =='AES-128-CMAC-GEN': # Do not change this
            # Write your script here
            cipher = CMAC.new(key, ciphermod=AES)
            cipher.update(pad(plaintext.encode('utf-8'), AES.block_size))
            auth_tag = cipher.digest()
            
        elif algo =='SHA3-256-HMAC-GEN': # Do not change this
            # Write your script here
            h = SHA3_256.new(key)
            h.update(plaintext.encode('utf-8'))
            auth_tag = h.digest()
            
        elif algo =='RSA-2048-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here
            rsa_key = RSA.import_key(key)
            h = SHA3_256.new(plaintext.encode('utf-8'))
            sign = pkcs1_15.new(rsa_key).sign(h)
            auth_tag = sign
            
        elif algo =='ECDSA-256-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here
            auth_tag = key.sign(plaintext.encode('utf-8'), ec.ECDSA(hashes.SHA256()))

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here
        # Record the end time
        end_time = time.time()
        
        # Calculate the elapsed time
        elapsed_time = end_time - start_time

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Elapsed time:", elapsed_time, "seconds")
        
        return auth_tag # Do not change this

    def verify_auth_tag(self, algo, key, plaintext, nonce, auth_tag): # Do not change this
        """Verify the authenticate tag for the given plaintext"""

        # Write your script here
        plaintext=plaintext.encode('utf-8')
        # Record the start time
        start_time = time.time()
        
        if algo == 'AES-128-CMAC-VRF': # Do not change this
            # Write your script here
            cipher = CMAC.new(key, ciphermod=AES)
            cipher.update(pad(plaintext, AES.block_size))
            auth_tag_valid = auth_tag == cipher.digest()

        elif algo == 'SHA3-256-HMAC-VRF': # Do not change this
            # Write your script here
            h = SHA3_256.new(key)
            h.update(plaintext)
            auth_tag_valid = auth_tag == h.digest()

        elif algo == 'RSA-2048-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            rsa_key = RSA.import_key(key)
            h = SHA3_256.new(plaintext)
            try:
                pkcs1_15.new(rsa_key).verify(h, auth_tag)
                auth_tag_valid = True
            except (ValueError, TypeError): 
                auth_tag_valid = False

        elif algo == 'ECDSA-256-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            try:
                key.verify(auth_tag, plaintext, ec.ECDSA(hashes.SHA256()))
                print("Signature is valid.")
                auth_tag_valid=True
            except utils.InvalidSignature:
                print("Signature is invalid.")
                auth_tag_valid=False
                
        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here
        # Record the end time
        end_time = time.time()
        
        # Calculate the elapsed time
        elapsed_time = end_time - start_time
        
        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not chang        e this
        print("Elapsed time:", elapsed_time, "seconds")
         
        return auth_tag_valid # Do not change this

    def encrypt_generate_auth(self, algo, key_encrypt, key_generate_auth, plaintext, nonce): # Do not change this
        """Encrypt and generate the authentication tag for the given plaintext"""

        # Write your script here
        plaintext=plaintext.encode('utf-8')
        # Record the start time
        start_time = time.time()
        
        if algo == 'AES-128-GCM-GEN': # Do not change this
            # Write your script here
            cipher = AES.new(key_encrypt, AES.MODE_GCM, nonce=nonce)
            ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here
        # Record the end time
        end_time = time.time()
        
        # Calculate the elapsed time
        elapsed_time = end_time - start_time
        
        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key_encrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_generate_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Elapsed time:", elapsed_time, "seconds")
        
        return ciphertext, auth_tag # Do not change this

    def decrypt_verify_auth(self, algo, key_decrypt, key_verify_auth, ciphertext, nonce, auth_tag): # Do not change this
        """Decrypt and verify the authentication tag for the given plaintext"""

        # Write your script here
        # Record the start time
        start_time = time.time()
        
        if algo == 'AES-128-GCM-VRF': # Do not change this
            # Write your script here
            cipher = AES.new(key_decrypt, AES.MODE_GCM, nonce=nonce)
            cipher.update(b"")
            
            try:
                decrypted_data = cipher.decrypt(ciphertext)
                cipher.verify(auth_tag)
                auth_tag_valid = True
                plaintext = decrypted_data
            except ValueError:
                plaintext = b"Decryption failed or authentication tag invalid"
                auth_tag_valid = True

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here
        plaintext=plaintext.decode('utf-8')
        # Record the end time
        end_time = time.time()
        
        # Calculate the elapsed time
        elapsed_time = end_time - start_time
        
        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key_decrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_verify_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this
        print("Elapsed time:", elapsed_time, "seconds")
        
        return plaintext, auth_tag_valid # Do not change this

if __name__ == '__main__': # Do not change this
    ExecuteCrypto() # Do not change this
```
## example_text.py
This Python script is designed to call various cryptographic algorithms and techniques using the ExecuteCrypto class.

``` py
from execute_crypto import ExecuteCrypto

# Call ExecuteCrypto class method
instance = ExecuteCrypto()

# Extract Plaintext
with open("original_plaintext.txt", "r") as file:
    # Read from file
    plaintext = file.read()

# Call the generate_keys function
symmetric_key, public_key_sender_rsa, \
private_key_sender_rsa, public_key_receiver_rsa, \
private_key_receiver_rsa, public_key_sender_ecc, private_key_sender_ecc = instance.generate_keys()

# Call the generate_nonces function
nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm = instance.generate_nonces()

# AES-128-CBC
ciphertext_AES_128_CBC_ENC = instance.encrypt('AES-128-CBC-ENC', symmetric_key, plaintext, nonce_aes_cbc)
plaintext_AES_128_CBC_DEC =  instance.decrypt('AES-128-CBC-DEC', symmetric_key, ciphertext_AES_128_CBC_ENC, nonce_aes_cbc)

# AES-128-CTR
ciphertext_AES_128_CTR_ENC = instance.encrypt('AES-128-CTR-ENC', symmetric_key, plaintext, nonce_aes_ctr)
plaintext_AES_128_CTR_DEC =  instance.decrypt('AES-128-CTR-DEC', symmetric_key, ciphertext_AES_128_CTR_ENC, nonce_aes_ctr)

# 'RSA-2048'
ciphertext_RSA_2048_ENC = instance.encrypt('RSA-2048-ENC', private_key_sender_ecc, plaintext, nonce_aes_ctr)
plaintext_RSA_2048_DEC =  instance.decrypt('RSA-2048-DEC', public_key_sender_ecc, ciphertext_RSA_2048_ENC, nonce_aes_ctr)

# AES-128-CMAC
auth_tag_AES_128_CMAC_GEN = instance.generate_auth_tag("AES-128-CMAC-GEN", symmetric_key, plaintext, nonce_aes_cmac)
auth_tag_valid_AES_128_CMAC_GEN = instance.verify_auth_tag("AES-128-CMAC-VRF", symmetric_key, plaintext, nonce_aes_cmac, auth_tag_AES_128_CMAC_GEN)

# SHA3-256-HMAC
auth_tag_SHA3_256_HMAC_GEN = instance.generate_auth_tag("SHA3-256-HMAC-GEN", symmetric_key, plaintext, nonce_hmac)
auth_tag_valid_SHA3_256_HMAC_GEN = instance.verify_auth_tag("SHA3-256-HMAC-VRF", symmetric_key, plaintext, nonce_hmac, auth_tag_SHA3_256_HMAC_GEN)

# RSA_2048_SHA3_256_SIG_GEN
auth_tag_RSA_2048_SHA3_256_SIG_GEN = instance.generate_auth_tag("RSA-2048-SHA3-256-SIG-GEN", private_key_sender_rsa, plaintext, nonce_tag_rsa)
auth_tag_valid_RSA_2048_SHA3_256_SIG_GEN = instance.verify_auth_tag("RSA-2048-SHA3-256-SIG-VRF", public_key_sender_rsa, plaintext, nonce_tag_rsa, auth_tag_RSA_2048_SHA3_256_SIG_GEN)

# ECDSA-256-SHA3-256-SIG-GEN
auth_tag_ECDSA_256_SHA3_256_SIG_GEN = instance.generate_auth_tag("ECDSA-256-SHA3-256-SIG-GEN", private_key_sender_ecc, plaintext, nonce_ecdsa)
auth_tag_valid_ECDSA_256_SHA3_256_SIG_GEN = instance.verify_auth_tag("ECDSA-256-SHA3-256-SIG-VRF", public_key_sender_ecc, plaintext, nonce_ecdsa, auth_tag_ECDSA_256_SHA3_256_SIG_GEN)

# AES-128-GCM-GEN
ciphertext_AES_128_GCM_GEN, auth_tag_AES_128_GCM_GEN = instance.encrypt_generate_auth("AES-128-GCM-GEN", symmetric_key, symmetric_key, plaintext, nonce_aes_gcm)
ecrypted_text_aes_gcm, auth_tag_valid_aes_gcm = instance.decrypt_verify_auth("AES-128-GCM-VRF", symmetric_key, symmetric_key, ciphertext_AES_128_GCM_GEN, nonce_aes_gcm, auth_tag_AES_128_GCM_GEN)
    
```

## Illustrative Table for Presesnting results 

| Algorithm                 | Execution Time (ms)        | Packet Length (bits) | Key Length (bits) |
|---------------------------|----------------------------|----------------------|-------------------|
| AES-128-CBC-ENC           | 0.2002716064453125 ms      | Plaintext Size:912 bits, Ciphertext Size:1024 bits              | 128 bits          |
| AES-128-CBC-DEC           | 0.11682510375976562 ms     | 1024 bits            | 128 bits          |
| AES-128-CTR-ENC           | 0.10466575622558594 ms     | 912 bits             | 128 bits          |
| AES-128-CTR-DEC           | 0.06985664367675781 ms     | 912 bits             | 128 bits          |
| RSA-2048-ENC              | 2.9397010803222656 ms      | 2048 bits             | 2048 bits         |
| RSA-2048-DEC              | 45.68362236022949 ms       | 2048 bits            | 2048 bits         |
| AES-128-CMAC-GEN          | 0.2701282501220703 ms      | 128 bits             | 128 bits          |
| AES-128-CMAC-VRF          | 0.08130073547363281 ms     | 128 bits             | 128 bits          |
| SHA3-256-HMAC-GEN         | 0.05626678466796875 ms     | 256 bits             | 128 bits          |
| SHA3-256-HMAC-VRF         | 0.012874603271484375 ms    | 256 bits             | 128 bits          |
| RSA-2048-SHA3-256-SIG-GEN | 46.645164489746094 ms      | 2048 bits             | 2048 bits         |
| RSA-2048-SHA3-256-SIG-VRF | 1.5120506286621094 ms      | 2048 bits            | 2048 bits         |
| ECDSA-256-SHA3-256-SIG-GEN| 0.34332275390625 ms        | 576 bits             | 256 bits          |
| ECDSA-256-SHA3-256-SIG-VRF| 0.14591217041015625 ms     | 576 bits             | 256 bits          |
| AES-128-GCM-GEN           | 0.2608299255371094 ms      | 912 bits             | 128 bits          |
| AES-128-GCM-VRF           | 0.36072731018066406 ms     | 912 bits             | 128 bits          |


# Execution Time (ms)

This graph illustrates the execution time, in milliseconds (ms), for various cryptographic algorithms. Each algorithm is represented along the x-axis, and the corresponding execution time is plotted along the y-axis.

- **Highest Execution Time:** RSA-2048-DEC - 45.68 ms
- **Lowest Execution Time:** SHA3-256-HMAC-VRF - 0.0129 ms


# Packet Length (bits)

This graph displays the packet length, measured in bits, used by each cryptographic algorithm. Similar to the execution time graph, each algorithm is plotted along the x-axis, and its respective packet length is represented along the y-axis.

- **Highest Packet Length:** RSA-2048-DEC - 2048 bits
- **Lowest Packet Length:** AES-128-CBC-ENC, AES-128-CTR-ENC, AES-128-CTR-DEC, AES-128-CMAC-GEN, AES-128-GCM-GEN, AES-128-GCM-VRF - 912 bits


# Key Length (bits)

The key length graph depicts the size of cryptographic keys used by each algorithm, measured in bits. Similar to the previous graphs, algorithms are listed along the x-axis, while the key length is represented along the y-axis.

- **Highest Key Length:** RSA-2048-ENC, RSA-2048-DEC, RSA-2048-SHA3-256-SIG-GEN, RSA-2048-SHA3-256-SIG-VRF - 2048 bits
- **Lowest Key Length:** AES-128-CBC-ENC, AES-128-CBC-DEC, AES-128-CTR-ENC, AES-128-CTR-DEC, AES-128-CMAC-GEN, AES-128-CMAC-VRF, SHA3-256-HMAC-GEN, SHA3-256-HMAC-VRF, ECDSA-256-SHA3-256-SIG-GEN, ECDSA-256-SHA3-256-SIG-VRF, AES-128-GCM-GEN, AES-128-GCM-VRF - 128 bits


These graphs and associated statistics provide a comprehensive overview of the performance, data size requirements, and security considerations associated with various cryptographic algorithms.

![Results Plot](plot.png)




