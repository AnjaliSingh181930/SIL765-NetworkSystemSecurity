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

        # Open the file in read mode
        # with open("examples/keys/symmetric_key.txt", "r") as file:
        #     # Read from file
        #     symmetric_key = file.read()
        #     symmetric_key = symmetric_key.encode()
        
        # public_key_sender_rsa = ""   
        # # Open the file in read mode
        # with open("examples/keys/public_key_sender_rsa.pem", "r") as file:
        #     # Read from file
        #     for line in file:
        #         if not line.startswith("---"):
        #             public_key_sender_rsa += line
        #     public_key_sender_rsa =  public_key_sender_rsa.encode()  
                    
        # private_key_sender_rsa = ""               
        # # Open the file in read mode    
        # with open("examples/keys/private_key_sender_rsa.pem", "r") as file:  
        #     # Read from file
        #     for line in file:
        #         if not line.startswith("---"):
        #             private_key_sender_rsa += line  
        #     private_key_sender_rsa =  private_key_sender_rsa.encode() 
                    
        # public_key_receiver_rsa = ""    
        # # Open the file in read mode
        # with open("examples/keys/public_key_receiver_rsa.pem", "r") as file:
        #     # Read from file
        #     for line in file:
        #         if not line.startswith("---"):
        #             public_key_receiver_rsa += line
        #     public_key_receiver_rsa = public_key_receiver_rsa.encode()
        
        # private_key_receiver_rsa = ""     
        # # Open the file in read mode
        # with open("examples/keys/private_key_receiver_rsa.pem", "r") as file:
        #     # Read from file
        #     for line in file:
        #         if not line.startswith("---"):
        #             private_key_receiver_rsa += line
        #     private_key_receiver_rsa = private_key_receiver_rsa .encode()

        # public_key_sender_ecc = ""     
        # # Open the file in read mode
        # with open("examples/keys/public_key_sender_ecc.pem", "r") as file:
        #     # Read from file
        #     for line in file:
        #         if not line.startswith("---"):
        #             public_key_sender_ecc += line
        #     public_key_sender_ecc = public_key_sender_ecc.encode()
        
        # private_key_sender_ecc = ""            
        # # Open the file in read mode
        # with open("examples/keys/private_key_sender_ecc.pem", "r") as file:
        #     # Read from file
        #     for line in file:
        #         if not line.startswith("---"):
        #             private_key_sender_ecc += line             
        #     private_key_sender_ecc = private_key_sender_ecc.encode()
        
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
        elapsed_time = (end_time - start_time)*1000

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
        print("Elapsed time:", elapsed_time, "milliseconds")
        print("Plaintext size: ", len(plaintext) * 8)
        print("Ciphertext size: ", len(ciphertext) * 8)

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
        elapsed_time = (end_time - start_time)*1000

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
        print("Plaintext size: ", len(plaintext) * 8)
        print("Ciphertext size: ", len(ciphertext) * 8)
        print("Elapsed time:", elapsed_time, "milliseconds")
 
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
        elapsed_time = (end_time - start_time)*1000

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
        print("Elapsed time:", elapsed_time, "milliseconds")
        print("Plaintext size: ", len(plaintext) * 8)
        print("Authentication Tag size: ", len(auth_tag) * 8)
        
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
        elapsed_time = (end_time - start_time)*1000
        
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
        print("Plaintext size: ", len(plaintext) * 8)
        print("Authentication tag size: ", len(auth_tag) * 8)
        print("Elapsed time:", elapsed_time, "milliseconds")
         
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
        elapsed_time = (end_time - start_time)*1000
        
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
        print("Elapsed time:", elapsed_time, "milliseconds")
        print("Ciphertext size: ", len(ciphertext) * 8)
        print("Authentication Tag size: ", len(auth_tag) * 8)
        
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
        elapsed_time = (end_time - start_time)*1000
        
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
        print("Elapsed time:", elapsed_time, "milliseconds")
        print("Plaintext size: ", len(plaintext) * 8)
        print("Ciphertext size: ", len(auth_tag) * 8)
        
        return plaintext, auth_tag_valid # Do not change this

if __name__ == '__main__': # Do not change this
    ExecuteCrypto() # Do not change this