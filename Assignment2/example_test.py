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
    