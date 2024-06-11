import pandas as pd
import matplotlib.pyplot as plt

# Define the data
data = {
    'Algorithm': ['AES-128-CBC-ENC', 'AES-128-CBC-DEC', 'AES-128-CTR-ENC', 'AES-128-CTR-DEC',
                  'RSA-2048-ENC', 'RSA-2048-DEC', 'AES-128-CMAC-GEN', 'AES-128-CMAC-VRF',
                  'SHA3-256-HMAC-GEN', 'SHA3-256-HMAC-VRF', 'RSA-2048-SHA3-256-SIG-GEN',
                  'RSA-2048-SHA3-256-SIG-VRF', 'ECDSA-256-SHA3-256-SIG-GEN',
                  'ECDSA-256-SHA3-256-SIG-VRF', 'AES-128-GCM-GEN', 'AES-128-GCM-VRF'],
    'Execution Time (ms)': [0.2002716064453125, 0.11682510375976562, 0.10466575622558594, 0.06985664367675781,
                             2.9397010803222656, 45.68362236022949, 0.2701282501220703, 0.08130073547363281,
                             0.05626678466796875, 0.012874603271484375, 46.645164489746094, 1.5120506286621094,
                             0.34332275390625, 0.14591217041015625, 0.2608299255371094, 0.36072731018066406],
    'Packet Length': ['Plaintext: 912 bits, Ciphertext: 1024 bits',
                      'Plaintext: 912 bits, Ciphertext: 1024 bits',
                      'Plaintext: 912 bits, Ciphertext: 912 bits',
                      'Plaintext: 912 bits, Ciphertext: 912 bits',
                      'Plaintext: 128 bits, Ciphertext: 2048 bits',
                      'Plaintext: 128 bits, Ciphertext: 2048 bits',
                      'Plaintext: 912 bits, Auth Tag: 128 bits',
                      'Plaintext: 912 bits, Auth Tag: 128 bits',
                      'Plaintext: 912 bits, Auth Tag: 256 bits',
                      'Plaintext: 912 bits, Auth Tag: 256 bits',
                      'Plaintext: 912 bits, Auth Tag: 2048 bits',
                      'Plaintext: 912 bits, Auth Tag: 2048 bits',
                      'Plaintext: 912 bits, Auth Tag: 576 bits',
                      'Plaintext: 912 bits, Auth Tag: 576 bits',
                      'Plaintext: 912 bits, Auth Tag: 576 bits',
                      'Plaintext: 912 bits, Auth Tag: 128 bits'],
    'Key Length (bits)': [128, 128, 128, 128, 2048, 2048, 128, 128, 128, 128, 2048, 2048, 256, 256, 128, 128]
}

# Calculate Total Length
total_length = []
for entry in data['Packet Length']:
    parts = entry.split(', ')
    plaintext_size = int(parts[0].split(': ')[1].split(' bits')[0])
    if 'Ciphertext' in entry:
        ciphertext_size = int(parts[1].split(': ')[1].split(' bits')[0])
        total_length.append(plaintext_size + ciphertext_size)
    elif 'Auth Tag' in entry:
        auth_tag_size = int(parts[1].split(': ')[1].split(' bits')[0])
        total_length.append(plaintext_size + auth_tag_size)

# Add Total Length to the data
data['Total Length'] = total_length

# Extract plaintext size from Packet Length
plaintext_size = []
for entry in data['Packet Length']:
    parts = entry.split(', ')
    plaintext_size.append(int(parts[0].split(': ')[1].split(' bits')[0]))

# Add Plaintext Size to the data
data['Plaintext Size (bits)'] = plaintext_size

# Create a DataFrame
df = pd.DataFrame(data)

# Plotting line graph for Execution Time (ms)
plt.figure(figsize=(10, 6))
plt.plot(df['Algorithm'], df['Execution Time (ms)'], marker='o', color='b')
plt.title('Execution Time (ms)')
plt.xlabel('Algorithm')
plt.ylabel('Time (ms)')
plt.xticks(rotation=45)
plt.grid(True)
plt.tight_layout()
plt.savefig('execution_time_graph.png')
plt.show()

# Plotting line graph for Plaintext Size (bits)
plt.figure(figsize=(10, 6))
plt.plot(df['Algorithm'], df['Plaintext Size (bits)'], marker='o', color='purple')
plt.title('Plaintext Size (bits)')
plt.xlabel('Algorithm')
plt.ylabel('Plaintext Size (bits)')
plt.xticks(rotation=45)
plt.grid(True)
plt.tight_layout()
plt.savefig('plaintext_size_graph.png')
plt.show()

# Plotting line graph for Key Length (bits)
plt.figure(figsize=(10, 6))
plt.plot(df['Algorithm'], df['Key Length (bits)'], marker='^', color='g')
plt.title('Key Length (bits)')
plt.xlabel('Algorithm')
plt.ylabel('Length (bits)')
plt.xticks(rotation=45)
plt.grid(True)
plt.tight_layout()
plt.savefig('key_length_graph.png')
plt.show()

# Plotting line graph for Total Length
plt.figure(figsize=(10, 6))
plt.plot(df['Algorithm'], df['Total Length'], marker='o', color='purple')
plt.title('Total Length')
plt.xlabel('Algorithm')
plt.ylabel('Length')
plt.xticks(rotation=45)
plt.grid(True)
plt.tight_layout()
plt.savefig('total_length_graph.png')
plt.show()
