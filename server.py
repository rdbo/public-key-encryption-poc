# NOTE: Client key is smaller than server key,
# because this is for testing purposes only!

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome import Random
import socket

# Generate server RSA keypair
# All the clients should know the server public key beforehand,
# so that they can encrypt messages that will be received by the server,
# and the server can decrypt them using the private key
print("Generating server RSA keypair...")
rng = Random.new().read
key = RSA.generate(4096, rng)
public_key_bytes = key.publickey().export_key()
print("Server Public Key: " + public_key_bytes.hex())

# Save public key in a file that will be read by the client
# NOTE: the public key can be hardcoded in the client, as long
# as the server keypair doesn't change
print("Saving server public key...")
with open("server_public_key.pem", "wb") as f:
    f.write(public_key_bytes)
    f.close()

# Create server socket
# NOTE: this server will only allow 1 client to connect,
#       since we don't want to complicate things now
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 1337))
sock.listen(1)

# Wait and handle client connection
print("Waiting for client...")
conn, addr = sock.accept()
print(f"Client connected from: {addr}")

# Create server cipher RSA for decrypting messages
cipher_rsa = PKCS1_OAEP.new(key)

# Client will send his public key encrypted so that we can encrypt our
# responses using their public key, and they will decrypt it using their
# private key.
# NOTE: the client public key is encrypted with the server private key that
# they've had beforehand, so we need to decrypt it first
packet_size = int(4096 / 8)
enc_client_pubkey = conn.recv(packet_size) # Receive up to "key-size" bytes
print("Encrypted Client Public Key: " + enc_client_pubkey.hex())

client_pubkey_raw = cipher_rsa.decrypt(enc_client_pubkey)
print("Decrypted Client Public Key: " + client_pubkey_raw.hex())

# Create client cipher RSA for encrypting messages
client_pubkey = RSA.import_key(client_pubkey_raw)
client_cipher_rsa = PKCS1_OAEP.new(client_pubkey)

# Send encrypted message to the client using his public key
enc_message = client_cipher_rsa.encrypt(b"Hello from server!")
conn.send(enc_message)

# Receive encrypted message from the client and decrypt with server private key
enc_message = conn.recv(packet_size)
message = cipher_rsa.decrypt(enc_message)
print("Message from Client: " + message.decode())
