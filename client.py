# NOTE: Client key is smaller than server key,
# because this is for testing purposes only!

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome import Random
import socket

# Genereate RSA keypair for this connection only
print("Generating client RSA keypair for this connection...")
key = RSA.generate(2048, Random.new().read)
public_key_bytes = key.publickey().export_key()

print("Client Public Key: " + public_key_bytes.hex())

# Read server public key from file
# NOTE: the server public key can also be hardcoded, as long as it doesn't change
print("Reading server public key...")
server_pubkey = RSA.import_key(open("server_public_key.pem").read())

# Create RSA ciphers for encrypting messages to the server,
# and decrypting messages from the server that use the client public key
server_cipher_rsa = PKCS1_OAEP.new(server_pubkey)
cipher_rsa = PKCS1_OAEP.new(key)

# Encrypt client public key using server public key.
# The result will be sent to the server
enc_client_pubkey = server_cipher_rsa.encrypt(public_key_bytes)

# Connect to the server
print("Connecting to server...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 1337))

# Send encrypted public key to the server
sock.sendall(enc_client_pubkey)

# Receive encrypted message from the server, decrypt with client private key
packet_size = int(2048 / 8)
enc_message = sock.recv(packet_size)
print("Encrypted Message from Server: " + enc_message.hex())

message = cipher_rsa.decrypt(enc_message)
print("Message from Server: " + message.decode())

# Send encrypted message to the server
enc_message = server_cipher_rsa.encrypt(b"Hello from client")
sock.sendall(enc_message)
