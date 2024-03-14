from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from colorama import Fore, Style
import time

previous_timestamps = [] # Stores all the previous timestamps used.

# Verifies the message has not been modified.
def verify_signature(message_nonce_timestamp, signature, public_key):
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message_nonce_timestamp.encode())
    digest = hasher.finalize()
    try:
        public_key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        print(Fore.GREEN + Style.BRIGHT + "Signature Valid!")
    except InvalidSignature:
        print(Fore.RED + Style.BRIGHT + "Signature Invalid!")

# Verifies timestamp is not too old and unique.
def verify_timestamp(timestamp):
    valid_time = time.time() >= timestamp >= (time.time() - 1)
    timestamp_not_reused = not timestamp in previous_timestamps
    if timestamp_not_reused: previous_timestamps.append(timestamp)
    if valid_time and timestamp_not_reused: print(Fore.GREEN + Style.BRIGHT + "Timestamp Valid!")
    else: print(Fore.RED + Style.BRIGHT + "Timestamp Invalid!")

# Alice generates private and public keys.
alice_private_key = ec.generate_private_key(ec.SECP256R1())
alice_public_key = alice_private_key.public_key()
private_key_serialized = alice_private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption() ).decode()
public_key_serialized = alice_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
print("Alice's Private Key:\n", private_key_serialized)
print("Alice's Public Key:\n", public_key_serialized)

# Alice generates a new message.
message = """The company website has not limited the number of transactions a single user or device can perform in a given period of time. The transactions/time should be above the actual business requirement, but low enough to deter automated attacks."""
timestamp = time.time()                           #Timestamp generation.
message_timestamp = f'{str(timestamp)} {message}' #Concatenation of timestamp, nonce and message.

print("\nTimestamp + Message: ", message_timestamp)

# Alice hashes the message.
hasher = hashes.Hash(hashes.SHA256())   
hasher.update(message_timestamp.encode())
digest = hasher.finalize()
print("\nAlice's Message Digest: ", digest.hex())

# Alice generates a signature for the message.
signature = alice_private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
print("\nAlice's Message Signature: ", Fore.YELLOW, signature.hex())

print(Style.RESET_ALL) #This is used to reset the color and style of the text.

# Message is stored to a dictionary for easier referencing.
alice_message = {"timestamp": timestamp, "message": message, "signature": signature}

# Attacker modified message.
attacker_message = {"timestamp": 1710277196.0713937, "message": "This is a modified message.", "signature": signature}

# Printing the final form of Alice's message.
print("\nFinal Message: ", Fore.CYAN, alice_message["timestamp"],Fore.WHITE, alice_message["message"], Fore.YELLOW, alice_message["signature"].hex())

print(Style.RESET_ALL)

##########################################################################################################################################################
######                                                      Examples of sent messages                                                               ######
##########################################################################################################################################################

print("Example 1: ") #Message recieved normally
verify_signature(f'{alice_message["timestamp"]} {alice_message["message"]}', alice_message["signature"], alice_public_key)
verify_timestamp(alice_message["timestamp"])

print(Style.RESET_ALL) 

print("Example 2: ") #Message replayed
verify_signature(f'{alice_message["timestamp"]} {alice_message["message"]}', alice_message["signature"], alice_public_key)
verify_timestamp(alice_message["timestamp"])

print(Style.RESET_ALL)
time.sleep(3)

# Alice generates a new message.
new_message = "This is Alice's new message"
new_timestamp = time.time()
new_message_timestamp = f'{new_message} {new_timestamp}'

# Alice hashes the message.
hasher = hashes.Hash(hashes.SHA256())   
hasher.update(new_message_timestamp.encode())
digest = hasher.finalize()

# Alice generates a new signature for the new message.
new_signature = alice_private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

# New message moved to a dictionary.
alice_new_message = {"timestamp": new_timestamp, "message": new_message, "signature": new_signature}

print("Example 3: ") # Message has been modified.
verify_signature(f'{alice_message["timestamp"]} This message has been modified!', alice_new_message["signature"], alice_public_key)
verify_timestamp(alice_new_message["timestamp"])

print(Style.RESET_ALL)

print("Example 4: ") # Timestamp has been modified.
verify_signature(f'1710277196.0713937 {alice_message["message"]}', alice_new_message["signature"], alice_public_key)
verify_timestamp(1710277196.0713937)

print(Style.RESET_ALL)

# Attacker generates their own private-public keys.
attacker_private_key = ec.generate_private_key(ec.SECP256R1())
attacker_public_key = attacker_private_key.public_key()

# Attacker concatenates their message and timestamp.
attacker_message = "This is the attacker's message!"
attacker_timestamp = time.time()
attacker_message_timestamp = f'{str(attacker_timestamp)} {attacker_message}'

# Attacker hashes their message.
hasher = hashes.Hash(hashes.SHA256())   
hasher.update(attacker_message_timestamp.encode())
attacker_digest = hasher.finalize()

# Attacker generates a new signature.
attacker_signature = attacker_private_key.sign(attacker_digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

# Attack message moved to a dictionary.
attacker_message = {"timestamp": attacker_timestamp, "message": attacker_message, "signature": attacker_signature}

print("Example 5: ") # Attacker creates their own signature
verify_signature(f'{attacker_message["timestamp"]} {attacker_message["message"]}', attacker_message["signature"], alice_public_key)
verify_timestamp(attacker_message["timestamp"])

print(Style.RESET_ALL+"\n")





