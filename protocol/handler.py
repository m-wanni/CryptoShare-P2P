import base64
import secrets
from protocol.json_handler import send_json, recv_json
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization


def auth_init(socket, identity):
    # generate and send our challenge + public key to verify peer
    a_pubKey = identity.get_public_key_bytes()
    a_challenge = secrets.token_bytes(32)

    send_json(socket, {
        "type": "AUTH_REQ",
        "public_key": base64.b64encode(a_pubKey).decode(),
        "challenge": base64.b64encode(a_challenge).decode()
    })

    # receive peer's signed response, peer signs our challenge with their private key
    response = recv_json(socket)
    if response.get("type") != "AUTH_RESP":
        print("Invalid response type.")
        return False, None

    b_pubKey_bytes = base64.b64decode(response["public_key"])
    b_signed_challenge = base64.b64decode(response["signed_challenge"])
    b_challenge = base64.b64decode(response["challenge"])

    # verify the peer signed our challenge correctly
    if not identity.verify(b_signed_challenge, a_challenge, b_pubKey_bytes):
        print("Failed to verify peer signature.")
        return False, None

    # sign their challenge and send back verifying you own associated private key to public key
    my_signed_peer_challenge = identity.sign(b_challenge)
    send_json(socket, {
        "type": "CHALLENGE_RESPONSE",
        "signed_challenge": base64.b64encode(my_signed_peer_challenge).decode()
    })
    sharedKey = dhke_init(socket)
    return True, b_pubKey_bytes, sharedKey

def auth_request(socket, identity):
    request = recv_json(socket)
    if request.get("type") != "AUTH_REQ":
        return False, None
    try:
        b_pub_key = base64.b64decode(request["public_key"])
        b_challenge = base64.b64decode(request["challenge"])
    except Exception as e:
        print(f"Failed to decode AUTH_REQ: {e}")
        return False, None
    
    # Step 2: Sign the initiator's challenge
    signed_peer_challenge = identity.sign(b_challenge)
    a_challenge = secrets.token_bytes(32)
    a_pub_key = identity.get_public_key_bytes()

    send_json(socket, {
        "type": "AUTH_RESP",
        "public_key": base64.b64encode(a_pub_key).decode(),
        "signed_challenge": base64.b64encode(signed_peer_challenge).decode(),
        "challenge": base64.b64encode(a_challenge).decode()
    })

    response = recv_json(socket)
    if response.get("type") != "CHALLENGE_RESPONSE":
        print("Invalid challenge response.")
        return False, None

    try:
        a_signed_challenge = base64.b64decode(response["signed_challenge"])
    except Exception as e:
        print("Failed to decode challenge response")
        return False, None
    
    if not identity.verify(a_signed_challenge, a_challenge, b_pub_key):
        print("Failed to verify initiator's signature.")
        return False, None  
    shared_key = dhke_response(socket)
    return True, b_pub_key, shared_key

def dhke_init(socket):
    """
    Initiator side of Diffie-Hellman key exchange using X25519.
    Generates an ephemeral key, sends its public key to the responder,
    receives the responder's public key, and computes the shared secret.
    """
    try:
        # Generate our ephemeral private key
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        # Send our public key
        send_json(socket, {
            "type": "DHKE_INIT",
            "public_key": base64.b64encode(public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode()
        })
        # Receive the responder's public key
        response = recv_json(socket)
        if response.get("type") != "DHKE_RESP":
            print("Invalid DHKE response type.")
            return None
        peer_pub_bytes = base64.b64decode(response["public_key"])
        peer_public_key = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        # Compute the shared key
        shared_key = private_key.exchange(peer_public_key)
        return shared_key
    except Exception as e:
        print(f"DHKE init error: {e}")
        return None

def dhke_response(socket):
    """
    Responder side of Diffie-Hellman key exchange using X25519.
    Receives the initiator's public key, generates its own ephemeral key,
    sends back its public key, and computes the shared secret.
    """
    try:
        # Receive the initiator's public key
        request = recv_json(socket)
        if request.get("type") != "DHKE_INIT":
            print("Invalid DHKE init message.")
            return None
        peer_pub_bytes = base64.b64decode(request["public_key"])
        peer_public_key = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        # Generate our ephemeral private key
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        # Send our public key back to the initiator
        send_json(socket, {
            "type": "DHKE_RESP",
            "public_key": base64.b64encode(public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode()
        })
        # Compute the shared key
        shared_key = private_key.exchange(peer_public_key)
        return shared_key
    except Exception as e:
        print(f"DHKE response error: {e}")
        return None