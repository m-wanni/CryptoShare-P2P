import base64
import secrets
from protocol.json_handler import send_json, recv_json


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

    return True, b_pubKey_bytes

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
    
    return True, b_pub_key



