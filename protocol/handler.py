import base64
import secrets
import os
import socket
from protocol.json_handler import send_json, recv_json
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
import hashlib
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

def hash_file(filepath):
    with open(filepath, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

class AuthHandler:
    def __init__(self, identity):
        self.identity = identity
        
    def auth_init(self, sock):
        """Initiator side authentication - fixed version"""
        logger.debug("Starting auth_init (initiator side)")
        sock.settimeout(10.0)
    
        try:
            # Step 1: Identity verification phase
            a_pubKey = self.identity.get_public_key_bytes()
            a_challenge = secrets.token_bytes(32)
            logger.debug("Sending AUTH_REQ with public key and challenge")
            send_json(sock, {
                "type": "AUTH_REQ",
                "public_key": base64.b64encode(a_pubKey).decode(),
                "challenge": base64.b64encode(a_challenge).decode()
            })
        
            # Step 2: Wait for responder's verification
            logger.debug("Waiting for AUTH_RESP")
            response = recv_json(sock)
            logger.debug(f"Received AUTH_RESP: {response}")
            if response.get("type") != "AUTH_RESP":
                logger.error(f"Expected AUTH_RESP, got {response.get('type')}")
                return False, None, None
        
            b_pubKey_bytes = base64.b64decode(response["public_key"])
            b_signed_challenge = base64.b64decode(response["signed_challenge"])
            b_challenge = base64.b64decode(response["challenge"])
        
            # Verify the responder's signature
            if not self.identity.verify(b_signed_challenge, a_challenge, b_pubKey_bytes):
                logger.error("Failed to verify peer signature in auth_init")
                return False, None, None
            
            # Step 3: Send our challenge response
            my_signed_peer_challenge = self.identity.sign(b_challenge)
            logger.debug("Sending CHALLENGE_RESPONSE")
            send_json(sock, {
                "type": "CHALLENGE_RESPONSE",
                "signed_challenge": base64.b64encode(my_signed_peer_challenge).decode()
            })
            
            # Step 4: Now initiate DHKE separately (send our ephemeral public key)
            private_key = X25519PrivateKey.generate()
            ephemeral_public_key = private_key.public_key()
            ephemeral_public_bytes = ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            logger.debug("Sending DHKE_INIT")
            send_json(sock, {
                "type": "DHKE_INIT",
                "public_key": base64.b64encode(ephemeral_public_bytes).decode()
            })
            
            # Step 5: Wait for DHKE response
            logger.debug("Waiting for DHKE_RESP")
            dhke_response = recv_json(sock)
            logger.debug(f"Received DHKE_RESP: {dhke_response}")
            if dhke_response.get("type") != "DHKE_RESP":
                logger.error(f"Expected DHKE_RESP, got {dhke_response.get('type')}")
                return False, None, None
            
            # Step 6: Complete DHKE
            peer_ephemeral_bytes = base64.b64decode(dhke_response["public_key"])
            peer_ephemeral_key = X25519PublicKey.from_public_bytes(peer_ephemeral_bytes)
            shared_key = private_key.exchange(peer_ephemeral_key)
            
            # Derive final key using HKDF
            shared_key_hash = hashlib.sha256(shared_key).digest()
            logger.debug("Authentication completed successfully")
            
            return True, b_pubKey_bytes, shared_key_hash
            
        except socket.timeout as e:
            logger.error(f"Socket timeout during auth_init: {e}")
            return False, None, None
        except Exception as e:
            logger.error(f"Exception during auth_init: {e}")
            return False, None, None

    def auth_request(self, sock, auth_req_msg=None):
        """Responder side authentication - fixed version"""
        logger.debug("Starting auth_request (responder side)")
        sock.settimeout(10.0)
        
        try:
            # Step 1: Process the AUTH_REQ (either passed in or wait for it)
            if auth_req_msg:
                request = auth_req_msg
                logger.debug(f"Using already received AUTH_REQ: {request}")
            else:
                logger.debug("Waiting for AUTH_REQ")
                request = recv_json(sock)
                logger.debug(f"Received AUTH_REQ: {request}")
                
            if request.get("type") != "AUTH_REQ":
                logger.error(f"Expected AUTH_REQ, got {request.get('type')}")
                return False, None, None
            
            # Extract initiator's details and continue with the rest of the method...
            peer_pub_key = base64.b64decode(request["public_key"])
            peer_challenge = base64.b64decode(request["challenge"])
            
            # Step 2: Send our response with signed challenge and our own challenge
            my_pub_key = self.identity.get_public_key_bytes()
            signed_peer_challenge = self.identity.sign(peer_challenge)
            my_challenge = secrets.token_bytes(32)
            
            logger.debug("Sending AUTH_RESP")
            send_json(sock, {
                "type": "AUTH_RESP",
                "public_key": base64.b64encode(my_pub_key).decode(),
                "signed_challenge": base64.b64encode(signed_peer_challenge).decode(),
                "challenge": base64.b64encode(my_challenge).decode()
            })
            
            # Step 3: Wait for the initiator's challenge response
            logger.debug("Waiting for CHALLENGE_RESPONSE")
            challenge_resp = recv_json(sock)
            logger.debug(f"Received CHALLENGE_RESPONSE: {challenge_resp}")
            if challenge_resp.get("type") != "CHALLENGE_RESPONSE":
                logger.error(f"Expected CHALLENGE_RESPONSE, got {challenge_resp.get('type')}")
                return False, None, None
            
            # Verify the initiator's signature on our challenge
            peer_signed_challenge = base64.b64decode(challenge_resp["signed_challenge"])
            if not self.identity.verify(peer_signed_challenge, my_challenge, peer_pub_key):
                logger.error("Failed to verify initiator's signature")
                return False, None, None
            
            # Step 4: Wait for DHKE initiation
            logger.debug("Waiting for DHKE_INIT")
            dhke_init = recv_json(sock)
            logger.debug(f"Received DHKE_INIT: {dhke_init}")
            if dhke_init.get("type") != "DHKE_INIT":
                logger.error(f"Expected DHKE_INIT, got {dhke_init.get('type')}")
                return False, None, None
            
            # Step 5: Process DHKE and send our ephemeral key
            peer_ephemeral_bytes = base64.b64decode(dhke_init["public_key"])
            peer_ephemeral_key = X25519PublicKey.from_public_bytes(peer_ephemeral_bytes)
            
            # Generate our ephemeral key pair
            my_ephemeral_private = X25519PrivateKey.generate()
            my_ephemeral_public = my_ephemeral_private.public_key()
            my_ephemeral_bytes = my_ephemeral_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            logger.debug("Sending DHKE_RESP")
            send_json(sock, {
                "type": "DHKE_RESP",
                "public_key": base64.b64encode(my_ephemeral_bytes).decode()
            })
            
            # Step 6: Complete DHKE
            shared_key = my_ephemeral_private.exchange(peer_ephemeral_key)
            
            # Derive final key using HKDF
            shared_key_hash = hashlib.sha256(shared_key).digest()
            logger.debug("Authentication completed successfully")
            
            return True, peer_pub_key, shared_key_hash
            
        except socket.timeout as e:
            logger.error(f"Socket timeout during auth_request: {e}")
            return False, None, None
        except Exception as e:
            logger.error(f"Exception during auth_request: {e}")
            return False, None, None


def handle_incoming_request(sock, addr, identity, peer_obj):
    try:
        msg = recv_json(sock)
        logger.debug(f"Received message from {addr}: {msg}")
        msg_type = msg.get("type")
        if msg_type == "AUTH_REQ":
            auth_handler = AuthHandler(identity)
            # IMPORTANT: Pass the already received message to auth_request
            authenticated, peer_pub_key, shared_key = auth_handler.auth_request(sock, msg)
            return {
                "status": "authenticated" if authenticated else "failed",
                "peer_pub_key": peer_pub_key if authenticated else None,
                "shared_key": shared_key if authenticated else None
            }
        elif msg_type == "LIST_FILES":
            from protocol.file_handler import FileHandler
            file_handler = FileHandler(peer_obj, addr)
            file_handler.handle_list_files(sock)
            return {"status": "list_sent"}
        elif msg_type == "FILE_REQ":
            from protocol.file_handler import FileHandler
            file_handler = FileHandler(peer_obj, addr)
            file_handler.handle_file_request(sock, msg)
            return {"status": "file_sent"}
        elif msg_type == "KEY_MIGRATION":
            new_pub = msg.get("new_public_key")
            if not new_pub:
                send_json(sock, {"error": "Missing new public key"})
                return {"status": "error", "reason": "Missing new public key"}
            peer_obj.authenticated_peer[addr] = base64.b64decode(new_pub)
            logger.debug(f"[✓] Received key migration from {addr}")
            send_json(sock, {"status": "key_updated"})
            return {"status": "key_migrated"}
        else:
            logger.warning(f"Unexpected message type from {addr}: {msg_type}")
            return {"status": "ignored", "reason": f"Unsupported message type: {msg_type}"}
    except Exception as e:
        logger.error(f"Exception handling request from {addr}: {e}")
        return {"status": "error", "reason": str(e)}