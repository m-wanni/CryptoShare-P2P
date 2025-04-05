import os
import base64
import hashlib
import secrets
import logging
from protocol.json_handler import send_json, recv_json

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

class FileHandler:
    def __init__(self, peer_obj, addr):
        self.peer_obj = peer_obj
        self.addr = addr

    def handle_list_files(self, sock):
        logger.debug(f"Listing files from shared directory: {self.peer_obj.shared_dir}")
        file_dict = {}
        shared_dir = self.peer_obj.shared_dir
        for fname in os.listdir(shared_dir):
            fpath = os.path.join(shared_dir, fname)
            if os.path.isfile(fpath):
                file_dict[fname] = hash_file(fpath)
        logger.debug(f"Sending file list: {file_dict}")
        send_json(sock, {
            "type": "FILE_LIST",
            "files": file_dict
        })

    def handle_file_request(self, sock, msg):
        filename = msg.get("filename")
        logger.debug(f"Received file request for '{filename}' from {self.addr}")
        if not filename:
            logger.error("No filename provided in file request")
            send_json(sock, {"type": "FILE_REQ_RESPONSE", "error": "Missing filename"})
            return

        file_path = os.path.join(self.peer_obj.shared_dir, filename)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            # Ask user for consent to share the file.
            consent = input(f"Peer {self.addr} is requesting '{filename}'. Share file? (yes/no): ")
            if consent.strip().lower() != "yes":
                logger.info("User rejected file transfer request")
                send_json(sock, {"type": "FILE_REQ_RESPONSE", "error": "File transfer rejected by user"})
                return

            with open(file_path, "rb") as f:
                file_data = f.read()
            file_hash = hash_file(file_path)
            logger.debug(f"File '{filename}' read successfully; hash: {file_hash}")

            shared_key = self.peer_obj.shared_keys.get(self.addr)
            if not shared_key:
                logger.error("No shared key found for file transfer")
                send_json(sock, {"type": "FILE_REQ_RESPONSE", "error": "No shared key established"})
                return

            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(shared_key)
            nonce = os.urandom(12)
            encrypted_data = aesgcm.encrypt(nonce, file_data, None)
            logger.debug(f"File '{filename}' encrypted successfully")
            send_json(sock, {
                "type": "FILE_REQ_RESPONSE",
                "nonce": base64.b64encode(nonce).decode(),
                "file_data": base64.b64encode(encrypted_data).decode(),
                "hash": file_hash
            })
        else:
            logger.error(f"File '{filename}' not found in shared directory")
            send_json(sock, {"type": "FILE_REQ_RESPONSE", "error": "File not found"})