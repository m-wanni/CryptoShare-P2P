from peer.broadcast import Broadcast
from peer.discovery import Discovery
from protocol.handler import handle_incoming_request, AuthHandler
from protocol.json_handler import send_json, recv_json
import socket
import threading
import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging

# Set up module-level logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

class Peer:
    def __init__(self, config, identity):
        self.identity = identity
        self.authenticated_peer = {}  # {(ip, port): peer_public_key}
        self.shared_keys = {}         # {(ip, port): shared_key}
        self.peer_file_index = {} 
        self.peer_name = config["peer_name"]
        self.key_path = config["key_path"]
        self.port = config["listen_port"]
        self.shared_dir = config["shared_dir"]
        self.download_dir = config["download_dir"]
        self.metadata_cache = config["metadata_cache"]
        self.discovery_timeout = config["discovery_timeout"]

        self.broadcast = Broadcast(self.peer_name, self.port)
        self.discovery = Discovery(self.discovery_timeout)
        # Load or generate a local encryption key for secure file storage.
        self.local_enc_key = self.load_local_enc_key()
        logger.debug(f"Peer '{self.peer_name}' initialized on port {self.port}")

    def load_local_enc_key(self):
        key_file = os.path.join(os.path.dirname(self.key_path), "local_enc_key.bin")
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                key = f.read()
                logger.debug("Loaded local encryption key")
                return key
        else:
            new_key = AESGCM.generate_key(bit_length=128)
            with open(key_file, "wb") as f:
                f.write(new_key)
            logger.debug("Generated and saved new local encryption key")
            return new_key

    def start_service(self):
        logger.debug("Starting broadcast and discovery services")
        self.broadcast.start_service()
        self.discovery.start_service()
        threading.Thread(target=self.listen_for_messages, daemon=True).start()
        logger.debug("Starting CLI")
        self.run_cli()

    def run_cli(self):  
        while True:
            try:
                cmd = input(">>> ").strip()
                if cmd == "exit":
                    logger.debug("Exiting CLI")
                    print("Exiting")
                    break
                elif cmd == "help":
                    print("Commands:\n  list                   List discovered peers\n  auth <peer>            Authenticate with a peer\n  filelist <peer>        Request file list from a peer\n  getfile <peer> <file>  Request a file from a peer\n  migrate                Migrate to a new key\n  exit                   Quit")
                elif cmd == "list":
                    peers = self.discovery.get_peers()
                    if not peers:
                        print("No peers found.")
                    for name, (ip, port) in peers.items():
                        print(f"{name} @ {ip}:{port}")
                elif cmd.startswith("filelist "):
                    parts = cmd.split()
                    if len(parts) != 2:
                        print("Usage: filelist <peer_name>")
                        continue
                    peer_name = parts[1]
                    try:
                        ip, port = self.discovery.get_peers()[peer_name]
                        sock = socket.create_connection((ip, port))
                        logger.debug(f"Requesting file list from {peer_name} at {ip}:{port}")
                        send_json(sock, {"type": "LIST_FILES"})
                        response = recv_json(sock)
                        if response.get("type") == "FILE_LIST":
                            self.peer_file_index[(ip, port)] = response["files"]
                            print(f"[✓] Files from {peer_name}:")
                            for fname, fhash in response["files"].items():
                                print(f" - {fname}  [{fhash[:8]}...]")
                        else:
                            print("[✗] Failed to receive file list.")
                    except Exception as e:
                        logger.error(f"Error during filelist: {e}")
                        print(f"[!] Error: {e}")
                    finally:
                        if 'sock' in locals():
                            sock.close()
                elif cmd.startswith("getfile "):
                    parts = cmd.split()
                    if len(parts) != 3:
                        print("Usage: getfile <peer_name> <filename>")
                        continue
                    peer_name = parts[1]
                    filename = parts[2]
                    try:
                        ip, port = self.discovery.get_peers()[peer_name]
                        sock = socket.create_connection((ip, port))
                        logger.debug(f"Requesting file '{filename}' from {peer_name} at {ip}:{port}")
                        send_json(sock, {"type": "FILE_REQ", "filename": filename})
                        response = recv_json(sock)
                        if response.get("type") == "FILE_REQ_RESPONSE":
                            if "error" in response:
                                print(f"[✗] Error from {peer_name}: {response['error']}")
                                logger.error(f"File request error from {peer_name}: {response['error']}")
                            else:
                                shared_key = self.shared_keys.get((ip, port))
                                if not shared_key:
                                    print("No shared key established with peer. Please authenticate first.")
                                    logger.error("Missing shared key for file transfer")
                                    continue
                                nonce = base64.b64decode(response["nonce"])
                                encrypted_data = base64.b64decode(response["file_data"])
                                aesgcm = AESGCM(shared_key)
                                decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
                                computed_hash = hashlib.sha256(decrypted_data).hexdigest()
                                file_hash = response.get("hash")
                                if computed_hash != file_hash:
                                    print("[✗] Hash mismatch: file may be corrupted.")
                                    logger.error("Hash mismatch during file transfer")
                                else:
                                    local_aesgcm = AESGCM(self.local_enc_key)
                                    local_nonce = os.urandom(12)
                                    encrypted_local = local_aesgcm.encrypt(local_nonce, decrypted_data, None)
                                    filepath = os.path.join(self.download_dir, filename)
                                    with open(filepath, "wb") as f:
                                        f.write(local_nonce + encrypted_local)
                                    self.peer_file_index[(ip, port)] = {filename: file_hash}
                                    print(f"[✓] Downloaded and securely stored '{filename}' from {peer_name}")
                                    logger.debug(f"File '{filename}' successfully downloaded and stored")
                        else:
                            print("[✗] Failed to get file.")
                            logger.error("File request did not return expected response")
                    except Exception as e:
                        logger.error(f"Error during getfile: {e}")
                        print(f"[!] Error: {e}")
                    finally:
                        if 'sock' in locals():
                            sock.close()
                elif cmd.startswith("auth "):
                    parts = cmd.split()
                    if len(parts) == 2:
                        logger.debug(f"Initiating authentication with peer: {parts[1]}")
                        self.initiate_authentication(parts[1])
                    else:
                        print("Usage: auth <peer_name>")
                elif cmd == "migrate":
                    self.migrate_key()
                else:
                    print("Unknown command. Type 'help'.")
            except KeyboardInterrupt:
                logger.debug("CLI interrupted by user")
                print("\nInterrupted. Exiting")
                break

    def listen_for_messages(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', self.port))
        sock.listen()
        logger.debug(f"Listening for incoming messages on port {self.port}")
        while True:
            conn, addr = sock.accept()
            logger.debug(f"Accepted connection from {addr}")
            threading.Thread(target=self.handle_req, args=(conn, addr)).start()

    def handle_req(self, conn, addr):
        try:
            logger.debug(f"Handling incoming request from {addr}")
            result = handle_incoming_request(conn, addr, self.identity, self)
            if result["status"] == "authenticated":
                self.authenticated_peer[addr] = result["peer_pub_key"]
                self.shared_keys[addr] = result["shared_key"]
                print(f"[✓] Authenticated peer from {addr}")
                logger.debug(f"Authenticated peer from {addr}")
            elif result["status"] == "failed":
                print(f"[✗] Failed to authenticate peer from {addr}")
                logger.error(f"Failed to authenticate peer from {addr}")
            elif result["status"] == "ignored":
                print(f"[!] Ignored non-auth message from {addr}")
                logger.warning(f"Ignored message from {addr}: {result.get('reason')}")
            elif result["status"] == "key_migrated":
                print(f"[✓] Key migration processed for peer {addr}")
                logger.debug(f"Key migration processed for peer {addr}")
            else:
                print(f"[!] Error during request from {addr}: {result.get('reason')}")
                logger.error(f"Error during request from {addr}: {result.get('reason')}")
        finally:
            conn.close()

    def initiate_authentication(self, peer):
        try:
            ip, port = self.discovery.get_peers()[peer]
            logger.debug(f"Found peer {peer} at {ip}:{port}")
        except KeyError:
            print(f"[!] Peer '{peer}' not found.")
            logger.error(f"Peer '{peer}' not found in discovery")
            return
        try:
            sock = socket.create_connection((ip, port))
            logger.debug(f"Connected to peer {peer} at {ip}:{port}")
            auth_handler = AuthHandler(self.identity)
            authenticated, peer_public_key, shared_key = auth_handler.auth_init(sock)
            if authenticated:
                print(f"[✓] Authenticated {peer} at {ip}:{port}")
                logger.debug(f"Authenticated {peer} at {ip}:{port}")
                self.authenticated_peer[(ip, port)] = peer_public_key
                self.shared_keys[(ip, port)] = shared_key
            else:
                print(f"[✗] Failed to authenticate {peer}")
                logger.error(f"Failed to authenticate {peer}")
        except (ConnectionRefusedError, TimeoutError) as e:
            logger.error(f"Could not connect to {peer} at {ip}:{port} — {e}")
            print(f"Could not connect to {peer} at {ip}:{port} — {e}")
        finally:
            if 'sock' in locals():
                sock.close()

    def migrate_key(self):
        logger.debug("Initiating key migration")
        self.identity.migrate()
        new_pub = base64.b64encode(self.identity.get_public_key_bytes()).decode()
        for (ip, port) in list(self.authenticated_peer.keys()):
            try:
                sock = socket.create_connection((ip, port))
                logger.debug(f"Notifying peer at {ip}:{port} about key migration")
                send_json(sock, {"type": "KEY_MIGRATION", "new_public_key": new_pub})
                response = recv_json(sock)
                if response.get("status") == "key_updated":
                    print(f"[✓] Notified peer at {ip}:{port} about key migration.")
                    logger.debug(f"Peer at {ip}:{port} updated key successfully")
                else:
                    print(f"[!] Peer at {ip}:{port} did not confirm key migration.")
                    logger.error(f"Peer at {ip}:{port} did not confirm key migration")
            except Exception as e:
                logger.error(f"Could not notify peer at {ip}:{port}: {e}")
                print(f"[!] Could not notify peer at {ip}:{port}: {e}")
            finally:
                if 'sock' in locals():
                    sock.close()