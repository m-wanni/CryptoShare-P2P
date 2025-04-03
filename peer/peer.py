from peer.broadcast import Broadcast
from peer.discovery import Discovery
from protocol.handler import auth_init
from protocol.handler import auth_request
import socket
import threading

class Peer:
    # Grab config info from yaml
    def __init__(self, config, identity):
        self.identity = identity
        self.authenticated_peers = {}
        self.peer_name = config["peer_name"]
        self.key_path = config["key_path"]
        self.port = config["listen_port"]
        self.shared_dir = config["shared_dir"]
        self.download_dir = config["download_dir"]
        self.metadata_cache = config["metadata_cache"]
        self.discovery_timeout = config["discovery_timeout"]

        self.broadcast = Broadcast(self.peer_name, self.port)
        self.discovery = Discovery(self.discovery_timeout)
     
    def start_service(self):
        self.broadcast.start_service()
        self.discovery.start_service()
        threading.Thread(target=self.listen_for_auth_connections, daemon=True).start()
        
        self.run_cli()

    def run_cli(self):  
        while True:
            try:
                cmd = input(">>> ").strip()
                if cmd == "exit":
                    print("Exiting")
                    break

                elif cmd == "help":
                    print("Commands:\n  list           List discovered peers\n  auth <peer>    Authenticate with a peer\n  exit           Quit")

                elif cmd == "list":
                    peers = self.discovery.get_peers()
                    if not peers:
                        print("No peers found.")
                    for name, (ip, port) in peers.items():
                        print(f"{name} @ {ip}:{port}")

                elif cmd.startswith("auth "):
                    parts = cmd.split()
                    if len(parts) == 2:
                        self.initiate_authentication(parts[1])
                    else:
                        print("Usage: auth <peer_name>")
            
                else:
                    print("Unknown command. Type 'help'.")

            except KeyboardInterrupt:
                print("\nInterrupted. Exiting")
                break

    def listen_for_auth_connections(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', self.port))
        sock.listen()

        while True:
            conn, addr = sock.accept()
            threading.Thread(target=self.handle_auth_req, args=(conn, addr)).start()

    def handle_auth_req(self, conn, addr):
        try:
            authenticated, peer_pub_key = auth_request(conn, self.identity)
            if authenticated:
                print(f"[✓] Authenticated peer from {addr}")
                self.authenticated_peers[addr] = peer_pub_key
            else:
                print(f"[✗] Failed to authenticate peer from {addr}")
            conn.close()
        except Exception as e:
            print(f"[!] Error during auth with {addr}: {e}")
        conn.close()


    def initiate_authentication(self, peer):
        try:
            ip, port = self.discovery.get_peers()[peer]
        except KeyError:
            print(f"[!] Peer '{peer}' not found.")
            return
        try:
            sock = socket.create_connection((ip, port))
            authenticated, peer_public_key = auth_init(sock, self.identity)
        except (ConnectionRefusedError, TimeoutError) as e:
            print(f"Could not connect to {peer} at {ip}:{port} — {e}")
        finally:
            if 'sock' in locals():
                sock.close()

