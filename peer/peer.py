from peer.broadcast import Broadcast
from peer.discovery import Discovery

class Peer:
    # Grab config info from yaml
    def __init__(self, config, identity):
        self.identity = identity
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
                    print("not implemented")

                else:
                    print("Unknown command. Type 'help'.")

            except KeyboardInterrupt:
                print("\nInterrupted. Exiting")
                break
        
