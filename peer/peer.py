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

        
