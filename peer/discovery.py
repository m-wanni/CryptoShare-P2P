from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
import socket

SERVICE_TYPE = "_p2pfileshare._tcp.local."

class DiscoveryListener(ServiceListener):
    def __init__(self):
        self.peers = {}

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            port = info.port
            ip = socket.inet_ntoa(info.addresses[0])
            peer_name = name.split('.')[0]
            self.peers[peer_name] = (ip, port)
            print(f"Found peer: {peer_name} at {ip}:{port}")

    def remove_service(self, zeroconf, type, name):
        peer_name = name.split('.')[0]
        if peer_name in self.peers:
            del self.peers[peer_name]
            print(f"Peer left: {peer_name}")

class Discovery:
    def __init__(self):
        self.zeroconf = Zeroconf()
        self.peer_listener = DiscoveryListener()
        self.browser = None

    def start_service(self):
        #watches local network for peers 
        self.browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, self.peer_listener)
        print("Discovery started...")

    def get_peers(self):
        return self.listener.peers

    def stop(self):
        self.zeroconf.close()