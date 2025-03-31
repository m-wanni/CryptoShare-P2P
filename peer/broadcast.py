from zeroconf import ServiceInfo, Zeroconf
import socket

class Broadcast():
    def __init__(self,peer_name, port):
        self.peer_name  = peer_name
        self.port = port
        self.zeroconf = Zeroconf()
        self.SERVICE_TYPE = "_p2pfileshare._tcp.local."

    #Starts zeroconf Mdns, broadcasting peers presence 
    def start_service(self):
        hostname = socket.gethostname()
        ip_addr = socket.gethostbyname(hostname)

        self.service_info = ServiceInfo(
            type_=self.SERVICE_TYPE,
            name=f"{self.peer_name}.{self.SERVICE_TYPE}",
            addresses=[socket.inet_aton(ip_addr)],
            port=self.port,
            properties={}, 
            server=f"{hostname}.local.",
        )

        print(f"Broadcasting at {self.peer_name}:{self.port}")

        self.zeroconf.register_service(self.service_info)

    def stop_service(self):
        if self.service_info:
            self.zeroconf.unregister_service(self.service_info)
        self.zeroconf.close()
        
    