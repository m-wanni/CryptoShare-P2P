#main.py  ==  full-featured P2P client
           #↳ announces itself
           #↳ discovers others
           #↳ accepts connections
           #↳ makes connections
           #↳ handles secure messaging
           #↳ acts on user input
'''p2pshare/
├── main.py                     # Entry point to launch the peer
├── config.py                  # Configuration constants (ports, protocol settings, etc.)
├── peer/
│   ├── __init__.py
│   ├── peer.py                # Peer class: handles core logic
│   ├── discovery.py    # mDNS discovery using zeroconf
│   ├── broadcast.py    # mDNS broadcast using zeroconf
│   ├── file_store.py   # Manages shared/received files
│   └── transfer.py            # Handles sending/receiving files
│
├── crypto/
│   ├── __init__.py
│   ├── identity.py            # Persistent keypair, key migration, fingerprinting
│   ├── session.py             # Ephemeral key exchange, PFS, session key handling
│   ├── encrypt.py             # AES-GCM encryption/decryption
│   └── integrity.py           # Hashing, signing, verification
│
├── protocol/
│   ├── __init__.py
│   ├── message.py             # JSON or Protobuf message structures
│   ├── handler.py             # Protocol dispatcher (e.g., FILE_REQUEST, LIST_RESPONSE)
│   └── errors.py              # Custom exceptions & error messaging
│
├── storage/
│   ├── __init__.pys
│   ├── secure_store.py        # Secure file storage encrypted at rest
│   └── metadata_cache.py      # Tracks file hashes, known peers, trust relationships
│
├── utils/
│   ├── __init__.py
│   └── helpers.py             # Misc. functions (e.g., chunking, formatting)
│
│
'''

from peer.peer import Peer
from crypto.identity import Identity
from config import load_config
def main():
    config = load_config("config.yaml")
    identity = Identity(config["key_path"])
    peer = Peer(config, identity)
    peer.start_service()
    peer.run_cli()
    #peer.run_cli()
    #peer.shutdown()

if __name__ == "__main__":
    main()
