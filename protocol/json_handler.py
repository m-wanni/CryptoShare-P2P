import json

def send_json(sock, obj):
    """
    Serialize and send a JSON object over a socket, ending with a newline.
    """
    message = json.dumps(obj) + '\n'  # newline as delimiter
    sock.sendall(message.encode('utf-8'))

def recv_json(sock):
    """
    Receive JSON data from a socket (expects newline-delimited JSON).
    """
    sock.settimeout(10) 
    buffer = b""
    while b'\n' not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Socket closed while receiving data.")
        buffer += chunk

    message = buffer.split(b'\n', 1)[0]
    return json.loads(message.decode('utf-8'))
