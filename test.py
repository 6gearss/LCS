import socket
import threading
import ipaddress
#import lionel_lcs
import irda_hex_decoder

# Command constants
BASE_RECORD_READ = "D1230002DBDF"
WIFI_CONNECT = "D13481014ADF"
PING_PACKET = "D129D7DF"

# Packet sizes and markers
PDI_RX_PKTSIZE = 1024
PDI_TX_PKTSIZE = 4096
SOP = 0xD1
EOP = 0xDF
STF = 0xDE

# Define servers and their expected networks
SERVER_PORT = 50001
SERVERS = {
    "192.168.99.0/24": "192.168.99.1",
    "192.168.111.0/24": "192.168.111.30"
}

SERVER_IP = None  # Will be set after determining network

def get_wifi_ip():
    """
    Attempts to determine the local WiFi IP by connecting only to local network targets.
    Since there is no internet connection, we only try known local addresses.
    """
    # Only local targets now—remove any external IPs
    targets = ["192.168.99.1", "192.168.111.30"]
    for target in targets:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                # Using UDP connect assigns a local IP without sending data.
                s.connect((target, 80))
                local_ip = s.getsockname()[0]
                if local_ip and not local_ip.startswith("127."):
                    print(f"Local IP determined using target {target}: {local_ip}")
                    return local_ip
        except Exception as e:
            print(f"Error connecting to {target}: {e}")
    
    # Fallback: try to get the IP via hostname resolution.
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        if local_ip and not local_ip.startswith("127."):
            print(f"Local IP determined using gethostname: {local_ip}")
            return local_ip
        else:
            raise Exception("Hostname returned a loopback address.")
    except Exception as e:
        print(f"Error using gethostbyname: {e}")
    
    return None

def determine_server():
    """
    Determines the server IP based on the current WiFi IP and the expected networks.
    """
    global SERVER_IP
    local_ip = get_wifi_ip()
    if not local_ip:
        print("Could not determine WiFi IP address.")
        return False

    for network, server_ip in SERVERS.items():
        if ipaddress.IPv4Address(local_ip) in ipaddress.IPv4Network(network, strict=False):
            SERVER_IP = server_ip
            print(f"Using server: {SERVER_IP}")
            return True
    
    print("Error: WiFi IP does not belong to expected networks.")
    return False

# Packet counters and connection event
sent_count = 0
recv_count = 0
connection_established = threading.Event()

def receive_data(sock):
    """
    Continuously receive data. If a PING_PACKET is received, reply with a PING.
    Also, decode packets if a special identifier is detected.
    """
    global recv_count, sent_count
    try:
        while True:
            data = sock.recv(PDI_RX_PKTSIZE)
            if not data:
                break
            
            decoded_data = data.decode('utf-8', errors='replace')
            recv_count += 1
            
            # Mark connection as established on first received packet.
            connection_established.set()

            if decoded_data == PING_PACKET:
                sent_count += 1
                sock.sendall(PING_PACKET.encode('utf-8'))
            else:
                print(f"[R:{recv_count}] Received: {decoded_data}")

            # If characters 3-4 equal "32", process the packet further.
            if decoded_data[2:4] == "32":
                print("IDRA")
                decoded = irda_hex_decoder.irda_decode_packet(decoded_data)
                print("Decoded Packet:")
                for key, value in decoded.items():
                    print(f"{key}: {value}")

    except socket.error as e:
        print(f"Socket error: {e}")
    finally:
        print("Receiver thread terminating...")

def main():
    global sent_count

    # Determine which server to use.
    if not determine_server():
        print("Terminating due to server determination failure.")
        return

    if SERVER_IP is None:
        print("SERVER_IP is not set. Exiting.")
        return

    # Create a socket and attempt to connect.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # Timeout for connection attempts.
        sock.connect((SERVER_IP, SERVER_PORT))
        print(f"Connected to {SERVER_IP}:{SERVER_PORT}")
    except socket.error as e:
        print(f"Failed to connect: {e}")
        return
    
    # Start a thread to handle incoming data.
    receive_thread = threading.Thread(target=receive_data, args=(sock,), daemon=True)
    receive_thread.start()
    
    print("Waiting for initial packet to confirm connection...")
    connection_established.wait()  # Wait until at least one packet is received.
    
    # Send WIFI CONNECT command.
    sent_count += 1
    print(f"[S:{sent_count}] Sending WIFI CONNECT: {WIFI_CONNECT}")
    sock.sendall(WIFI_CONNECT.encode('utf-8'))
    
    try:
        while True:
            pass  # Keep the main thread active.
    except KeyboardInterrupt:
        print("Shutting down...")
    except socket.error as e:
        print(f"Socket error during sending: {e}")
    finally:
        sock.close()
        print("Socket closed.")

if __name__ == "__main__":
    main()
