import socket
import ipaddress

# Define servers and their expected networks
SERVERS = {
    "192.168.99.0/24": "192.168.99.1",
    "192.168.111.0/24": "192.168.111.30"
}

SERVER_IP = None  # Variable to store the selected server IP

def get_wifi_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.168.99.1", 1))  # Attempting to connect without sending data
            return s.getsockname()[0]
    except Exception as e:
        print(f"Error retrieving WiFi IP: {e}")
        return None

def determine_server():
    global SERVER_IP
    local_ip = get_wifi_ip()
    if not local_ip:
        print("Could not determine WiFi IP address.")
        return

    for network, server_ip in SERVERS.items():
        if ipaddress.IPv4Address(local_ip) in ipaddress.IPv4Network(network, strict=False):
            SERVER_IP = server_ip
            print(f"Using server: {SERVER_IP}")
            return
    
    print("Error: WiFi IP does not belong to expected networks.")

if __name__ == "__main__":
    determine_server()