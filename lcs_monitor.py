import socket
import threading
import ipaddress
import time
import logging
#import lionel_lcs
import irda_hex_decoder
import train_db
import config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Global variable for Server IP
SERVER_IP = None

def get_wifi_ip():
    """
    Attempts to determine the local WiFi IP by connecting only to local network targets.
    """
    # Use targets from the config map keys (converting CIDR to a likely target IP is hard, 
    # so we'll stick to the hardcoded test targets for now as they seem specific to the environment).
    # Ideally, we would just broadcast or use a known reliable external IP if allowed.
    targets = ["192.168.99.1", "192.168.111.30"]
    for target in targets:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                # Using UDP connect assigns a local IP without sending data.
                s.connect((target, 80))
                local_ip = s.getsockname()[0]
                if local_ip and not local_ip.startswith("127."):
                    logging.info(f"Local IP determined using target: {local_ip}")
                    return local_ip
        except Exception as e:
            logging.debug(f"Error connecting to {target}: {e}")
    
    # Fallback: try to get the IP via hostname resolution.
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        if local_ip and not local_ip.startswith("127."):
            logging.info(f"Local IP determined using gethostname: {local_ip}")
            return local_ip
    except Exception as e:
        logging.error(f"Error using gethostbyname: {e}")
    
    return None

def determine_server():
    """
    Determines the server IP based on the current WiFi IP and the expected networks.
    """
    global SERVER_IP
    local_ip = get_wifi_ip()
    if not local_ip:
        logging.error("Could not determine WiFi IP address.")
        return False

    for network, server_ip in config.NETWORK_SERVER_MAP.items():
        if ipaddress.IPv4Address(local_ip) in ipaddress.IPv4Network(network, strict=False):
            SERVER_IP = server_ip
            logging.info(f"Using server: {SERVER_IP}")
            return True
    
    logging.error("WiFi IP does not belong to expected networks.")
    return False

# Packet counters and connection event
sent_count = 0
recv_count = 0
connection_established = threading.Event()

def process_message(decoded_data, sock):
    global recv_count, sent_count
    recv_count += 1
    
    # Mark connection as established on first received packet.
    if not connection_established.is_set():
        connection_established.set()

    if decoded_data == config.PING_PACKET:
        sent_count += 1
        try:
            sock.sendall(config.PING_PACKET.encode('utf-8'))
        except socket.error as e:
            logging.error(f"Error sending PING reply: {e}")
    else:
        logging.info(f"[R:{recv_count}] Received: {decoded_data}")

    # If characters 3-4 equal "32", process the packet further.
    # Checks index 2 and 3 (0-based) which are the 3rd and 4th chars.
    if len(decoded_data) >= 4 and decoded_data[2:4] == "32":
        logging.info("IDRA packet detected")
        try:
            decoded = irda_hex_decoder.irda_decode_packet(decoded_data)
            logging.info("Decoded Packet:")
            for key, value in decoded.items():
                logging.info(f"{key}: {value}")
            
            # Use .get() to avoid KeyErrors if decoding fails partly
            train_db.insert_train_passage(
                decoded.get('irda_tmcc'),
                decoded.get('direction'),
                decoded.get('engine_name'),
                decoded.get('road_number')
            )
        except Exception as e:
            logging.error(f"Error processing IDRA packet: {e}")

def receive_data(sock):
    """
    Continuously receive data. Handles TCP buffering by splitting on 'DF'.
    """
    buffer = ""
    try:
        while True:
            data = sock.recv(config.PDI_RX_PKTSIZE)
            if not data:
                break
            
            # Append new data to buffer
            buffer += data.decode('utf-8', errors='replace')
            
            # Process complete messages ending in 'DF'
            # Note: config.EOP is 0xDF (int), but protocol strings seem to use "DF"
            while "DF" in buffer:
                # Split at the first "DF"
                # We want to include "DF" in the message we process
                segment, buffer = buffer.split("DF", 1)
                message = segment + "DF"
                
                # Check if it starts with 'D1' (SOP) just to be safe/clean?
                # The existing code didn't check SOP explicitly every time but let's assume valid framing for now.
                process_message(message, sock)
                
    except socket.error as e:
        logging.error(f"Socket error: {e}")
    finally:
        logging.info("Receiver thread terminating...")

def main():
    global sent_count

    # Determine which server to use.
    if not determine_server():
        logging.critical("Terminating due to server determination failure.")
        return

    if SERVER_IP is None:
        logging.critical("SERVER_IP is not set. Exiting.")
        return

    # Create a socket and attempt to connect.
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # Timeout for connection attempts.
        sock.connect((SERVER_IP, config.SERVER_PORT))
        logging.info(f"Connected to {SERVER_IP}:{config.SERVER_PORT}")
    except socket.error as e:
        logging.critical(f"Failed to connect: {e}")
        return
    
    # Start a thread to handle incoming data.
    receive_thread = threading.Thread(target=receive_data, args=(sock,), daemon=True)
    receive_thread.start()
    
    logging.info("Waiting for initial packet to confirm connection...")
    if connection_established.wait(timeout=30): # Wait with timeout
        # Send WIFI CONNECT command.
        sent_count += 1
        logging.info(f"[S:{sent_count}] Sending WIFI CONNECT: {config.WIFI_CONNECT}")
        try:
            sock.sendall(config.WIFI_CONNECT.encode('utf-8'))
        except socket.error as e:
            logging.error(f"Error sending WIFI CONNECT: {e}")
    else:
        logging.warning("Timed out waiting for initial packet.")

    try:
        while receive_thread.is_alive():
            time.sleep(1)  # Efficient wait
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    finally:
        if sock:
            sock.close()
        logging.info("Socket closed.")

if __name__ == "__main__":
    main()
