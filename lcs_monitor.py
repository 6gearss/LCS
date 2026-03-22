import socket
import threading
import ipaddress
import time
import logging
import json
import atexit
import paho.mqtt.client as mqtt

#import lionel_lcs
import irda_hex_decoder
import train_db
import config
import engine_decoder


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    # format='%(asctime)s - %(levelname)s - %(message)s'
    format='%(message)s'
)

# Global variable for Server IP
SERVER_IP = None

# MQTT Client
mqtt_client = None

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
waiting_for_config_reply = False

def setup_mqtt():
    """
    Initialize and connect to the MQTT broker.
    Sets up a Last Will and Testament message for graceful disconnection handling.
    """
    global mqtt_client
    
    def on_connect(client, userdata, flags, rc, properties=None):
        if rc == 0:
            logging.info(f"Connected to MQTT broker at {config.MQTT_BROKER}:{config.MQTT_PORT}")
            # Publish service UP status
            publish_status("UP")
        else:
            logging.error(f"Failed to connect to MQTT broker, return code {rc}")
    
    def on_disconnect(client, userdata, flags, rc, properties=None):
        logging.info("Disconnected from MQTT broker")
        if rc != 0:
            logging.warning(f"Unexpected disconnection. Return code: {rc}")
    
    try:
        # Use VERSION2 to avoid DeprecationWarning
        mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="lcs_monitor", clean_session=True)
        mqtt_client.on_connect = on_connect
        mqtt_client.on_disconnect = on_disconnect
        
        # Set Last Will and Testament - published if connection is lost ungracefully
        mqtt_client.will_set(config.MQTT_TOPIC_STATUS, "DOWN", qos=1, retain=True)
        
        mqtt_client.connect(config.MQTT_BROKER, config.MQTT_PORT, keepalive=60)
        mqtt_client.loop_start()  # Start background thread for MQTT
        
        return True
    except Exception as e:
        logging.error(f"Failed to setup MQTT: {e}")
        return False

def publish_status(status):
    """
    Publish service status to MQTT.
    
    Args:
        status (str): Either 'UP' or 'DOWN'
    """
    if mqtt_client and mqtt_client.is_connected():
        # Publish simple status value (just the word)
        mqtt_client.publish(config.MQTT_TOPIC_STATUS, status.upper(), qos=1, retain=True)
        logging.info(f"Published service status: {status.upper()}")
    else:
        logging.warning(f"Cannot publish service status '{status}' - client not connected")

def publish_irda_status(status, error_msg=None):
    """
    Publish LCS Base connection status to MQTT.
    
    Args:
        status (str): 'CONNECTED', 'DISCONNECTED', or 'ERROR'
        error_msg (str): Optional error message
    """
    if mqtt_client and mqtt_client.is_connected():
        # Publish simple status value (just the word)
        mqtt_client.publish(config.MQTT_TOPIC_IRDA_STATUS, status.upper(), qos=1, retain=True)
        
        # Publish base IP to separate topic
        if SERVER_IP:
            mqtt_client.publish(config.MQTT_TOPIC_BASE_IP, SERVER_IP, qos=1, retain=True)
        
        # If there's an error message, publish it to a data topic
        if error_msg:
            mqtt_client.publish(f"{config.MQTT_TOPIC_IRDA_STATUS}/error", error_msg, qos=1, retain=False)
        
        logging.info(f"Published base status: {status.upper()}")
    else:
        logging.warning(f"Cannot publish base status '{status}' - MQTT not connected")

def cleanup_mqtt():
    """
    Gracefully disconnect from MQTT broker and publish down status.
    """
    global mqtt_client
    if mqtt_client:
        try:
            publish_status("DOWN")
            time.sleep(0.5)  # Give time for message to be sent
            mqtt_client.loop_stop()
            mqtt_client.disconnect()
            logging.info("MQTT client disconnected")
        except Exception as e:
            logging.error(f"Error during MQTT cleanup: {e}")

def process_message(decoded_data, sock):
    global recv_count, sent_count, waiting_for_config_reply
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

        if waiting_for_config_reply:
            waiting_for_config_reply = False
            sent_count += 1
            logging.info(f"[S:{sent_count}] Sending GET All Status: {config.GET_ALL_STATUS}")
            try:
                sock.sendall(config.GET_ALL_STATUS.encode('utf-8'))
            except socket.error as e:
                logging.error(f"Error sending GET All Status: {e}")

    # If characters 3-4 equal "32", this is an IRDA REQ/RESP packet
    # Checks index 2 and 3 (0-based) which are the 3rd and 4th chars.
    if len(decoded_data) >= 4 and decoded_data[2:4] == "32":
        try:
            # Decode the packet natively with our newly enhanced IRDA decoder
            irda_decoded = irda_hex_decoder.irda_decode_packet(decoded_data)
            
            if irda_decoded:
                tmcc = irda_decoded.get('irda_tmcc', 'N/A')
                name = irda_decoded.get('engine_name', 'Unknown Engine')
                road = irda_decoded.get('road_number', 'Unknown')
                
                logging.info(f"=== IRDA Engine Record #{tmcc} ===")
                logging.info(f"  {name} #{road}")
                
                # We can safely extract prod mapping fields because they are properly indexed
                p_id = irda_decoded.get('prod_id', 'Unknown')
                p_rev = irda_decoded.get('prod_rev', 'Unknown')
                eng_id = irda_decoded.get('engine_id', 'Unknown')
                train_id = irda_decoded.get('train_id', 'Unknown')
                
                logging.info(f"  Type: {p_id} ({p_rev}) | Engine ID: {eng_id} | Train ID: {train_id}")
                
                fuel = irda_decoded.get('fuel_pct', 'N/A')
                water = irda_decoded.get('water_pct', 'N/A')
                logging.info(f"  Fuel: {fuel}% | Water: {water}%")
                
                dir_txt = irda_decoded.get('direction_text', 'Unknown')
                odo = irda_decoded.get('odometer', 'Unknown')
                logging.info(f"  Direction: {dir_txt} | Odometer: {odo} ft")
                
                # Insert to database
                train_db.insert_train_passage(
                    irda_decoded.get('irda_tmcc'),
                    irda_decoded.get('direction'),
                    name, 
                    road
                )
                
        except Exception as e:
            logging.error(f"Error processing IRDA Engine Table packet: {e}")
            import traceback
            logging.debug(traceback.format_exc())

def receive_data(sock):
    """
    Continuously receive data. Handles TCP buffering by splitting on 'DF'.
    Returns True if connection was lost, False if terminated normally.
    """
    buffer = ""
    try:
        while True:
            data = sock.recv(config.PDI_RX_PKTSIZE)
            if not data:
                logging.warning("Connection closed by server")
                return True  # Connection lost
            
            # Append new data to buffer
            buffer += data.decode('utf-8', errors='replace')
            
            # Process complete messages ending in 'DF'
            while "DF" in buffer:
                segment, buffer = buffer.split("DF", 1)
                message = segment + "DF"
                process_message(message, sock)
                
    except socket.error as e:
        logging.error(f"Socket error: {e}")
        return True  # Connection lost
    except Exception as e:
        logging.error(f"Unexpected error in receive_data: {e}")
        return True
    finally:
        logging.info("Receiver thread terminating...")

def connect_to_lcs_base():
    """
    Attempt to connect to the LCS Base.
    Returns (socket, success) tuple.
    """
    global sent_count, connection_established, waiting_for_config_reply
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((SERVER_IP, config.SERVER_PORT))
        logging.info(f"Connected to LCS Base at {SERVER_IP}:{config.SERVER_PORT}")
        publish_irda_status("CONNECTED")
        
        # Reset connection event for this new connection
        connection_established.clear()
        
        # Start receiver thread
        receive_thread = threading.Thread(target=receive_data, args=(sock,), daemon=True)
        receive_thread.start()
        
        # Wait for initial packet
        logging.info("Waiting for initial packet to confirm connection...")
        if connection_established.wait(timeout=30):
            # Send WIFI CONNECT command
            sent_count += 1
            logging.info(f"[S:{sent_count}] Sending WIFI CONNECT: {config.WIFI_CONNECT}")
            sock.sendall(config.WIFI_CONNECT.encode('utf-8'))
            
            # Send GET All Configs command
            sent_count += 1
            logging.info(f"[S:{sent_count}] Sending GET All Configs: {config.GET_ALL_CONFIGS}")
            sock.sendall(config.GET_ALL_CONFIGS.encode('utf-8'))
            
            waiting_for_config_reply = True
            
            return sock, receive_thread, True
        else:
            logging.warning("Timed out waiting for initial packet")
            sock.close()
            publish_irda_status("ERROR", "Timeout waiting for initial packet")
            return None, None, False
            
    except socket.error as e:
        logging.error(f"Failed to connect to LCS Base: {e}")
        publish_irda_status("DISCONNECTED", str(e))
        return None, None, False
    except Exception as e:
        logging.error(f"Unexpected error connecting to LCS Base: {e}")
        publish_irda_status("ERROR", str(e))
        return None, None, False

def main():
    global sent_count
    
    # Register cleanup handler
    atexit.register(cleanup_mqtt)

    # Setup MQTT first - this should succeed even if LCS Base is down
    if not setup_mqtt():
        logging.warning("MQTT setup failed, continuing without MQTT reporting")

    # Determine which server to use
    if not determine_server():
        logging.critical("Terminating due to server determination failure.")
        cleanup_mqtt()
        return

    if SERVER_IP is None:
        logging.critical("SERVER_IP is not set. Exiting.")
        cleanup_mqtt()
        return

    # Retry configuration
    retry_delay = 10  # Start with 10 seconds
    
    running = True
    
    try:
        while running:
            # Attempt to connect to LCS Base
            sock, receive_thread, success = connect_to_lcs_base()
            
            if success:
                # Reset retry delay on successful connection
                retry_delay = 10
                
                # Monitor the connection
                try:
                    while receive_thread.is_alive():
                        time.sleep(1)
                    
                    # Thread died - connection was lost
                    logging.warning("Connection to LCS Base lost")
                    publish_irda_status("DISCONNECTED", "Connection lost")
                    
                except KeyboardInterrupt:
                    logging.info("Shutting down...")
                    running = False
                finally:
                    if sock:
                        sock.close()
            
            # If we're still running, wait before retry
            if running:
                logging.info(f"Will retry connection to LCS Base in {retry_delay} seconds...")
                time.sleep(retry_delay)
                
                
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    except Exception as e:
        logging.error(f"Unexpected error in main loop: {e}")
    finally:
        logging.info("Service shutting down")
        publish_irda_status("DISCONNECTED", "Service shutdown")
        cleanup_mqtt()

if __name__ == "__main__":
    main()
