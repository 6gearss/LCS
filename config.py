"""
Configuration settings for the LCS Project.
"""
import os

# Network Configuration
# You can override these with environment variables if needed
SERVER_PORT = int(os.getenv('LCS_SERVER_PORT', 50001))

# Database Configuration
DB_HOST = os.getenv('LCS_DB_HOST', 'sql.internal')
DB_USER = os.getenv('LCS_DB_USER', 'train_operator')
DB_PASSWORD = os.getenv('LCS_DB_PASSWORD', 'StrongPassword123!')
DB_NAME = os.getenv('LCS_DB_NAME', 'train_tracking')

DB_CONFIG = {
    'host': DB_HOST,
    'user': DB_USER,
    'password': DB_PASSWORD,
    'database': DB_NAME
}

# Command Constants
BASE_RECORD_READ = "D1230002DBDF"
WIFI_CONNECT = "D13481014ADF"
PING_PACKET = "D129D7DF"

# Packet Constants
PDI_RX_PKTSIZE = 1024
PDI_TX_PKTSIZE = 4096
SOP = 0xD1
EOP = 0xDF
STF = 0xDE

# Server Discovery Configuration
# Helper map to determine which server IP to use based on the local subnet.
# Format: "CIDR": "Target Server IP"
NETWORK_SERVER_MAP = {
    "192.168.99.0/24": "192.168.99.1",
    "192.168.111.0/24": "192.168.111.30"
}

# MQTT Configuration
MQTT_BROKER = os.getenv('LCS_MQTT_BROKER', 'mqtt.internal')
MQTT_PORT = int(os.getenv('LCS_MQTT_PORT', 1883))
MQTT_TOPIC_STATUS = "HSC/irda/status"  # Topic for service status (UP/DOWN)
MQTT_TOPIC_IRDA_STATUS = "HSC/irda/base"  # Topic for LCS Base connection status (CONNECTED/DISCONNECTED/ERROR)
MQTT_TOPIC_BASE_IP = "HSC/irda/base/ip"  # Topic for LCS Base IP address
MQTT_TOPIC_DATA = "HSC/irda/data"      # Topic for data (optional, for future use)
