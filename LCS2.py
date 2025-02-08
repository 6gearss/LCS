import os
import sys
sys.path.append('')

import lionel_lcs
#import legacy_3word as lionel_lcs

def main():
    test_packets = [
        # Legacy command examples:
        bytes([0xF8, 0x19, 0xC8]),  # Set Momentum (legacy)
        bytes([0xF9, 0x0B, 0xE3]),  # Set Brake Level (level 3)
        bytes([0xF8, 0x1F, 0xBF]),  # Possibly Set Absolute Speed
        # Alternate syntax examples:
        bytes([0xF9, 0x81, 0x00]),  # Forward Direction
        bytes([0xF8, 0x82, 0x11]),  # Numeric Command 1
        bytes([0xF9, 0x83, 0x27]),  # Assign as Rear End Unit Reverse Direction
        bytes([0xF8, 0x84, 0x05]),  # Open Front Coupler
        # Engine-specific commands (from log file):
        bytes([0xF8, 0xAF, 0x03]),  # F8 AF 03 – Reverse Direction
        bytes([0xF8, 0xAE, 0xFB]),  # F8 AE FB – Stop Immediate
        bytes([0xF8, 0xAE, 0x00]),  # F8 AE 00 – Absolute Speed 0
        bytes([0xF8, 0xAE, 0xF0]),  # F8 AE F0 – Trainbrake Level 0
        bytes([0xF8, 0xAF, 0xCC]),  # F8 AF CC – Engine Labor 12
        bytes([0xF8, 0xAE, 0xC8]),  # F8 AE C8 – Momentum Low 0
        bytes([0xF8, 0xAE, 0x01]),  # F8 AE 01 – Absolute Speed 1
        bytes([0xF8, 0xAE, 0x0A]),  # F8 AE 0A – Absolute Speed 10
        bytes([0xF8, 0xAE, 0x14]),  # F8 AE 14 – Absolute Speed 20
        bytes([0xF8, 0xAE, 0xF7]),  # F8 AE F7 – Trainbrake Level 7
        bytes([0xF8, 0xAF, 0xDA]),  # F8 AF DA – Engine Labor 26
        bytes([0xF8, 0xAE, 0xF3]),  # F8 AE F3 – Trainbrake Level 3
        bytes([0xF8, 0xAE, 0xF1]),  # F8 AE F1 – Trainbrake Level 1
        bytes([0xF8, 0xAF, 0xCF]),  # F8 AF CF – Engine Labor 15
        # Multi–word command example:
        bytes([0xFB, 0x00, 0x00, 0x01]),
    ]

    print("TMCC2 Command Packet Decoder Demo")
    for pkt in test_packets:
        # Format the packet bytes as "0xXX" separated by spaces.
        pkt_str = " ".join(f"0x{b:02X}" for b in pkt)
        try:
            result = lionel_lcs.decode_packet(pkt)
        except Exception as e:
            result = f"Error: {e}"
        print(f"Packet [{pkt_str}] --> {result}")


if __name__ == '__main__':
    main()