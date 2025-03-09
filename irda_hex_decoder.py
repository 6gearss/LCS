#!/usr/bin/env python3
"""
irda_hex_decoder.py

This module provides functionality to decode a hex string representing a packet.
The packet structure is assumed to be:
  - SOP: the first byte (0xD1)
  - Byte 1: a command indicator; if it equals 0x32, the packet is an IRDA command.
  - (Optional) STF: 0xDE, may appear in the packet.
  - If no STF is found, then:
      * The engine name is located starting at byte 25 and spans 32 bytes.
      * The road number is contained in bytes 59 to 62 (ASCII encoded).
  - EOP: the final byte (0xDF)
  
Note: The hex string is expected to be continuous (without spaces).
"""

SOP = 0xD1
EOP = 0xDF
STF = 0xDE

def irda_decode_packet(hex_string):

    #print (hex_string)
    """
    Decode a continuous hex-encoded packet into its components.

    Args:
        hex_string (str): A continuous string of hex digits (e.g. "D1320A10...").

    Returns:
        dict: A dictionary with the following keys:
              - "command": a string representing the command type (e.g. "IRDA")
              - "engine_name": the decoded engine name (str), if available.
              - "road_number": the decoded road number (str), if available.
              - "raw_bytes": the list of integer byte values representing the packet.

    Raises:
        ValueError: if the packet is empty, if the hex string has an odd number of characters,
                    or if SOP/EOP are not found in their expected locations.
    """
    hex_string = hex_string.strip()
    if not hex_string:
        raise ValueError("Empty packet provided.")

    # The hex string is assumed to be continuous with no spaces.
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string must have an even number of characters.")

    # Convert the continuous hex string into a list of two-character chunks.
    parts = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    
    try:
        bytes_list = [int(part, 16) for part in parts]
    except ValueError as err:
        raise ValueError("Invalid hex string format.") from err

    # Validate SOP and EOP.
    if bytes_list[0] != SOP:
        raise ValueError(f"Invalid SOP: expected 0x{SOP:02X}, got 0x{bytes_list[0]:02X}.")
    if bytes_list[-1] != EOP:
        raise ValueError(f"Invalid EOP: expected 0x{EOP:02X}, got 0x{bytes_list[-1]:02X}.")


    # Determine command type from the byte immediately after SOP.
    command_byte = bytes_list[1]
    if command_byte == 0x32:
        command_type = "IRDA"
    else:
        command_type = f"Unknown (0x{command_byte:02X})"

    # Determine direction .
    direction_byte = bytes_list[8]
    if direction_byte == 0x01:
        direction = "RIGHT"
    else:
        direction = "LEFT"


    # If there is no STF, extract engine_name and road_number.
    engine_name = None

     # Ensure there are enough bytes for engine name extraction.
    if len(bytes_list) >= 25 + 32:
        # Engine name is located at byte 25 and spans the next 32 bytes.
        engine_bytes = bytes_list[25:25 + 32]
        # Decode the bytes into an ASCII string and remove any null bytes.
        engine_name = bytes(engine_bytes).decode('ascii', errors='ignore').split('\x00')[0]
    else:
         engine_name = ""

    # Extract road number from bytes 58-61.
    road_number = ""
    if len(bytes_list) >= 62:  # Ensure byte index 61 exists.
        road_bytes = bytes_list[58:62]
        road_number = bytes(road_bytes).decode('ascii', errors='ignore').split('\x00')[0]

    return {
        "command": command_type,
        "direction" : direction,
        "engine_name": engine_name,
        "road_number": road_number,
       # "raw_bytes": bytes_list,
    }

# Example usage when running this module directly.
if __name__ == "__main__":
    example_hex = ("D1320110FFFF01000019000AD8C6063F0200010256D032340050656E6E73796C76616E696120475039000000000000000000000000000000000037303235000908C3B2010000EADF")
    decoded = irda_decode_packet(example_hex)
    print("Decoded Packet:")
    for key, value in decoded.items():
       print(f"{key}: {value}")
