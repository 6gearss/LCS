#!/usr/bin/env python3
"""
irda_hex_decoder.py

This module provides functionality to decode a hex string representing a packet.
The packet structure is assumed to be an LCS IRDA packet.
"""

SOP = 0xD1
EOP = 0xDF
STF = 0xDE

PRODUCT_REV_MAP = {
    0x00: "Switcher",
    0x01: "Road",
}

PRODUCT_ID_MAP = {
    0x02: "Diesel",
    0x03: "Diesel Switcher",
    0x04: "Steam",
    0x05: "Steam Switcher",
    0x06: "Subway",
    0x07: "Electric",
    0x08: "Acela",
    0x09: "Pullmor Diesel",
    0x0A: "Pullmor Steam",
    0x0B: "Breakdown",
    0x0C: "Track Crane",
    0x0D: "Accessory",
    0x0E: "Stock Car",
    0x0F: "Passenger Car",
}

TSDB_MAP = {
    0x01: "Ditch Lights",
    0x02: "Ground Lights",
    0x03: "MARS Lights",
    0x04: "Hazard Lights",
    0x05: "Strobe Lights",
    0x06: "Reserved",
    0x07: "Reserved",
    0x08: "Rule 17",
    0x09: "Loco Marker",
    0x0A: "Tender Marker",
    0x0B: "Doghouse",
    0x0C: "Reserved",
    0x0D: "Reserved",
    0x0E: "Reserved",
    0x0F: "Reserved",
}

def decode_text(data_bytes):
    """Decode to ascii and strip tracking null bytes."""
    return bytes(data_bytes).decode('ascii', errors='ignore').split('\x00')[0]

def irda_decode_packet(hex_string):
    """
    Decode a continuous hex-encoded packet into its components.

    Args:
        hex_string (str): A continuous string of hex digits (e.g. "D1320A10...").

    Returns:
        dict: A dictionary of decoded packet fields.

    Raises:
        ValueError: if the packet is empty, if the hex string has an odd number of characters,
                    or if SOP/EOP are not found in their expected locations.
    """
    hex_string = hex_string.strip()
    if not hex_string:
        raise ValueError("Empty packet provided.")

    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string must have an even number of characters.")

    parts = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    
    try:
        bytes_list = [int(part, 16) for part in parts]
    except ValueError as err:
        raise ValueError("Invalid hex string format.") from err

    if bytes_list[0] != SOP:
        raise ValueError(f"Invalid SOP: expected 0x{SOP:02X}, got 0x{bytes_list[0]:02X}.")
    if bytes_list[-1] != EOP:
        raise ValueError(f"Invalid EOP: expected 0x{EOP:02X}, got 0x{bytes_list[-1]:02X}.")

    command_byte = bytes_list[1] if len(bytes_list) > 1 else None
    if command_byte == 0x32:
        command_type = "IRDA_RESPONSE"
    elif command_byte == 0x31:
        command_type = "IRDA_SET"
    elif command_byte == 0x30:
        command_type = "IRDA_GET"
    else:
        command_type = f"Unknown (0x{command_byte:02X})" if command_byte is not None else "Unknown"

    irda_tmcc_byte = bytes_list[2] if len(bytes_list) > 2 else None

    # Fallback to original blind extraction logic just in case
    direction_byte = bytes_list[8] if len(bytes_list) > 8 else None
    if direction_byte == 0x01:
        direction = "RIGHT"
    elif direction_byte is not None:
        direction = "LEFT"
    else:
        direction = None

    engine_name = ""
    if len(bytes_list) >= 25 + 32:
        engine_name = decode_text(bytes_list[25:57])
        
    road_number = ""
    if len(bytes_list) >= 62:
        road_number = decode_text(bytes_list[58:62])

    decoded_info = {
        "command": command_type,
        "irda_tmcc": irda_tmcc_byte,
        "direction": direction,
        "engine_name": engine_name,
        "road_number": road_number,
    }

    # Extract detailed payload data if action is DATA (0x10)
    data_len = len(bytes_list)
    if data_len > 3:
        action = bytes_list[3]
        if action == 0x10:  # IrdaAction.DATA
            decoded_info["valid1"] = bytes_list[4] if data_len > 4 else None
            decoded_info["valid2"] = bytes_list[6] if data_len > 6 else None
            
            # Direction re-confirmed
            if data_len > 8:
                dir_byte = bytes_list[8]
                decoded_info["direction"] = "RIGHT" if dir_byte == 0x01 else ("LEFT" if dir_byte == 0x00 else dir_byte)
            
            decoded_info["engine_id"] = bytes_list[9] if data_len > 9 else None
            decoded_info["train_id"] = bytes_list[10] if data_len > 10 else None
            decoded_info["status"] = bytes_list[11] if data_len > 11 else None
            
            if data_len > 12:
                decoded_info["fuel_raw"] = bytes_list[12]
                decoded_info["fuel_pct"] = round(100.0 * bytes_list[12] / 255, 2)
            if data_len > 13:
                decoded_info["water_raw"] = bytes_list[13]
                decoded_info["water_pct"] = round(100.0 * bytes_list[13] / 255, 2)
            
            decoded_info["burn"] = bytes_list[14] if data_len > 14 else None
            decoded_info["fwb_mask"] = bytes_list[15] if data_len > 15 else None
            decoded_info["runtime"] = bytes_list[16] if data_len > 16 else None
            
            if data_len > 18:
                rev = bytes_list[18]
                decoded_info["prod_rev"] = PRODUCT_REV_MAP.get(rev, f"Unknown ({rev})")
            
            if data_len > 19:
                pid = bytes_list[19]
                decoded_info["prod_id"] = PRODUCT_ID_MAP.get(pid, f"Unknown ({pid})")
                
            if data_len > 22:
                bt_bytes = bytes_list[20:22]
                decoded_info["bluetooth_id"] = bytes(bt_bytes).hex(":")
                
            if data_len > 25:
                try:
                    yr_str = decode_text(bytes_list[22:25])
                    decoded_info["prod_year"] = 2000 + int(yr_str) if yr_str else None
                except ValueError:
                    decoded_info["prod_year"] = None

            if data_len > 59:
                decoded_info["engine_name"] = decode_text(bytes_list[25:59])
                
            if data_len > 63:
                decoded_info["road_number"] = decode_text(bytes_list[58:63])

            if data_len > 63:
                tsdb_l = bytes_list[63]
                decoded_info["tsdb_left"] = TSDB_MAP.get(tsdb_l, f"Unknown ({tsdb_l})")
            if data_len > 64:
                tsdb_r = bytes_list[64]
                decoded_info["tsdb_right"] = TSDB_MAP.get(tsdb_r, f"Unknown ({tsdb_r})")
            if data_len > 65:
                decoded_info["max_speed"] = bytes_list[65]
            if data_len > 69:
                decoded_info["odometer"] = int.from_bytes(bytes(bytes_list[66:69]), byteorder="little")
            
    return decoded_info

if __name__ == "__main__":
    example_hex = "D1321510FFFF010000080008FBFB063F020001025419323200496C6C696E6F69732043656E7472616C204553343441430000000000000000000033303038000108C3D001000051DF"
    print("Decoding Example HEX:", example_hex)
    decoded = irda_decode_packet(example_hex)
    for key, value in decoded.items():
        if isinstance(value, float):
            print(f"{key}: {value}%")
        else:
            print(f"{key}: {value}")
