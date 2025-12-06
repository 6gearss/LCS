#!/usr/bin/env python3
"""
engine_decoder.py

Decoder for Legacy Engine Table Structure (PDI_CMD_BASEDATA_ENGINE - 0x20/0x32)
Based on Lionel LCS Partner Documentation Doc rev 1.02

The engine table record is 68 bytes total with the following structure:
- Control Data (8 bytes)
- Engine Table Data (60 bytes)
"""

# Lookup tables based on LCS documentation

LOCO_TYPES = {
    0: "Diesel Road Locomotive",
    1: "Steam Road Locomotive",
    2: "Electric Road Locomotive",
    3: "Subway Passenger Car Set",
    4: "Operating Car / Trackside Accessory",
    5: "Passenger Car",
    6: "Breakdown 'B' Unit",
    7: "Reserved",
    8: "Acela Electric",
    9: "TMCC Track Crane Car",
    10: "Diesel Switcher Locomotive",
    11: "Steam Switcher Locomotive",
    12: "Freight Sounds Operating Car",
    13: "Diesel - Flyer or Pullmor",
    14: "Steam - Flyer or Pullmor",
    15: "Transformer"
}

CONTROL_TYPES = {
    0: "CAB-1",
    1: "TMCC",
    2: "Legacy",
    3: "R100"
}

SOUND_TYPES = {
    0: "No Sounds",
    1: "RailSounds v2-4",
    2: "RailSounds v5",
    3: "RailSounds v6+ (Legacy)"
}

CLASS_TYPES = {
    0: "Road Locomotive",
    1: "Switcher Locomotive",
    2: "Subway Passenger Car Set",
    10: "Diesel or Steam, Flyer or Legacy Pullmor",
    20: "Transformer",
    255: "Wildcard, Universal Class"
}

TSDB_ICONS = {
    2: "Hazard Light Controls",
    4: "Strobe Light Controls",
    6: "Ground Light Controls",
    8: "MARS Light Controls",
    23: "Dog House Light Controls",
    25: "Tender Marker Light Controls",
    27: "Engine Marker Light Controls",
    29: "Ditch Light Controls",
    32: "Rule 17 Light Controls"
}

TRAIN_POSITIONS = {
    0: "Single Unit",
    1: "Head Unit",
    2: "Middle Unit",
    3: "Tail Unit"
}

SMOKE_LEVELS = {
    0: "Off",
    1: "Low",
    2: "Medium",
    3: "High"
}

DITCH_LIGHT_MODES = {
    0: "Off",
    1: "Off, Pulse On",
    2: "On, Pulse Off",
    3: "On"
}

RESULT_STATUS = {
    0: "No Errors",
    1: "No Write Required (base record table identical)",
    2: "Local Ack Returned state",
    3: "ERROR - Base Authentication failed",
    4: "ERROR - No Base Connection",
    5: "ERROR - Baud Rate incorrect",
    6: "ERROR - Base Locked",
    7: "ERROR - Read table record failed",
    8: "ERROR - Write failed to NVM (non-volatile storage)",
    9: "ERROR - Write failed to RAM",
    10: "ERROR - Write failed, Base Table Record Locked",
    11: "ERROR - Write or Read failed, Base1-L specific, no NVM or RAM",
    12: "ERROR - Write or Read failed, No Base specific, no NVM or RAM"
}


def decode_process_flags(flags):
    """Decode the Process Flags byte."""
    return {
        "write_read": bool(flags & 0x80),  # 1=Write, 0=Read
        "update_cab2": bool(flags & 0x40),
        "clear_lock": bool(flags & 0x10),
        "set_lock": bool(flags & 0x08),
        "lock_status": bool(flags & 0x04),
        "base_ack": bool(flags & 0x02),
        "local_ack": bool(flags & 0x01)
    }


def decode_train_position(position_byte):
    """Decode the Train Position byte."""
    position_code = position_byte & 0x03
    return {
        "position": TRAIN_POSITIONS.get(position_code, f"Unknown ({position_code})"),
        "direction": "Reverse" if (position_byte & 0x04) else "Forward",
        "train_linked_enabled": bool(position_byte & 0x08),
        "horn_bell_masking": bool(position_byte & 0x10),
        "dialog_masking": bool(position_byte & 0x20),
        "tmcc2_enabled": bool(position_byte & 0x40),
        "accessory_enabled": bool(position_byte & 0x80)
    }


def decode_engine_table(packet_bytes):
    """
    Decode a Legacy Engine Table structure packet.
    
    Args:
        packet_bytes: bytes object containing the full packet (including SOP/EOP)
        
    Returns:
        dict: Decoded engine table data
    """
    # Validate minimum packet length
    # SOP (1) + Command (1) + Engine Data (68) + Checksum (1) + EOP (1) = 72 bytes minimum
    if len(packet_bytes) < 72:
        return {"error": f"Packet too short: {len(packet_bytes)} bytes (expected at least 72)"}
    
    # Skip SOP (0xD1) and command byte (0x32), start at offset 2
    data = packet_bytes[2:-2]  # Exclude SOP, command, checksum, and EOP
    
    if len(data) < 68:
        return {"error": f"Engine data too short: {len(data)} bytes (expected 68)"}
    
    # Parse Control Data (first 8 bytes)
    record_number = data[0]
    process_flags = data[1]
    result_status = data[2]
    # data[3] is spare
    valid1 = (data[4] << 8) | data[5]
    valid2 = (data[6] << 8) | data[7]
    
    # Parse Engine Table Data (remaining 60 bytes)
    offset = 8
    
    # Extract strings (null-terminated ASCII)
    road_name_bytes = data[offset:offset+33]
    road_name = bytes(road_name_bytes).decode('ascii', errors='ignore').split('\x00')[0]
    offset += 33
    
    road_number_bytes = data[offset:offset+5]
    road_number = bytes(road_number_bytes).decode('ascii', errors='ignore').split('\x00')[0]
    offset += 5
    
    # Extract single-byte fields
    loco_type = data[offset]
    offset += 1
    
    control_type = data[offset]
    offset += 1
    
    sound_system_type = data[offset]
    offset += 1
    
    class_spec = data[offset]
    offset += 1
    
    tsdb_left = data[offset]
    offset += 1
    
    tsdb_right = data[offset]
    offset += 1
    
    # spare byte
    offset += 1
    
    speed_step = data[offset]
    offset += 1
    
    run_level = data[offset]
    offset += 1
    
    labor_bias = data[offset]
    offset += 1
    
    speed_limit = data[offset]
    offset += 1
    
    max_speed = data[offset]
    offset += 1
    
    # Valid2 fields
    fuel_level = data[offset]
    offset += 1
    
    water_level = data[offset]
    offset += 1
    
    train_address = data[offset]
    offset += 1
    
    train_position_byte = data[offset]
    offset += 1
    
    smoke_level_byte = data[offset]
    offset += 1
    
    ditch_light_byte = data[offset]
    offset += 1
    
    train_brake = data[offset]
    offset += 1
    
    momentum = data[offset]
    
    # Build the decoded structure
    decoded = {
        "control_data": {
            "record_number": record_number,
            "process_flags": decode_process_flags(process_flags),
            "result_status": RESULT_STATUS.get(result_status, f"Unknown ({result_status})"),
            "valid1": f"0x{valid1:04X}",
            "valid2": f"0x{valid2:04X}"
        },
        "engine_data": {
            "road_name": road_name,
            "road_number": road_number,
            "loco_type": LOCO_TYPES.get(loco_type, f"Unknown ({loco_type})"),
            "control_type": CONTROL_TYPES.get(control_type, f"Unknown ({control_type})"),
            "sound_system": SOUND_TYPES.get(sound_system_type, f"Unknown ({sound_system_type})"),
            "class": CLASS_TYPES.get(class_spec, f"Unknown ({class_spec})"),
            "tsdb_left": TSDB_ICONS.get(tsdb_left, f"Unknown ({tsdb_left})"),
            "tsdb_right": TSDB_ICONS.get(tsdb_right, f"Unknown ({tsdb_right})"),
            "speed_step": speed_step,
            "run_level": run_level,
            "labor_bias": labor_bias,
            "speed_limit": speed_limit if speed_limit != 255 else "No Limit",
            "max_speed": max_speed,
            "fuel_level": fuel_level,
            "water_level": water_level,
            "train_address": train_address,
            "train_position": decode_train_position(train_position_byte),
            "smoke_level": SMOKE_LEVELS.get(smoke_level_byte & 0x03, f"Unknown ({smoke_level_byte & 0x03})"),
            "ditch_lights": DITCH_LIGHT_MODES.get(ditch_light_byte & 0x03, f"Unknown ({ditch_light_byte & 0x03})"),
            "train_brake": train_brake,
            "momentum": momentum,
            "momentum_setting": f"{momentum / 16:.1f}" if momentum > 0 else "0"
        }
    }
    
    return decoded


if __name__ == "__main__":
    # Test with example hex string
    example_hex = "D1320A10FFFF01000157031AF6F2063F01000102000032300050656E6E73796C76616E696120547261696E204D6173746572000000000000000038373034000908C36001000003DF"
    
    try:
        packet_bytes = bytes.fromhex(example_hex)
        decoded = decode_engine_table(packet_bytes)
        
        print("=== Decoded Engine Table ===\n")
        
        if "error" in decoded:
            print(f"Error: {decoded['error']}")
        else:
            print("Control Data:")
            for key, value in decoded["control_data"].items():
                print(f"  {key}: {value}")
            
            print("\nEngine Data:")
            for key, value in decoded["engine_data"].items():
                if isinstance(value, dict):
                    print(f"  {key}:")
                    for k, v in value.items():
                        print(f"    {k}: {v}")
                else:
                    print(f"  {key}: {value}")
    except Exception as e:
        print(f"Error decoding: {e}")
        import traceback
        traceback.print_exc()
