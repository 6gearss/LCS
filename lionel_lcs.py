#!/usr/bin/env python3
"""
lionel_lcs.py

A TMCC2 command decoder module for Lionel LCS that takes into account
the first byte identifier and outputs a neatly formatted message.

TMCC2 command packets have a leading byte that indicates:
  • 0xF8: Command directed to the Engine address.
  • 0xF9: Command directed to the Assigned Train address.
  • 0xFB: A multi–word command (more complex commands).

For 0xF8 and 0xF9 packets, the next two bytes form the 16–bit command word.
That 16–bit word is then divided into:
  - Bits 15..9: a 7–bit address (the TMCC address)
  - Bits 8..0 : a 9–bit command field.
"""


def decode_packet(packet_bytes):
    """
    Decode a TMCC2 command packet.

    The packet is expected to be a bytes–like object where:
      - The first byte is the command identifier:
          0xF8 => Engine–directed command.
          0xF9 => Train–directed command.
          0xFB => Multi–word command.
      - For 0xF8 or 0xF9, the next two bytes form the 16–bit command word.
    
    :param packet_bytes: a bytes object (or list of integers) with at least 3 bytes.
    :return: A string describing the decoded command in a neat format.
    """
    if not packet_bytes:
        raise ValueError("Packet is empty.")

    first_byte = packet_bytes[0]
    if first_byte == 0xF8:
        direction = "Engine"
    elif first_byte == 0xF9:
        direction = "Train"
    elif first_byte == 0xFB:
        # For multi–word commands you might have additional bytes.
        return "Multi–word command detected – not implemented in this decoder."
    else:
        return f"Unknown first byte (0x{first_byte:02X}). Cannot decode packet."

    if len(packet_bytes) < 3:
        raise ValueError("Packet too short: expected at least 3 bytes for F8/F9 commands.")

    # Next two bytes form the 16-bit command word (big-endian).
    cmd_word = (packet_bytes[1] << 8) | packet_bytes[2]
    address, cmd_desc = decode_command(cmd_word)
    return f"Directed to address: {direction}: {address}, Command: {cmd_desc}"


def decode_command(word):
    """
    Decode a 16–bit TMCC2 command word.

    The 16 bits are assumed to be organized as:
      Bits 15..9: Address (7 bits)
      Bits 8..0 : Command field (9 bits)

    The command field is interpreted differently based on its MSB (bit8).
      • If bit8 is 0, the legacy (TMCC1–style) command syntax is used.
      • If bit8 is 1, an alternate command syntax is used.

    :param word: an integer in the range 0..0xFFFF representing the command word.
    :return: A tuple (address, command_description)
    """
    if not (0 <= word <= 0xFFFF):
        raise ValueError("Command word must be a 16‐bit value (0..0xFFFF).")

    # Extract the 7–bit address (bits 15..9) and the 9–bit command field (bits 8..0)
    address = (word >> 9) & 0x7F
    cmd_field = word & 0x1FF

    if cmd_field & 0x100:
        # bit8 is 1: use the alternate command syntax.
        cmd_desc = decode_bit9_one(cmd_field)
    else:
        # bit8 is 0: use the legacy command syntax.
        cmd_desc = decode_bit9_zero(cmd_field)

    return address, cmd_desc


# --- Decoding for legacy commands (bit8 == 0) ---
def decode_bit9_zero(cmd_field):
    """
    Decode a TMCC2 command (legacy syntax, bit8 == 0).

    Handles a representative subset of commands:
      - Set Momentum:      pattern 0 1 1 0 0 1 D D D   (D = 0–7)
      - Brake Level:       pattern 0 1 1 1 0 0 D D D   (D = 0–7)
      - Boost Level:       pattern 0 1 1 1 0 1 D D D   (D = 0–7)
      - Train Brake:       pattern 0 1 1 1 1 0 D D D   (D = 0–7)
      - Set Stall:         fixed pattern 0 1 1 1 1 1 0 0 0
      - Stop Immediate:    fixed pattern 0 1 1 1 1 1 0 1 1
      - Otherwise, if cmd_field < 200, it is assumed to be a Set Absolute Speed command.
    """
    fixed_mask = 0xF8  # bits 8..3

    if (cmd_field & fixed_mask) == 0xC8:
        value = cmd_field & 0x07
        return f"Set Momentum (value {value} of 0–7)"
    elif (cmd_field & fixed_mask) == 0xE0:
        value = cmd_field & 0x07
        return f"Set Brake Level (level {value} of 0–7)"
    elif (cmd_field & fixed_mask) == 0xE8:
        value = cmd_field & 0x07
        return f"Set Boost Level (level {value} of 0–7)"
    elif (cmd_field & fixed_mask) == 0xF0:
        value = cmd_field & 0x07
        return f"Set Train Brake (level {value} of 0–7)"
    elif cmd_field == 0xF8:
        return "Set Stall"
    elif cmd_field == 0xFB:
        return "Stop Immediate"
    else:
        if cmd_field < 200:
            return f"Set Absolute Speed (speed step {cmd_field} of 0–199)"
        else:
            return f"Unknown legacy command (cmd_field = 0x{cmd_field:02X})"


# --- Decoding for commands with alternate syntax (bit8 == 1) ---
def decode_bit9_one(cmd_field):
    """
    Decode a TMCC2 command (alternate syntax, bit8 == 1).

    Handles a representative subset of fixed commands and commands with embedded parameters.
    Examples:
      - 0x100: Forward Direction
      - 0x101: Toggle Direction
      - 0x103: Reverse Direction
      - etc.
    """
    fixed_cmds = {
        0x100: "Forward Direction",
        0x101: "Toggle Direction",
        0x102: "Reserved",
        0x103: "Reverse Direction",
        0x104: "Boost Speed",
        0x105: "Open Front Coupler",
        0x106: "Open Rear Coupler",
        0x107: "Brake Speed",
        0x108: "Aux1 Off",
        0x109: "Aux1 Option 1 (Cab1 AUX1)",
        0x10A: "Aux1 Option 2",
        0x10B: "Aux1 On",
        0x10C: "Aux2 Off",
        0x10D: "Aux2 Option 1 (Cab1 AUX2)",
        0x10E: "Aux2 Option 2",
        0x10F: "Aux2 On",
        0x11B: "Forward Direction (not used)",
        0x11C: "Blow Horn 1",
        0x11D: "Ring Bell",
        0x11E: "Reserved",
        0x11F: "Blow Horn 2",
        0x120: "Assign as Single Unit Forward Direction",
        0x121: "Assign as Single Unit Reverse Direction",
        0x122: "Assign as Head End Unit Forward Direction",
        0x123: "Assign as Head End Unit Reverse Direction",
        0x124: "Assign as Middle Unit Forward Direction",
        0x125: "Assign as Middle Unit Reverse Direction",
        0x126: "Assign as Rear End Unit Forward Direction",
        0x127: "Assign as Rear End Unit Reverse Direction",
        0x128: "Set Momentum Low",
        0x129: "Set Momentum Medium",
        0x12A: "Set Momentum High",
        0x12B: "Set Engine or Train Address",
        0x12C: "Clear Consist (Lash‐Up)",
        0x12D: "Locomotive Re‐Fueling Sound",
        0x12E: "Reserved",
        0x12F: "Reserved",
        0x1A8: "RS Trigger, Water Injector",
        0x1A9: "RS Trigger, Aux Air Horn (not used)",
        0x1AB: "System HALT",
        0x1F4: "Bell Off",
        0x1F5: "Bell On",
        0x1F6: "Brake Squeal Sound",
        0x1F7: "Auger Sound",
        0x1F8: "RS Trigger, Brake Air Release",
        0x1F9: "RS Trigger, Short Let‐Off",
        0x1FA: "RS Trigger, Long Let‐Off",
        0x1FB: "Start Up Sequence 1 (Delayed Prime Mover)",
        0x1FC: "Start Up Sequence 2 (Immediate Start Up)",
        0x1FD: "Shut Down Sequence 1 (Delay w/ Announcement)",
        0x1FE: "Shut Down Sequence 2 (Immediate Shut Down)",
    }
    if cmd_field in fixed_cmds:
        return fixed_cmds[cmd_field]
    # (a) Numeric Command: upper 5 bits 0x110 and lower 4 bits as value.
    if (cmd_field & 0x1F0) == 0x110:
        num = cmd_field & 0x0F
        return f"Numeric Command: {num}"
    # (b) Assign to Train: pattern 0x130 with lower 4 bits as train address.
    if (cmd_field & 0xF0) == 0x130:
        train_addr = cmd_field & 0x0F
        return f"Assign to Train (Train Address {train_addr})"
    # (c) Set Relative Speed: valid codes 0x140 to 0x14A.
    if 0x140 <= cmd_field <= 0x14A:
        rel_speed = cmd_field - 0x140
        return f"Set Relative Speed (value {rel_speed})"
    # (d) Diesel Run Level: pattern with bits [1 1 0 1 0 0 D D D].
    if (cmd_field & 0x1C0) == 0x1A0:
        level = cmd_field & 0x07
        return f"Diesel Run Level (level {level} of 0–7)"
    # (e) Bell Slider Position: pattern with bits [1 1 0 1 1 0 D D D].
    if (cmd_field & 0x1F8) == 0x1B0:
        pos = cmd_field & 0x07
        return f"Bell Slider Position (position {pos}, nominally 2–5)"
    # (f) Engine Labor: if bits 8..5 equal 0x0E.
    if (cmd_field >> 5) == 0x0E:
        labor = cmd_field & 0x1F
        return f"Engine Labor (value {labor} of 0–31)"
    # (g) Quilling Horn Intensity: pattern with bits [1 1 1 1 0 DDDD].
    if (cmd_field & 0x1F0) == 0x1E0:
        intensity = cmd_field & 0x0F
        return f"Quilling Horn Intensity (value {intensity} of 0–16)"
    # (h) Bell One–Shot Ding: pattern with bits [1 1 1 1 1 0 0 D D].
    if (cmd_field & 0x1FC) == 0x1F0:
        ding = cmd_field & 0x03
        return f"Bell One–Shot Ding (value {ding} of 0–3)"
    return f"Unknown alternate syntax command (cmd_field = 0x{cmd_field:03X})"
