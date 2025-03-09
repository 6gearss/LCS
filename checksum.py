def create_packet(payload_hex: str) -> str:
    """
    Takes a payload hex string, adds SOP (0xD1) at the beginning and EOP (0xDF) at the end.
    Computes a checksum using only the payload bytes so that:
    
        (sum(payload) + checksum) mod 256 = 0
    
    The checksum is calculated as:
    
        checksum = (- sum(payload)) mod 256
    
    and is inserted between the payload and the EOP.
    
    :param payload_hex: Hex string representing the payload (e.g., "01 02 03" or "010203")
    :return: Final packet as a hex string (e.g., "D101020329DF")
    """
    # Remove any whitespace from the hex string
    payload_hex = payload_hex.replace(" ", "")
    
    # Convert the payload hex string into bytes
    payload_bytes = bytes.fromhex(payload_hex)
    
    # Define SOP and EOP
    SOP = 0xD1
    EOP = 0xDF

    # Calculate the checksum using only the payload bytes
    payload_sum = sum(payload_bytes)
    checksum = (-payload_sum) & 0xFF  # ensure result is within 0-255

    # Construct the final packet: SOP + payload + checksum + EOP
    packet = bytearray([SOP]) + payload_bytes + bytearray([checksum, EOP])
    
    # Return the packet as an uppercase hex string
    return packet.hex().upper()


# Example usage:
if __name__ == "__main__":
    # Example payload
    input_hex = "34 81 01"
    packet_hex = create_packet(input_hex)
    print(f"Input payload: {input_hex}")
    print(f"Generated packet: {packet_hex}")

def check_packet(packet_hex: str) -> bool:
    """
    Verifies that a given packet hex string is valid.
    
    A valid packet must:
      - Start with SOP (0xD1)
      - End with EOP (0xDF)
      - Have a checksum such that (sum(payload) + checksum) mod 256 == 0
      
    The packet structure is:
      [SOP][payload bytes][checksum][EOP]
      
    :param packet_hex: Hex string representing the full packet (e.g., "D101020329DF")
    :return: True if the packet is valid, False otherwise.
    """
    # Remove any whitespace from the hex string
    packet_hex = packet_hex.replace(" ", "")
    
    try:
        # Convert the packet hex string into bytes
        packet_bytes = bytes.fromhex(packet_hex)
    except ValueError:
        # Not a valid hex string
        return False

    # Minimum packet length: must have at least 3 bytes (SOP, checksum, EOP)
    if len(packet_bytes) < 3:
        return False

    SOP = 0xD1
    EOP = 0xDF

    # Check for correct SOP and EOP values
    if packet_bytes[0] != SOP or packet_bytes[-1] != EOP:
        return False
