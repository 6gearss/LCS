def create_packet(payload_hex: str) -> str:
    """
    Creates a packet from a payload hex string by:
      1. Removing whitespace and converting to bytes.
      2. Calculating a checksum over the payload such that:
           (sum(payload) + checksum) mod 256 = 0
      3. Performing byte stuffing on the payload and checksum:
           If a byte equals SOP (0xD1) or EOP (0xDF), an escape byte (0xDE) is inserted before it.
      4. Framing the stuffed data with SOP at the start and EOP at the end.
    
    :param payload_hex: Hex string representing the payload (e.g., "01 02 03" or "010203")
    :return: Final packet as an uppercase hex string.
             For example, with payload "01 02 03", it might return "D101020329DF"
    """
    # Remove any whitespace from the input hex string.
    payload_hex = payload_hex.replace(" ", "")
    
    # Convert the cleaned hex string into a bytes object.
    payload_bytes = bytes.fromhex(payload_hex)
    
    # Define the special bytes.
    SOP     = 0xD1  # Start Of Packet
    EOP     = 0xDF  # End Of Packet
    STF     = 0xDE  # Escape byte
    
    # Calculate the checksum using only the payload bytes.
    # The checksum is chosen so that: (sum(payload) + checksum) mod 256 = 0.
    payload_sum = sum(payload_bytes)
    checksum = (-payload_sum) & 0xFF  # Ensures a value in 0-255.
    
    def stuff_data(data: bytes) -> bytes:
        """
        Inserts the escape byte (0xDE) before any occurrence of the SOP (0xD1) or EOP (0xDF)
        in the provided data.
        """
        stuffed = bytearray()
        for byte in data:
            if byte in (SOP, EOP):
                stuffed.append(STF)
            stuffed.append(byte)
        return bytes(stuffed)
    
    # Perform byte stuffing on the payload and checksum.
    stuffed_payload  = stuff_data(payload_bytes)
    stuffed_checksum = stuff_data(bytes([checksum]))
    
    # Construct the final packet: SOP + stuffed_payload + stuffed_checksum + EOP.
    packet = bytearray([SOP]) + stuffed_payload + stuffed_checksum + bytearray([EOP])
    
    # Return the final packet as an uppercase hex string.
    return packet.hex().upper()

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

    # Extract the checksum from the packet (the byte before EOP)
    checksum_in_packet = packet_bytes[-2]

    # The payload is everything between SOP and the checksum
    payload_bytes = packet_bytes[1:-2]

    # Compute the expected checksum using the payload bytes
    expected_checksum = (-sum(payload_bytes)) & 0xFF

    # If the checksums match, the packet is valid
    return checksum_in_packet == expected_checksum


# # Example usage:
# if __name__ == "__main__":
#     # Generate a packet from a sample payload
#     input_hex = "34 81 01"
#     packet_hex = create_packet(input_hex)
#     print(f"Generated packet: {packet_hex}")

#     # Validate the generated packet
#     is_valid = check_packet(packet_hex)
#     print(f"Packet valid? {is_valid}")


#     # Validate the sample packet
#     sample_hex="D1 36 81 01 02 03 00 43 DF"
#     is_valid = check_packet(sample_hex)
#     print(f"Packet valid? {is_valid}")


#     # Testing with an invalid packet (tampering with checksum)
#     invalid_packet_hex = packet_hex[:-4] + "00" + packet_hex[-2:]
#     print(f"Tampered packet: {invalid_packet_hex}")
#     print(f"Packet valid? {check_packet(invalid_packet_hex)}")


