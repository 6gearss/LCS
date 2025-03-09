#!/usr/bin/env python3
"""
train_db.py

This module decodes a continuous hex string to extract engine name and road number,
generates random values for direction and track, and then inserts a new record
into the TrainPassages table in the train_tracking database.
"""

import random
import mysql.connector
from irda_hex_decoder import irda_decode_packet  # our previously defined module

# Database configuration
db_config = {
    'host': '10.70.3.25',
    'user': 'train_operator',
    'password': 'StrongPassword123!',
    'database': 'train_tracking'
}

def insert_train_passage(irda_tmcc, direction, engine_name, road_number):
    """
    Inserts a new train passage record into the TrainPassages table.

    Args:
        engine_name (str): The decoded engine name.
        road_number (str): The decoded road number.
    """
    # Generate random values for direction and track
    #direction = random.choice(["East", "West"])
    #track = random.randint(1, 4)

    # Note: "road_namuber" is assumed to be the correct column name as per your schema.
    insert_query = """
        INSERT INTO irda_pass (irda_tmcc, direction, engine_name, road_number, pass_time)
        VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP())
    """
    values = (irda_tmcc, direction, engine_name, road_number)

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute(insert_query, values)
        conn.commit()
        print("Record inserted successfully.")
    except mysql.connector.Error as err:
        print("Error while inserting record:", err)
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    # Example continuous hex string without spaces.
    hex_string = (
        "D1320A
        10FFFF01000157031AF6F2063F01000102000032300050656E6E73796C76616E696120547261696E204D6173746572000000000000000038373034000908C36001000003DF"
    )
    
    # Decode the packet to extract engine name and road number.
    decoded = irda_decode_packet(hex_string)
    irda_tmcc = decoded.get("irda_tmcc", "")
    direction = decoded.get("direction", "")
    engine_name = decoded.get("engine_name", "")
    road_number = decoded.get("road_number", "")
    
    if engine_name and road_number:
        print("Decoded IRDA TMCC ID:", irda_tmcc)
        print("Decoded Direction:", direction)
        print("Decoded Engine Name:", engine_name)
        print("Decoded Road Number:", road_number)
        insert_train_passage(irda_tmcc, direction, engine_name, road_number)
    else:
        print("Engine name or road number not found in the decoded packet.")
