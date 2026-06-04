import socket
import json
import time

# Used for GPS time conversion. Source:
# https://gnss-lib-py.readthedocs.io/en/latest/tutorials/utils/ tutorials_time_conversions_notebook.html
import gnss_lib_py as glp

from threading import Thread, Event

import pygame, sys

# Initialise a UDP connection with MAVProxy
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # IPV4, UDP
out_addr = ("127.0.0.1", 25100)

end = Event()
MODE = 2

# Send a GPS update every second when the program starts
TIMEOUT = 1
MIN_TIMEOUT = 0.05

# How long to disconnect GPS for when switching the time offset
DISCONNECTION_TIME = 0

GPS_CHANGE_RATE = 200

# MODE == 0 specifies offset mode
# MODE == 1 specifies absolute mode
while(MODE != 0 and MODE != 1):
    MODE = int(input("Would you like to set the GPS time to offset mode [0], or to chosen mode [1]?\n\n"))

# Get the offset/raw time from the user
OFFSET = int(input(
    f"""
Enter a GPS {'offset' if MODE == 0 else 'time'} in SECONDS

For example, 86400 would be 1 day.

Once the {'offset' if MODE == 0 else 'time'} has been entered, the program will begin.

"""))

# Default spoofed location is Clifton Suspension Bridge
POS = [514492880, -26083820]
ALT = 5

# ================================================================================ #

# This is the GPS spoofing thread, which runs forever
def gpsThread():
    # How many times we've sent the time with the same second
    roundsInSecond = 0
    currentSecond = 0

    while not end.is_set():
        # Send a GPS message every 0.05 seconds or so
        time.sleep(TIMEOUT)

        # Get the time in UNIX time in SECONDS, and apply the
        # user-defined offset
        unixNow = (int(time.time()) if MODE == 0 else 0) + OFFSET

        # Keep track of how many messages we've sent in the same second
        if (unixNow == currentSecond):
            roundsInSecond += 1
        
        else:
            roundsInSecond = 0
            currentSecond = unixNow

        gpsWeek, gpsTimeInWeek = 0,0

        # Expects UNIX MILLISECONDS, returns time of week in SECONDS
        try:
            gpsWeek, gpsTimeInWeek = glp.unix_millis_to_tow(unixNow * 1E3)

            # Keep track of how many messages we've sent so far this second, to allow us to sub-divide the second over different messages,
            # so two messges _never_ send the same time
            gpsTimeInWeek = (gpsTimeInWeek + (TIMEOUT * roundsInSecond))
        except:
            print("Can't convert the given offset to GPS time - exiting.")
            end.set()
            break

        # Send a MAVLink GPS_INPUT message to the FMU
        # https://mavlink.io/en/messages/common.html#GPS_INPUT
        data = {
            # (uint64_t) Timestamp (MICROSECONDS since boot or Unix epoch)
            'time_usec': int(glp.tow_to_unix_millis(gpsWeek, gpsTimeInWeek) * 1E3),
            # (uint8_t) ID of the GPS for multiple GPS inputs
            'gps_id': 0,
            # (uint16_t) Flags indicating which fields to ignore (see GPS_INPUT_IGNORE_FLAGS enum). All other fields must be provided.
            'ignore_flags': 0,
            # (uint32_t) GPS time (MILLISECONDS from start of GPS week)
            'time_week_ms': int(gpsTimeInWeek * 1E3),
            # (uint16_t) GPS week number
            'time_week': int(gpsWeek),                        
            # (uint8_t) 0-1: no fix, 2: 2D fix, 3: 3D fix. 4: 3D with DGPS. 5: 3D with RTK
            'fix_type': 3,
            # (int32_t) Latitude (WGS84), in degrees * 1E7
            'lat': round(POS[0]),
            # (int32_t) Longitude (WGS84), in degrees * 1E7
            'lon': round(POS[1]),
            # (float) Altitude (AMSL, not WGS84), in m (positive for up)
            'alt': round(ALT),
            # (float) GPS HDOP horizontal dilution of position in m
            'hdop': 1,
            # (float) GPS VDOP vertical dilution of position in m
            'vdop': 1,
            # (float) GPS velocity in m/s in NORTH direction in earth-fixed NED frame
            'vn': 0,
            # (float) GPS velocity in m/s in EAST direction in earth-fixed NED frame
            've': 0,
            # (float) GPS velocity in m/s in DOWN direction in earth-fixed NED frame
            'vd': -1,
            # (float) GPS speed accuracy in m/s
            'speed_accuracy': 0,
            # (float) GPS horizontal accuracy in m
            'horiz_accuracy': 2,
            # (float) GPS vertical accuracy in m
            'vert_accuracy': 2,
            # (uint8_t) Number of satellites visible.
            'satellites_visible': 13
        }

        # Prepare the data to send to the FMU, and send it
        try:
            s.sendto(json.dumps(data).encode(), out_addr)
        except:
            print("Can't send the GPS data - exiting.")
            end.set()

# ================================================================================ #

# Allow for the user to update the GPS offset while the program is running
def offsetThread():
    global OFFSET
    global TIMEOUT

    while not end.is_set():

        # Get the spoofed time to show to the user
        unixNow = int(time.time()) + OFFSET if MODE == 0 else OFFSET
        datetime = glp.unix_millis_to_datetime(unixNow * 1E3)

        # Wait until  the user wants to update the GPS time
        toUpdate = input(
            f"""
The GPS time is currently {datetime.strftime('%d %B, %Y %H:%M:%S')}. This is currently being sent every {TIMEOUT} second(s).

Enter a GPS {'offset' if MODE == 0 else 'time'} in seconds to change the current date and time.

Press "k" to toggle the timeout.

For example, 86400 would be 1 day.

Press ENTER to exit.

 """)
        
        # If they just press ENTER, then exit the program
        if(toUpdate == ""):
            end.set()
            break
        
        # Toggle the timeout
        elif(toUpdate == "k"):
            TIMEOUT = 1 if TIMEOUT == MIN_TIMEOUT else MIN_TIMEOUT

        else:
            # Update the offset
            OFFSET = int(toUpdate)

            # Force a disconnection and then a reconnection by changing the timeout
            OLD_TIMEOUT = TIMEOUT
            TIMEOUT = DISCONNECTION_TIME
            print("Disconnecting...")
            time.sleep(TIMEOUT)
            print("Reconnecting...")
            TIMEOUT = OLD_TIMEOUT



# ================================================================================ #

# Allow for the user to update the GPS location while the program is running
def positionThread():
    global POS, ALT

    pygame.init()
    pygame.display.set_mode((500, 500))
    pygame.display.set_caption("GPS Spoofing Control")
    pygame.event.clear()

    while not end.is_set():

        lastKey = None

        # Get the spoofed time to show to the user
        unixNow = int(time.time()) + OFFSET if MODE == 0 else OFFSET
        datetime = glp.unix_millis_to_datetime(unixNow * 1E3)

        event = pygame.event.wait()
        if event.type == pygame.KEYDOWN:
            lastKey = event.key
            while True:
                if lastKey == pygame.K_ESCAPE:
                    pygame.display.quit()
                    return
                if lastKey == pygame.K_UP:
                    POS[0] += GPS_CHANGE_RATE * TIMEOUT
                    print("UP")
                if lastKey == pygame.K_LEFT:
                    POS[1] -= GPS_CHANGE_RATE * TIMEOUT
                    print("LEFT")
                if lastKey == pygame.K_RIGHT:
                    POS[1] += GPS_CHANGE_RATE * TIMEOUT
                    print("RIGHT")
                if lastKey == pygame.K_DOWN:
                    POS[0] -= GPS_CHANGE_RATE * TIMEOUT
                    print("DOWN")
                if lastKey in [pygame.K_PLUS, pygame.K_KP_PLUS]:
                    print("ALT: ", ALT)
                    ALT += GPS_CHANGE_RATE * TIMEOUT
                if lastKey in [pygame.K_MINUS, pygame.K_KP_MINUS]:
                    print("ALT: ", ALT)
                    ALT -= GPS_CHANGE_RATE * TIMEOUT

                # Keep circling until a new keyup event
                event = pygame.event.poll()
                time.sleep(TIMEOUT)

                if event.type == pygame.KEYUP:
                    break            
            
        if event.type == pygame.QUIT:
            pygame.display.quit()
            return
# ================================================================================ #

# Spin off all the loops and start the program
thread1 = Thread(target=gpsThread)
thread2 = Thread(target=offsetThread)
thread3 = Thread(target=positionThread)
thread1.start()
thread2.start()
thread3.start()
thread1.join()
thread2.join()
thread3.join()
