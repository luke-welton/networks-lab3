#!/usr/bin/env python

import socket
import sys
import os


def byte_to_int(byte):
    integer = 0
    for b in byte:
        integer += ord(b)
    return int(integer)


def int_to_byte(value, length):
    result = []
    for i in range(0, length):
        result.append(value >> (i * 8) & 0xff)

    result.reverse()
    return result

def main(argv):
    try:
        master_hostname = argv[1]
        master_port = argv[2]  # for us this should be 10075
    except:
        print("Invalid arguments.")
        sys.exit()

    # Send Join Ring Request
    s_join = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_join.connect((master_hostname, int(master_port)))
    
    request = ''.join(chr(x) for x in [0x0D, 0x4A, 0x6F, 0x79, 0x21])
    s_join.sendall(request.encode())

    response = s_join.recv(4096)
    s_join.close()

    print(response)

    # Set self as slave node on ring and get ring ID
    master_gid = byte_to_int(response[0])
    magic_number = str(response[1]) + str(response[2]) + str(response[3]) + str(response[4])
    this_rid = byte_to_int(response[5])
    # nextSlaveIP = int(str(response[6]) + str(response[7]) + str(response[8]) + str(response[9]))
    next_slave_pretty = str(byte_to_int(response[6])) + "." + str(byte_to_int(response[7])) + "." + str(byte_to_int(response[8])) + "." + str(byte_to_int(response[9]))

    # Display the GID of master, own ring ID, and the IP address of next slave
    print("Master GID: ", master_gid)
    print("My Ring ID: ", this_rid)
    print("Next Slave: ", next_slave_pretty)

    # Threading
    new_ref = os.fork()
    if new_ref == 0:
        while True:
            # Prompt user for a ring ID and message
            new_rid = ""
            while new_rid == "":
                raw_rid = raw_input('Enter a Ring ID: ')
                try:
                    new_rid = int(raw_rid)
                except:
                    new_rid = ""
                    print("Invalid Ring ID")
            raw_message = ""
            while raw_message == "":
                raw_message = raw_input('Enter your message: ')
                if len(raw_message) > 64:
                    print("Message too long. Try again.")
                    raw_message = ""

            # Calculate Checksum
            sum = checksum_add(0x0D, 0x4A)
            sum = checksum_add(sum, 0x6f)
            sum = checksum_add(sum, 0x79)
            sum = checksum_add(sum, 0x21)
            sum = checksum_add(sum, 0xFF)
            sum = checksum_add(sum, new_rid)
            sum = checksum_add(sum, this_rid)
            for letter in raw_message:
                sum = checksum_add(sum, byte_to_int(letter))

            # Send message to node

            new_message = ''.join(chr(x) for x in [0x0D, 0x4A, 0x6F, 0x79, 0x21])  # This GID, Magic Number
            new_message = new_message + ''.join(chr(x) for x in [0xFF])  # TTL
            new_message = new_message + ''.join(chr(x) for x in int_to_byte(new_rid, 1)) # RID Destination
            new_message = new_message + ''.join(chr(x) for x in int_to_byte(this_rid, 1))  # RID Source
            new_message = new_message + ''.join(chr(x) for x in raw_message)  # Message
            new_message = new_message + ''.join(chr(x) for x in int_to_byte(sum, 1))  # Checksum

            s_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_send.connect((next_slave_pretty, int(10010 + master_gid * 5 + this_rid - 1)))
            s_send.sendall(new_message)
            s_send.close()

    else:
        # Forwarding server
        s_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_server.bind(('', int(10010 + master_gid * 5 + this_rid)))

        while True:
            incoming_message, address = s_server.recvfrom(4096)
            in_gid = incoming_message[0]
            in_magic = str(incoming_message[1]) + str(incoming_message[2]) + str(incoming_message[3]) + str(incoming_message[4])
            in_ttl = byte_to_int(incoming_message[5])
            in_dest = byte_to_int(incoming_message[6])
            in_src = incoming_message[7]
            in_msg = ""
            for i in range(8, len(incoming_message) - 1):
                in_msg = in_msg + incoming_message[i]
            in_check = incoming_message[len(incoming_message) - 1]

            # Validate checksum
            sum = checksum_add(int(incoming_message[0]), int(incoming_message[1]))
            sum = checksum_add(sum, byte_to_int(incoming_message[2]))
            sum = checksum_add(sum, byte_to_int(incoming_message[3]))
            sum = checksum_add(sum, byte_to_int(incoming_message[4]))
            sum = checksum_add(sum, byte_to_int(incoming_message[5]))
            sum = checksum_add(sum, byte_to_int(incoming_message[6]))
            sum = checksum_add(sum, byte_to_int(incoming_message[7]))
            for i in range(8, len(incoming_message) - 1):
                sum = checksum_add(sum, byte_to_int(incoming_message[i]))

            if sum == in_check:
                if in_dest == this_rid:  # Display any message addressed to this node
                    print(str(in_msg))
                elif in_ttl > 1:
                    in_ttl = in_ttl - 1
                    # Recalculate checksum
                    new_sum = checksum_add(int(incoming_message[0]), int(incoming_message[1]))
                    new_sum = checksum_add(new_sum, byte_to_int(incoming_message[2]))
                    new_sum = checksum_add(new_sum, byte_to_int(incoming_message[3]))
                    new_sum = checksum_add(new_sum, byte_to_int(incoming_message[4]))
                    new_sum = checksum_add(new_sum, byte_to_int(incoming_message[5]) - 1)
                    new_sum = checksum_add(new_sum, byte_to_int(incoming_message[6]))
                    new_sum = checksum_add(new_sum, byte_to_int(incoming_message[7]))
                    for i in range(8, len(incoming_message) - 1):
                        new_sum = checksum_add(new_sum, byte_to_int(incoming_message[i]))

                    # Forward any other packet with TTL > 1
                    forward = ''.join(chr(x) for x in in_gid)
                    forward = forward + ''.join(chr(x) for x in in_magic)
                    forward = forward + ''.join(chr(x) for x in in_ttl)
                    forward = forward + ''.join(chr(x) for x in in_dest)
                    forward = forward + ''.join(chr(x) for x in in_src)
                    forward = forward + ''.join(chr(x) for x in in_msg)
                    forward = forward + ''.join(chr(x) for x in new_sum)

                    s_forward = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s_forward.connect((next_slave_pretty, int(10010 + master_gid * 5 + this_rid - 1)))
                    s_forward.sendall(forward)
                    s_forward.close()

def checksum_add(arg1, arg2):
    sum = arg1 + arg2
    if sum > 0xFF:
        sum = sum - 0x100
        sum = sum + 0x1
    return sum


if __name__ == '__main__':

    main(sys.argv)
