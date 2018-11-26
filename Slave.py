#!/usr/bin/env python

import socket
import sys


def byte_to_int(byte):
    integer = 0
    for b in byte:
        integer += ord(b)
    return int(integer)


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
    
    request = ''.join(chr(x) for x in [13, 0x4A, 0x6F, 0x79, 0x21])
    s_join.sendall(request)

    response = s.recv(4096)

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

    # Prompt user for a ring ID and message
    new_rid = ""
    while new_rid == "":
        raw_rid = raw_input('Enter a Ring ID: ')
        try:
            new_rid = int(raw_rid)
        except:
            new_rid = ""
            print("Invalid Ring ID")
    raw_message = raw_input('Enter your message: ')

    # TODO: Send message to node
    s_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_send.connect((next_slave_pretty, int(10010 + master_gid * 5 + this_rid - 1)))
    new_message = ''.join(chr(x) for x in [13, 0x4A, 0x6F, 0x79, 0x21])  # This GID, Magic Number

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

        # TODO: Validate checksum

        if in_dest == this_rid:
            # TODO: Display any packet addressed to this node
            print(incoming_message)
        elif in_ttl > 1:
            # TODO: Forward any other packet with TTL > 1
            s_forward = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_forward.connect((next_slave_pretty, int(10010 + master_gid * 5 + this_rid - 1)))


if __name__ == '__main__':

    print(byte_to_int(''))

    main(sys.argv)
