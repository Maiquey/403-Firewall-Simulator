import sys

def read_packets(filename):
    packets = []

    with open(filename, 'r') as file:
        lines = file.readlines()

    byte_string = ""
    for rawLine in lines:
        line = rawLine.strip()
        if line.isdigit():
            if byte_string != "":
                byte_array = bytes.fromhex("".join(byte_string))
                packets.append(byte_array)
            byte_string = ""
        else:
            hexes = line.split(":")[1].strip()
            byte_string = byte_string + hexes

    if byte_string != "":
        byte_array = bytes.fromhex("".join(byte_string))
        packets.append(byte_array)

    return packets

# personal print function purely for testing and debugging
def myPrint(string):
    # print(string)
    test = 1

def main():
    if len(sys.argv) != 3:
        print("Use: python3 filter.py <option> <filename>")
        return

    option = sys.argv[1]
    file_name = sys.argv[2]

    packets = read_packets(file_name)

    #subnet 142.58.22.0/24
    subnet_prefix = '100011100011101000010110'
    broadcast_address = '10001110001110100001011011111111'

    if option == "-i":

        for packet in packets:

            source_address = ''.join(f'{byte:08b}' for byte in packet[12:16])
            destination_address = ''.join(f'{byte:08b}' for byte in packet[16:20])

            if subnet_prefix == source_address[0:24] and subnet_prefix != destination_address[0:24]:
                print("no")
            else:
                print("yes")

    elif option == "-j":
        for packet in packets:
            if int(packet[9]) == 1:
                icmp_type = int(packet[20])
                if icmp_type == 8:
                    destination_address = ''.join(f'{byte:08b}' for byte in packet[16:20])
                    # print(destination_address)
                    if destination_address == broadcast_address:
                        print("yes")
                    if destination_address[0:24] == subnet_prefix:
                        length = packet[2:4]
                        length = int(''.join(f'{byte:08b}' for byte in packet[2:4]), 2)
                        offset = int(''.join(f'{byte:08b}' for byte in packet[6:8])[3:], 2)*8 #cut off first 3 bits
                        if offset + length > 65535:
                            print("yes")
                        else:
                            print("no")
                    else:
                        print("no")
                else:
                    print("no")
            else:
                print("no")

    elif option == "-k":
        # If single outside IP attempts to half-open more than 10 connections with a host in the subnet,
        # filter out all further SYN packets until the total number of half-open connections is reduced below 10

        # ASSUMPTIONS

        # Assume that a host on our subnet is a (destination_address, destination port)

        # If a SINGLE IP attempts to half-open more than 10 connections with a host, all further SYN packets are dropped
        # until the number of half-open connections to that host is reduced below 10

        # This means that the only way for a specific counter on a specific port in our subnet to reach 10 half-connections
        # is if a single outside IP address uses 10 different ports to open half connections with the our single subnet port

        # we can keep track of each counter in a dictionary. Each counter has a key (destination_address, destination_port, source_address)
        # so connections = {(destination_address, destination_port, source_address):[source_port]}
        # the values attached to each key is a list of ports that are connected (or half-connected) on the source_address
        incoming_half_open_connections = {}
        outgoing_half_open_connections = {}
        open_connections = []
        # flooded = False

        i = 1
        for packet in packets:
            if int(packet[9]) == 6:
                incoming_packet = False
                source_address = hex(int(''.join(f'{byte:08b}' for byte in packet[12:16]), 2))
                destination_address = hex(int(''.join(f'{byte:08b}' for byte in packet[16:20]), 2))
                source_port = hex(int(''.join(f'{byte:08b}' for byte in packet[20:22]), 2))
                destination_port = hex(int(''.join(f'{byte:08b}' for byte in packet[22:24]), 2))
                # sequence number packet[24:28]
                # ack number packet[28:32]
                flag_bits = (f'{packet[33]:08b}')
                SYN = int(flag_bits[6])
                ACK = int(flag_bits[3])
                RST = int(flag_bits[5])
                FIN = int(flag_bits[7])

                if subnet_prefix == ''.join(f'{byte:08b}' for byte in packet[16:20])[0:24]:
                    incoming_packet = True

                half_connection_key = (destination_address, destination_port, source_address)
                source_connection_point = (source_address, source_port)
                dest_connection_point = (destination_address, destination_port)
                full_connection = frozenset([source_connection_point, dest_connection_point])

                # RST/FIN
                if RST == 1 or FIN == 1:
                    # cut the connection half or full
                    # reverse the source and destination because FIN and RST come from the other side
                    if full_connection in open_connections:
                        open_connections.remove(full_connection)
                        print("no")
                        myPrint(str(i) + " - " + "removed full connection")
                    elif incoming_packet:
                        if half_connection_key in incoming_half_open_connections:
                            source_ports = incoming_half_open_connections[half_connection_key]
                            if source_port in source_ports:
                                source_ports.remove(source_port)
                                incoming_half_open_connections[half_connection_key] = source_ports
                                print("no")
                                myPrint(str(i) + " - " + "removed incoming half connection")
                            else:
                                print("no")
                                myPrint(str(i) + " - " + "no half-connection found")
                        else:
                            print("no")
                            myPrint(str(i) + " - " + "no half-connection found 2")
                    else:
                        if half_connection_key in outgoing_half_open_connections:
                            source_ports = outgoing_half_open_connections[half_connection_key]
                            if source_port in source_ports:
                                source_ports.remove(source_port)
                                outgoing_half_open_connections[half_connection_key] = source_ports
                                print("no")
                                myPrint(str(i) + " - " + "removed outgoing half connection")
                            else:
                                print("no")
                                myPrint(str(i) + " - " + "no half-connection found")
                        else:
                            print("no")
                            myPrint(str(i) + " - " + "no half-connection found 2")




                    # elif half_connection_key in incoming_half_open_connections:
                    #     source_ports = half_open_connections[half_connection_key]
                    #     if source_port in source_ports:
                    #         source_ports.remove(source_port)
                    #         incoming_half_open_connections[half_connection_key] = source_ports
                    #         print("no")
                    #         myPrint(str(i) + " - " + "removed half connection")
                    #     else:
                    #         print("no")
                    #         myPrint(str(i) + " - " + "no half-connection found")
                    # elif half_connection_key in outgoing_half_open_connections:
                    # else:
                    #     print("no")
                    #     myPrint(str(i) + " - " + "no connection found")
                # SYN msg
                elif SYN == 1 and ACK == 0:
                    # add half-open connection
                    if full_connection in open_connections:
                        print("no")
                        myPrint("duplicate open connection")
                    elif incoming_packet:
                        if half_connection_key in incoming_half_open_connections:
                            source_ports = incoming_half_open_connections[half_connection_key]
                            if source_port in source_ports:
                                print("no")
                                myPrint(str(i) + " - " + "duplicate half-open connection")
                            elif len(source_ports) == 10:
                                print("yes")
                                myPrint(str(i) + " - " + "tried to open >10 connections")
                            else:
                                source_ports.append(source_port)
                                incoming_half_open_connections[half_connection_key] = source_ports
                                print("no")
                                myPrint(str(i) + " - " + "half-open connection added")
                        else:
                            #create half connection
                            incoming_half_open_connections[half_connection_key] = [source_port]
                            print("no")
                            myPrint(str(i) + " - " + "half-open connection added")
                    else:
                        if half_connection_key in outgoing_half_open_connections:
                            source_ports = outgoing_half_open_connections[half_connection_key]
                            if source_port in source_ports:
                                print("no")
                                myPrint(str(i) + " - " + "duplicate half-open connection")
                            else:
                                source_ports.append(source_port)
                                outgoing_half_open_connections[half_connection_key] = source_ports
                                print("no")
                                myPrint(str(i) + " - " + "half-open connection added")
                        else:
                            #create half connection
                            outgoing_half_open_connections[half_connection_key] = [source_port]
                            print("no")
                            myPrint(str(i) + " - " + "half-open connection added")

                # SYN-ACK
                elif SYN == 1 and ACK == 1:
                    print("no")
                    myPrint(str(i) + " - " + "SYNC ACK")
                # ACK
                elif SYN == 0 and ACK == 1:
                    # ACK msg, make full from half-connection
                    if full_connection in open_connections:
                        print("no")
                        myPrint(str(i) + " - " + "ACK but full connection already established")
                    elif incoming_packet:
                        if half_connection_key in incoming_half_open_connections:
                            source_ports = incoming_half_open_connections[half_connection_key]
                            if source_port in source_ports:
                                #remove it from the list of ports
                                source_ports.remove(source_port)
                                incoming_half_open_connections[half_connection_key] = source_ports
                                #add full connection
                                open_connections.append(full_connection)
                                print("no")
                                myPrint(str(i) + " - " + "full connection established")
                        else:
                            print("no")
                            myPrint(str(i) + " - " + "garbage ACK")
                    else:
                        if half_connection_key in outgoing_half_open_connections:
                            source_ports = outgoing_half_open_connections[half_connection_key]
                            if source_port in source_ports:
                                #remove it from the list of ports
                                source_ports.remove(source_port)
                                outgoing_half_open_connections[half_connection_key] = source_ports
                                #add full connection
                                open_connections.append(full_connection)
                                print("no")
                                myPrint(str(i) + " - " + "full connection established")
                        else:
                            print("no")
                            myPrint(str(i) + " - " + "garbage ACK")
                else:
                    print("no")
                    myPrint(str(i) + " - " + "Not a SYN, ACK, FIN or RST")
            else:
                print("no")
                myPrint(str(i) + " - " + "Not a TCP msg")
            i += 1
    else:
        print("Invalid option")

if __name__ == "__main__":
    main()

