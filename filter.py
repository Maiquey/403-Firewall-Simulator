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

    elif option == "-k":
        print("k")
    else:
        print("Invalid option")

if __name__ == "__main__":
    main()

