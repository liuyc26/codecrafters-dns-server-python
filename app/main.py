import socket


def parse_question_section(buf: bytes, qdcount: int) -> bytes:
    offset = 12

    for _ in range(qdcount):
        # QNAME is a sequence of length-prefixed labels terminated by a zero byte.
        while buf[offset] != 0:
            offset += 1 + buf[offset]

        offset += 1  # null terminator
        offset += 4  # QTYPE (2 bytes) + QCLASS (2 bytes)

    return buf[12:offset]


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # Uncomment the code below to pass the first stage
    #
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            # header section
            packet_id = int.from_bytes(buf[0:2], byteorder="big") # 16 bits - Packet Identifier (ID): A random ID assigned to query packets. Response packets must reply with the same ID.
            flags = int.from_bytes(buf[2:4], byteorder="big") #  1 bit - Query/Response Indicator (QR), 4 bits - Operation Code (OPCODE), 1 bit - Authoritative Answer (AA), 1 bit - Truncation (TC), 1 bit - Recursion Desired (RD), 1 bit - Recursion Available (RA), 3 bits - Reserved (Z), 4 bits - Response Code (RCODE)
            qdcount = int.from_bytes(buf[4:6], byteorder="big") # 16 bits - Question Count (QDCOUNT): Number of questions in the Question section.
            ancount = int.from_bytes(buf[6:8], byteorder="big") # 16 bits - Answer Record Count (ANCOUNT): Number of records in the Answer section.
            nscount = int.from_bytes(buf[8:10], byteorder="big") # 16 bits - Authority Record Count (NSCOUNT): Number of records in the Authority section.
            arcount = int.from_bytes(buf[10:12], byteorder="big") # 16 bits - Additional Record Count (ARCOUNT): Number of records in the Additional section.

            flags |= 1 << 15 # set to response flag

            # question section
            question_section = parse_question_section(buf, qdcount)

            response = (
                packet_id.to_bytes(2, byteorder="big")
                + flags.to_bytes(2, byteorder="big")
                + qdcount.to_bytes(2, byteorder="big")
                + ancount.to_bytes(2, byteorder="big")
                + nscount.to_bytes(2, byteorder="big")
                + arcount.to_bytes(2, byteorder="big")
                + question_section
            )
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
