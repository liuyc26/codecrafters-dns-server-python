import socket


def parse_questions(buf: bytes, qdcount: int) -> tuple[bytes, list[tuple[int, bytes, int, int]]]:
    offset = 12
    questions = []

    for _ in range(qdcount):
        name_start = offset

        while buf[offset] != 0:
            offset += 1 + buf[offset]

        offset += 1  # null terminator
        qname = buf[name_start:offset]
        qtype = int.from_bytes(buf[offset:offset + 2], byteorder="big")
        qclass = int.from_bytes(buf[offset + 2:offset + 4], byteorder="big")
        offset += 4

        questions.append((name_start, qname, qtype, qclass))

    return buf[12:offset], questions


def build_answer_section(questions: list[tuple[int, bytes, int, int]]) -> bytes:
    answers = b""

    for name_start, _, qtype, qclass in questions:
        answers += (
            (0xC000 | name_start).to_bytes(2, byteorder="big")
            + qtype.to_bytes(2, byteorder="big")
            + qclass.to_bytes(2, byteorder="big")
            + (60).to_bytes(4, byteorder="big")  # TTL
            + (4).to_bytes(2, byteorder="big")  # RDLENGTH for IPv4
            + bytes([8, 8, 8, 8])  # RDATA
        )

    return answers


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
            qdcount = int.from_bytes(buf[4:6], byteorder="big") # 16 bits - Question Count (QDCOUNT): Number of questions in the Question section.
            nscount = int.from_bytes(buf[8:10], byteorder="big") # 16 bits - Authority Record Count (NSCOUNT): Number of records in the Authority section.
            arcount = int.from_bytes(buf[10:12], byteorder="big") # 16 bits - Additional Record Count (ARCOUNT): Number of records in the Additional section.

            # Extract flags from request
            opcode = (buf[2] >> 3)& 0x0F
            rd = buf[2]& 0x01

            # Set RCODE based on OPCODE
            if opcode == 0:
                rcode = 0
            else:
                rcode = 4
            
            # Build response flags
            flags = (0x80 << 8) | (opcode << 11) | (rd << 8) | rcode

            # question section
            question_section, questions = parse_questions(buf, qdcount)

            # answer section
            ancount = qdcount
            answer_section = build_answer_section(questions)

            response = (
                packet_id.to_bytes(2, byteorder="big")
                + flags.to_bytes(2, byteorder="big")
                + qdcount.to_bytes(2, byteorder="big")
                + ancount.to_bytes(2, byteorder="big")
                + nscount.to_bytes(2, byteorder="big")
                + arcount.to_bytes(2, byteorder="big")
                + question_section
                + answer_section
            )
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
