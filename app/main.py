import socket


def decode_name(buf: bytes, offset: int) -> tuple[list[bytes], int]:
    labels = []
    next_offset = offset
    jumped = False

    while True:
        length = buf[offset]

        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = pointer
            continue

        if length == 0:
            if not jumped:
                next_offset = offset + 1
            break

        offset += 1
        labels.append(buf[offset:offset + length])
        offset += length

    return labels, next_offset


def encode_name(labels: list[bytes]) -> bytes:
    return b"".join(len(label).to_bytes(1, byteorder="big") + label for label in labels) + b"\x00"


def parse_questions(buf: bytes, qdcount: int) -> tuple[bytes, list[tuple[bytes, int, int]]]:
    offset = 12
    question_section = b""
    questions = []

    for _ in range(qdcount):
        labels, offset = decode_name(buf, offset)
        qname = encode_name(labels)
        qtype = int.from_bytes(buf[offset:offset + 2], byteorder="big")
        qclass = int.from_bytes(buf[offset + 2:offset + 4], byteorder="big")
        offset += 4

        question_section += qname + qtype.to_bytes(2, byteorder="big") + qclass.to_bytes(2, byteorder="big")
        questions.append((qname, qtype, qclass))

    return question_section, questions


def build_answer_section(questions: list[tuple[bytes, int, int]]) -> bytes:
    answers = b""

    for qname, _, qclass in questions:
        answers += (
            qname
            + (1).to_bytes(2, byteorder="big")
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
