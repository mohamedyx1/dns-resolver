#!/usr/bin/env python3
import socket

# header: id, flags, counts
ID = format(22, "016b")

qr = "0"
opcode = f"{0:04b}"  # standard query
aa = "0"
tc = "0"
rd = "1"
ra = "0"
z = "000"
rcode = "0000"

qdcount = f"{1:016b}"
ancount = "0" * 16
nscount = f"{0:016b}"
arcount = format(0, "016b")

assert (
    len(
        ID
        + qr
        + opcode
        + aa
        + tc
        + rd
        + ra
        + z
        + rcode
        + qdcount
        + ancount
        + nscount
        + arcount
    )
    == 16 * 6
)

# question: name, type, class
domain = "dns.google.com"
qname = "".join(
    f"{len(part):08b}" + "".join(f"{ord(c):08b}" for c in part)
    for part in f"{domain}.".split(".")
)
qtype = f"{1:016b}"  # 1: a host address
qclass = f"{1:016b}"  # 1: the internet

request_bits = (
    ID
    + qr
    + opcode
    + aa
    + tc
    + rd
    + ra
    + z
    + rcode
    + qdcount
    + ancount
    + nscount
    + arcount
    + qname
    + qtype
    + qclass
)
# print(request_bits)

SWITCH_MSB = False
if request_bits.startswith("0"):
    request_bits = "1" + request_bits[1:]
    SWITCH_MSB = True

request_hex = format(int(request_bits, 2), "x")
# print(request_hex)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.connect_ex(("8.8.8.8", 53))
    s.sendall(bytes.fromhex(request_hex))
    response = s.recv(1024)
response_hex = response.hex()
# print(response_hex)

response_bits = format(int(response_hex, 16), "b")
# response_bits = "10000000000101101000000110000000000000000000000100000000000000100000000000000000000000000000000000000011011001000110111001110011000001100110011101101111011011110110011101101100011001010000001101100011011011110110110100000000000000000000000100000000000000011100000000001100000000000000000100000000000000010000000000000000000000100000010000000000000001000000100000001000000010000000100011000000000011000000000000000001000000000000000100000000000000000000001000000100000000000000010000001000000010000000010000000100"

# print(response_bits)
assert response_bits[:16] == request_bits[:16]

if SWITCH_MSB:
    response_bits = "0" + response_bits[1:]

# id, flags
start, size = 0, 16
ID = int(response_bits[start:size], 2)
assert ID == 22
start += size

size = 1
qr = response_bits[start : start + size]
assert qr == "1"
start += size

size = 4
opcode = response_bits[start : start + size]
start += size
assert opcode == "0000"

size = 1
aa = response_bits[start : start + size]
start += size

size = 1
tc = response_bits[start : start + size]
start += size

size = 1
rd = response_bits[start : start + size]
start += size

size = 1
ra = response_bits[start : start + size]
start += size

size = 3
z = response_bits[start : start + size]
start += size

size = 4
rcode = response_bits[start : start + size]
start += size

print(f"{ID=}")
print(f"{qr=}")
print(f"{opcode=}")
print(f"{aa=}")
print(f"{tc=}")
print(f"{rd=}")
print(f"{ra=}")
print(f"{z=}")
print(f"{rcode=}")

# counts
size = 16
qdcount = int(response_bits[start : start + size], 2)
start += size

ancount = int(response_bits[start : start + size], 2)
start += size

nscount = int(response_bits[start : start + size], 2)
start += size

arcount = int(response_bits[start : start + size], 2)
start += size

print(f"{qdcount=}")
print(f"{ancount=}")
print(f"{nscount=}")
print(f"{arcount=}")

# question
size = 8
qname = []
while True:
    length_octet = int(response_bits[start : start + size], 2)
    start += size
    print(f"{length_octet=}")
    # null label is 0-length octet
    if length_octet == 0:
        break
    for _ in range(length_octet):
        char = chr(int(response_bits[start : start + size], 2))
        print(char)
        start += size
        qname.append(char)
    qname.append(".")
qname = "".join(qname).rstrip(".")

size = 16
qtype = int(response_bits[start : start + size], 2)
start += size

qclass = int(response_bits[start : start + size], 2)
start += size

print(f"{qname=}")
print(f"{qtype=}")
print(f"{qclass=}")


# answer
for _ in range(ancount):
    # pointer
    size = 2
    if response_bits[start : start + size] == "11":
        prefix = response_bits[start : start + size]
        start += size
        size = 14
        offset = int(response_bits[start : start + size], 2)
        print(f"{offset=}")
        start += size

        # name + pointer
        another_start = offset * 8
        size = 8
        name = []
        while True:
            length_octet = int(response_bits[another_start : another_start + size], 2)
            another_start += size
            print(f"{length_octet=}")
            # null label is 0-length octet
            if length_octet == 0:
                break
            for _ in range(length_octet):
                char = chr(int(response_bits[another_start : another_start + size], 2))
                print(char)
                another_start += size
                name.append(char)
            name.append(".")
        name = "".join(name).rstrip(".")
        print(f"{name=}")
    else:
        # name
        size = 8
        name = []
        while True:
            length_octet = int(response_bits[start : start + size], 2)
            start += size
            print(f"{length_octet=}")
            # null label is 0-length octet
            if length_octet == 0:
                break
            for _ in range(length_octet):
                char = chr(int(response_bits[start : start + size], 2))
                print(char)
                start += size
                name.append(char)
            name.append(".")
        name = "".join(name).rstrip(".")
        print(f"{name=}")

    size = 16
    type_ = int(response_bits[start : start + size], 2)
    start += size

    class_ = int(response_bits[start : start + size], 2)
    start += size

    size = 32
    ttl = int(response_bits[start : start + size], 2)
    start += size

    size = 16
    rdlength = int(response_bits[start : start + size], 2)
    start += size

    rdata = []
    for _ in range(rdlength):
        size = 8
        n = int(response_bits[start : start + size], 2)
        rdata.append(n)
        start += size
    rdata = ".".join(map(str, rdata))

    print(f"{name=}")
    print(f"{type_=}")
    print(f"{class_=}")
    print(f"{ttl=}")
    print(f"{rdlength=}")
    print(f"{rdata=}")


# authority
for _ in range(nscount):
    print("parse authority")


# additional
for _ in range(arcount):
    print("parse additional")
