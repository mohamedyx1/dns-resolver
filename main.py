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


def slice(start, size, as_int=True, increment_start=True):
    """return slice either as bits string or int, and new/current start"""
    bits = response_bits[start : start + size]
    if increment_start:
        start += size
    if as_int:
        return int(bits, 2), start
    return bits, start


# id, flags
start = 0
ID, start = slice(start, 16)
assert ID == 22

qr, start = slice(start, 1, as_int=False)
assert qr == "1"

opcode, start = slice(start, 4, as_int=False)
assert opcode == "0000"

aa, start = slice(start, 1, as_int=False)
tc, start = slice(start, 1, as_int=False)
rd, start = slice(start, 1, as_int=False)
ra, start = slice(start, 1, as_int=False)
z, start = slice(start, 3, as_int=False)
rcode, start = slice(start, 4, as_int=False)

# print(f"{ID=}")
# print(f"{qr=}")
# print(f"{opcode=}")
# print(f"{aa=}")
# print(f"{tc=}")
# print(f"{rd=}")
# print(f"{ra=}")
# print(f"{z=}")
# print(f"{rcode=}")

# counts
qdcount, start = slice(start, 16)
ancount, start = slice(start, 16)
nscount, start = slice(start, 16)
arcount, start = slice(start, 16)

print(f"{qdcount=}")
print(f"{ancount=}")
print(f"{nscount=}")
print(f"{arcount=}")

# question
qname = []
while True:
    length_octet, start = slice(start, 8)
    # print(f"{length_octet=}")
    # null label is 0-length octet
    if length_octet == 0:
        break
    for _ in range(length_octet):
        ordinal, start = slice(start, 8)
        char = chr(ordinal)
        # print(char)
        qname.append(char)
    qname.append(".")
qname = "".join(qname).rstrip(".")

qtype, start = slice(start, 16)
qclass, start = slice(start, 16)

print(f"{qname=}")
print(f"{qtype=}")
print(f"{qclass=}")

# answer
for _ in range(ancount):
    # pointer
    size = 2
    prefix, start = slice(start, 2, as_int=False, increment_start=False)
    if prefix == "11":
        prefix, start = slice(start, 2, as_int=False)
        offset, start = slice(start, 14)
        print(f"{offset=}")

        # name + pointer
        another_start = offset * 8
        name = []
        while True:
            length_octet, another_start = slice(another_start, 8)
            # print(f"{length_octet=}")
            # null label is 0-length octet
            if length_octet == 0:
                break
            for _ in range(length_octet):
                ordinal, another_start = slice(another_start, 8)
                char = chr(ordinal)
                # print(char)
                name.append(char)
            name.append(".")
        name = "".join(name).rstrip(".")
        print(f"{name=}")
    else:
        # name
        name = []
        while True:
            length_octet, start = slice(start, 8)
            # print(f"{length_octet=}")
            # null label is 0-length octet
            if length_octet == 0:
                break
            for _ in range(length_octet):
                ordinal, start = slice(start, 8)
                char = chr(ordinal)
                # print(char)
                name.append(char)
            name.append(".")
        name = "".join(name).rstrip(".")
        print(f"{name=}")

    type_, start = slice(start, 16)
    class_, start = slice(start, 16)
    ttl, start = slice(start, 32)
    rdlength, start = slice(start, 16)

    rdata = []
    for _ in range(rdlength):
        n, start = slice(start, 8)
        rdata.append(n)
    rdata = ".".join(map(str, rdata))

    print(f"{name=}")
    # print(f"{type_=}")
    # print(f"{class_=}")
    # print(f"{ttl=}")
    print(f"{rdlength=}")
    print(f"{rdata=}")


# authority
for _ in range(nscount):
    print("parse authority")


# additional
for _ in range(arcount):
    print("parse additional")
