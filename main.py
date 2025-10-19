#!/usr/bin/env python3

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

message_bits = (
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
# print(message_bits)
if message_bits.startswith("0"):
    message_bits = "1" + message_bits[1:]
message_hex = format(int(message_bits, 2), "x")
# print(message_hex)
