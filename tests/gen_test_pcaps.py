#!/usr/bin/env python3
"""Deterministic pcap fixtures for the tcpflow reassembly / HTTP2 tests.

The script only uses the Python standard library so the fixtures can be
regenerated without scapy or any third-party package:

    python3 gen_test_pcaps.py

It writes three little-endian Ethernet/IPv4 pcap files (LINKTYPE_ETHERNET):

  reassembly-outoforder.pcap  one TCP connection whose data segments are
                              shuffled and contain a retransmission
  http2-streams.pcap          one HTTP/2 (h2c) connection carrying three
                              interleaved streams
  naming-template.pcap        two independent TCP connections used to
                              exercise the output naming template
"""

import os
import struct


PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1

ETH_HDR_LEN = 14
IP_HDR_LEN = 20
TCP_HDR_LEN = 20


def checksum(data):
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | data[offset + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class PcapWriter:
    def __init__(self, path):
        self.path = path
        self.handle = open(path, "wb")
        self.handle.write(struct.pack("<IHHIIII", PCAP_MAGIC, 2, 4, 0, 0,
                                      65535, LINKTYPE_ETHERNET))
        self.ts_sec = 1_700_000_000
        self.ts_usec = 0

    def close(self):
        self.handle.close()

    def _tick(self):
        self.ts_usec += 1000
        if self.ts_usec >= 1_000_000:
            self.ts_sec += 1
            self.ts_usec -= 1_000_000

    def write(self, packet):
        self.handle.write(struct.pack("<IIII", self.ts_sec, self.ts_usec,
                                      len(packet), len(packet)))
        self.handle.write(packet)
        self._tick()


def ethernet(src_mac, dst_mac, payload):
    return (dst_mac + src_mac + struct.pack("!H", 0x0800) + payload)


def ipv4(src, dst, protocol, payload, identification=1):
    src_b = bytes(int(part) for part in src.split("."))
    dst_b = bytes(int(part) for part in dst.split("."))
    total_len = IP_HDR_LEN + len(payload)
    header = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0, total_len, identification, 0, 64,
                         protocol, 0, src_b, dst_b)
    csum = checksum(header)
    header = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0, total_len, identification, 0, 64,
                         protocol, csum, src_b, dst_b)
    return header + payload


def tcp_segment(src, dst, sport, dport, seq, ack, flags, payload=b""):
    """Build an IPv4 TCP segment (no options)."""
    offset_flags = (TCP_HDR_LEN // 4) << 12 | flags
    header = struct.pack("!HHIIHHHH", sport, dport, seq & 0xFFFFFFFF,
                         ack & 0xFFFFFFFF, offset_flags, 8192, 0, 0)
    src_b = bytes(int(part) for part in src.split("."))
    dst_b = bytes(int(part) for part in dst.split("."))
    pseudo = src_b + dst_b + struct.pack("!BBH", 0, 6,
                                         TCP_HDR_LEN + len(payload))
    csum = checksum(pseudo + header + payload)
    header = struct.pack("!HHIIHHHH", sport, dport, seq & 0xFFFFFFFF,
                         ack & 0xFFFFFFFF, offset_flags, 8192, csum, 0)
    return ipv4(src, dst, 6, header + payload)


FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10

CLIENT_MAC = b"\x02\x00\x00\x00\x00\x01"
SERVER_MAC = b"\x02\x00\x00\x00\x00\x02"


class TcpConnection:
    """Minimal stateful TCP endpoint pair that emits full packet traces."""

    def __init__(self, pcap, client, server, sport, dport, isn_c=1000,
                 isn_s=5000):
        self.pcap = pcap
        self.client = client
        self.server = server
        self.sport = sport
        self.dport = dport
        self.isn_c = isn_c
        self.isn_s = isn_s
        self.seq_c = isn_c
        self.seq_s = isn_s

    def _emit(self, segment, from_client):
        if from_client:
            frame = ethernet(CLIENT_MAC, SERVER_MAC, segment)
        else:
            frame = ethernet(SERVER_MAC, CLIENT_MAC, segment)
        self.pcap.write(frame)

    def handshake(self):
        self._emit(tcp_segment(self.client, self.server, self.sport,
                               self.dport, self.isn_c, 0, SYN), True)
        self.seq_c += 1
        self._emit(tcp_segment(self.server, self.client, self.dport,
                               self.sport, self.isn_s, self.seq_c,
                               SYN | ACK), False)
        self.seq_s += 1
        self._emit(tcp_segment(self.client, self.server, self.sport,
                               self.dport, self.seq_c, self.seq_s,
                               ACK), True)

    def client_data(self, data):
        self._emit(tcp_segment(self.client, self.server, self.sport,
                               self.dport, self.seq_c, self.seq_s,
                               PSH | ACK, data), True)
        self.seq_c += len(data)

    def server_data(self, data):
        self._emit(tcp_segment(self.server, self.client, self.dport,
                               self.sport, self.seq_s, self.seq_c,
                               PSH | ACK, data), False)
        self.seq_s += len(data)

    def server_raw(self, seq, ack, flags, data):
        self._emit(tcp_segment(self.server, self.client, self.dport,
                               self.sport, seq, ack, flags, data), False)

    def client_ack(self):
        self._emit(tcp_segment(self.client, self.server, self.sport,
                               self.dport, self.seq_c, self.seq_s,
                               ACK), True)

    def teardown(self):
        self._emit(tcp_segment(self.server, self.client, self.dport,
                               self.sport, self.seq_s, self.seq_c,
                               FIN | ACK), False)
        self.seq_s += 1
        self._emit(tcp_segment(self.client, self.server, self.sport,
                               self.dport, self.seq_c, self.seq_s,
                               ACK), True)
        self._emit(tcp_segment(self.client, self.server, self.sport,
                               self.dport, self.seq_c, self.seq_s,
                               FIN | ACK), True)
        self.seq_c += 1
        self._emit(tcp_segment(self.server, self.client, self.dport,
                               self.sport, self.seq_s, self.seq_c,
                               ACK), False)


def build_reassembly_pcap(path):
    """Out-of-order delivery plus a retransmission, reassembled by sequence."""
    pcap = PcapWriter(path)
    conn = TcpConnection(pcap, "10.0.0.1", "10.0.0.2", 40001, 9000)
    conn.handshake()

    chunks = [b"AAA-1-", b"BBB-2-", b"CCC-3-", b"DDD-4-", b"EEE-5-END"]
    base_seq = conn.seq_c

    def raw_client(seq, data):
        conn._emit(tcp_segment(conn.client, conn.server, conn.sport,
                               conn.dport, seq, conn.seq_s,
                               PSH | ACK, data), True)

    # Deliberately shuffled: 2, 4, 1, 3, 5.
    order = [1, 3, 0, 2, 4]
    offsets = []
    running = 0
    for chunk in chunks:
        offsets.append(running)
        running += len(chunk)
    for index in order:
        raw_client(base_seq + offsets[index], chunks[index])

    # Retransmission of the first segment after the gap was filled.
    raw_client(base_seq, chunks[0])

    conn.seq_c = base_seq + sum(len(chunk) for chunk in chunks)
    conn.client_ack()
    conn.teardown()
    pcap.close()


# HTTP/2 framing (RFC 7540), plaintext h2c without TLS.
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_DATA = 0x0
H2_HEADERS = 0x1
H2_SETTINGS = 0x4
H2_PING = 0x6
H2_FLAG_ACK = 0x1
H2_FLAG_END_STREAM = 0x1
H2_FLAG_END_HEADERS = 0x4


def h2_frame(frame_type, flags, stream_id, payload=b""):
    stream_field = stream_id & 0x7FFFFFFF
    length = len(payload)
    header = bytes(((length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF,
                    frame_type, flags))
    return header + struct.pack("!I", stream_field) + payload


def h2_headers(stream_id, payload):
    return h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, stream_id, payload)


def h2_data(stream_id, payload, end_stream=False):
    flags = H2_FLAG_END_STREAM if end_stream else 0
    return h2_frame(H2_DATA, flags, stream_id, payload)


def build_http2_pcap(path):
    pcap = PcapWriter(path)
    conn = TcpConnection(pcap, "10.1.0.10", "10.1.0.20", 51000, 8443)
    conn.handshake()

    # Client preface and initial SETTINGS.
    conn.client_data(H2_PREFACE + h2_frame(H2_SETTINGS, 0, 0))
    conn.server_data(h2_frame(H2_SETTINGS, H2_FLAG_ACK, 0))
    conn.server_data(h2_frame(H2_PING, 0, 0, b"tcpflow0"))
    conn.client_data(h2_frame(H2_PING, H2_FLAG_ACK, 0, b"tcpflow0"))

    # Three interleaved response streams sent server -> client.
    conn.server_data(
        h2_headers(1, b"h1-stream-1")
        + h2_data(1, b"stream1-part1-"))
    conn.server_data(
        h2_headers(3, b"h3-stream-3")
        + h2_data(3, b"stream3-part1-"))
    conn.server_data(h2_data(1, b"stream1-part2-"))
    conn.server_data(
        h2_headers(5, b"h5-stream-5")
        + h2_data(5, b"stream5-only", end_stream=True))
    conn.server_data(h2_data(3, b"stream3-part2", end_stream=True))
    conn.server_data(h2_data(1, b"stream1-end", end_stream=True))

    conn.client_ack()
    conn.teardown()
    pcap.close()


def build_naming_pcap(path):
    pcap = PcapWriter(path)
    first = TcpConnection(pcap, "172.16.0.1", "172.16.0.2", 41001, 7001,
                          isn_c=2000, isn_s=7000)
    first.handshake()
    first.client_data(b"naming-connection-one")
    first.teardown()

    second = TcpConnection(pcap, "172.16.0.1", "172.16.0.2", 41002, 7002,
                           isn_c=3000, isn_s=8000)
    second.handshake()
    second.client_data(b"naming-connection-two")
    second.teardown()
    pcap.close()


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    build_reassembly_pcap(os.path.join(here, "reassembly-outoforder.pcap"))
    build_http2_pcap(os.path.join(here, "http2-streams.pcap"))
    build_naming_pcap(os.path.join(here, "naming-template.pcap"))


if __name__ == "__main__":
    main()
