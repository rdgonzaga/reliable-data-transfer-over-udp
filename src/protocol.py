import struct

# protocol constants
PAYLOAD_SIZE    = 1024 
PACKET_SIZE     = PAYLOAD_SIZE + 16
TIMEOUT         = 0.5               # 500 ms
MAX_RETRIES     = 10

# message types
MSG_SYN         = 0x00
MSG_SYN_ACK     = 0x01
MSG_ACK         = 0x02
MSG_DATA        = 0x03
MSG_FIN         = 0x04
MSG_FIN_ACK     = 0x05
MSG_ERR         = 0x06

# flags
FLAG_NONE       = 0x00
FLAG_EOF        = 0x01

# header format
HEADER_FORMAT   = '!B B I I I H'
HEADER_SIZE     = struct.calcsize(HEADER_FORMAT)  



# packs a full protocol packet (header and yung payload)
def build_packet(msg_type: int, session_id: int, seq: int, ack: int,
                 payload: bytes = b'', flags: int = FLAG_NONE) -> bytes:
    header = struct.pack(
        HEADER_FORMAT,
        msg_type,
        flags,
        session_id,
        seq,
        ack,
        len(payload)
    )
    return header + payload

# unpacks a raw udp datagram into a dictionary  
def parse_packet(raw: bytes) -> dict:
    if len(raw) < HEADER_SIZE:
        raise ValueError(f"Packet is too short: {len(raw)} bytes")

    msg_type, flags, session_id, seq, ack, payload_len = struct.unpack(
        HEADER_FORMAT, raw[:HEADER_SIZE]
    )
    payload = raw[HEADER_SIZE: HEADER_SIZE + payload_len]

    return {
        'type':        msg_type,
        'flags':       flags,   
        'session_id':  session_id,  
        'seq':         seq,
        'ack':         ack,
        'payload_len': payload_len,
        'payload':     payload,
    }

# just makes the types a string for easier readability sa terminal
def type_to_str(msg_type: int) -> str:
    names = {
        MSG_SYN:     'SYN',
        MSG_SYN_ACK: 'SYN_ACK',
        MSG_ACK:     'ACK',
        MSG_DATA:    'DATA',
        MSG_FIN:     'FIN',
        MSG_FIN_ACK: 'FIN_ACK',
        MSG_ERR:     'ERR',
    }
    return names.get(msg_type, f'UNKNOWN(0x{msg_type:02x})')