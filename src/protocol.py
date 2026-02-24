import struct

# protocol constants
PAYLOAD_SIZE    = 1024 # mathematically, we can use until 1456 before mag ip fragmentation
PACKET_SIZE     = PAYLOAD_SIZE + 16 # 1040 bytes
TIMEOUT         = 0.5 # 500 ms
MAX_RETRIES     = 10

# message types
MSG_SYN         = 0x00
MSG_SYN_ACK     = 0x01
MSG_ACK         = 0x02
MSG_DATA        = 0x03
MSG_FIN         = 0x04
MSG_FIN_ACK     = 0x05
MSG_ERROR       = 0x06

# error codes
ERR_FILE_NOT_FOUND  = 0x01
ERR_BAD_REQUEST     = 0x02
ERR_SESSION_MISMATCH= 0x03
ERR_TIMEOUT_ABORT   = 0x04
ERR_INTERNAL_ERROR  = 0x05

# flags
FLAG_NONE       = 0x00
FLAG_EOF        = 0x01

# header format
HEADER_FORMAT   = '!B B I I I H'
HEADER_SIZE     = struct.calcsize(HEADER_FORMAT)  

SYN_PAYLOAD_FORMAT = '!B H B'
ERR_PAYLOAD_FORMAT = '!B B'
SYN_ACK_PAYLOAD_FORMAT = '!B H I'

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

# packs the syn payload 
def build_syn_payload(op: int, chunk_size: int, filename: str) -> bytes:
    filename_bytes = filename.encode('utf-8')
    base = struct.pack(SYN_PAYLOAD_FORMAT, op, chunk_size, len(filename_bytes))
    return base + filename_bytes

# unpacks the syn payload
def parse_syn_payload(payload: bytes) -> dict:
    op, chunk_size, name_len = struct.unpack(SYN_PAYLOAD_FORMAT, payload[:4])
    filename = payload[4:4+name_len].decode('utf-8')
    return {'op': op, 'chunk_size': chunk_size, 'filename': filename}

# packs the error payload
def build_err_payload(err_code: int, msg: str) -> bytes:
    msg_bytes = msg.encode('utf-8')
    base = struct.pack(ERR_PAYLOAD_FORMAT, err_code, len(msg_bytes))
    return base + msg_bytes

# unpacks the error payload
def parse_err_payload(payload: bytes) -> dict:
    err_code, msg_len = struct.unpack(ERR_PAYLOAD_FORMAT, payload[:2])
    msg = payload[2:2+msg_len].decode('utf-8')
    return {'error_code': err_code, 'msg': msg}

# packs the syn ack payload
def build_syn_ack_payload(status: int, chunk_size: int, isn: int) -> bytes:
    return struct.pack(SYN_ACK_PAYLOAD_FORMAT, status, chunk_size, isn)

# unpacks the syn ack payload
def parse_syn_ack_payload(payload: bytes) -> dict:
    status, chunk_size, isn = struct.unpack(SYN_ACK_PAYLOAD_FORMAT, payload[:7])
    return {'status': status, 'chunk_size': chunk_size, 'isn': isn}

# just makes the types a string for easier readability sa terminal
def type_to_str(msg_type: int) -> str:
    names = {
        MSG_SYN:     'SYN',
        MSG_SYN_ACK: 'SYN_ACK',
        MSG_ACK:     'ACK',
        MSG_DATA:    'DATA',
        MSG_FIN:     'FIN',
        MSG_FIN_ACK: 'FIN_ACK',
        MSG_ERROR:   'ERROR',
    }
    return names.get(msg_type, f'UNKNOWN(0x{msg_type:02x})')