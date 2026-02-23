# logic:

# 1. nakalisten state yung server
# 2. pag dumating yung syn, parse payload to check if get or put 
#   2.1 pag get and file is missing, sends an error
#   2.2 pag no generate a session id and isn and magsesend ng syn ack
# then magloloop yung stop nd wait arq para makasend or receive ng files 
import socket
import os
import random
from protocol import *

SERVER_ADDR = ('127.0.0.1', 8080)

active_sessions = set()  # track active session_ids to avoid collisions

# generate a uniqued session id that is not used
def generate_session_id():
    while True:
        session_id = random.randint(1, 2**32 - 1)
        if session_id not in active_sessions:
            return session_id

def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(SERVER_ADDR)
    print(f"Server listening on {SERVER_ADDR[0]}:{SERVER_ADDR[1]}...")

    try:
        while True:
            # listen state
            packet, client_addr = sock.recvfrom(PACKET_SIZE)
            try:
                parsed = parse_packet(packet)
            except ValueError:
                continue  # drop corrupted / too small na packets

            if parsed['type'] == MSG_SYN and parsed['session_id'] == 0:
                try:
                    syn_data = parse_syn_payload(parsed['payload'])
                except Exception:
                    continue  # drop malformed SYN payloads

                op = syn_data['op']
                filename = syn_data['filename']

                print(f"\n[!] Received SYN from {client_addr}: OP={'PUT' if op == 1 else 'GET'}, File={filename}")

                # check if file exists for get requests
                if op == 0 and not os.path.exists(filename):
                    print(f"[-] File '{filename}' not found. Sending ERROR.")
                    err_payload = build_err_payload(0x01, "File not found")
                    err_packet = build_packet(MSG_ERROR, 0, 0, 0, err_payload)
                    sock.sendto(err_packet, client_addr)
                    continue

               # handshake state — generate unique session_id and ISN
                session_id = generate_session_id()
                isn = random.randint(0, 2**32 - 1)
                active_sessions.add(session_id)

                syn_ack_payload = build_syn_ack_payload(0x00, PAYLOAD_SIZE, isn)
                syn_ack_packet = build_packet(MSG_SYN_ACK, session_id, 0, 0, syn_ack_payload)

                # send SYN_ACK once. if na drop, the client will timeout and resend SYN
                sock.sendto(syn_ack_packet, client_addr)
                print(f"[+] Sent SYN_ACK. Session: {session_id}, ISN: {isn}")

                # proceed sa transfer state
                sock.settimeout(TIMEOUT)
                try:
                    if op == 0:
                        # GET: server sends file
                        server_send_file(sock, client_addr, session_id, isn, filename)
                    elif op == 1:
                        # PUT: server receives file
                        server_receive_file(sock, client_addr, session_id, isn, filename)
                except socket.timeout:
                    print("[-] Transfer timed out. Session dropped.")
                    err_payload = build_err_payload(ERR_TIMEOUT_ABORT, "Timeout abort")
                    err_packet = build_packet(MSG_ERROR, session_id, 0, 0, err_payload)
                    sock.sendto(err_packet, client_addr)

                active_sessions.discard(session_id)
                sock.settimeout(None)  # reset to blocking mode for the next client

    finally:
        sock.close()

def server_send_file(sock, client_addr, session_id, isn, filename):
    # todo: 
    # 1. open file in 'rb' mode
    # 2. read chunks of PAYLOAD_SIZE
    # 3. build MSG_DATA packets
    # 4. wait for MSG_ACK, retransmit on timeout
    # 5. send MSG_FIN when done
    pass

def server_receive_file(sock, client_addr, session_id, isn, filename):
    # todo: 
    # 1. open file in 'wb' mode
    # 2. receive MSG_DATA packets
    # 3. write payload to file, send MSG_ACK
    # 4. handle duplicates or out-of-order packets
    # 5. handle MSG_FIN and send MSG_FIN_ACK
    pass

if __name__ == "__main__":
    start_server()