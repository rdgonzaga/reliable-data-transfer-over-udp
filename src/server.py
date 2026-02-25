import socket
import os
import random
import time
from protocol import *

VERBOSE = False         # for verbose logging mode
SIMULATE_LOSS = False   # for timeout test
LOSS_RATE = 0.2     

SERVER_DIR = "server_files"
if not os.path.exists(SERVER_DIR):
    os.makedirs(SERVER_DIR)

active_sessions = set()  # track active session IDs to avoid collisions

# send a best-effort bad_request error to the given address with unknown session_id = 0
def send_bad_request(sock, client_addr):
    err_payload = build_err_payload(ERR_BAD_REQUEST, "BAD_REQUEST")
    err_pkt = build_packet(MSG_ERROR, 0, 0, 0, err_payload)
    sock.sendto(err_pkt, client_addr)

# notify the sender that their packet belongs to an unknown or mismatched session
def send_session_mismatch(sock, client_addr, wrong_session_id):
    err_pkt = build_packet(MSG_ERROR, wrong_session_id, 0, 0,
                           build_err_payload(ERR_SESSION_MISMATCH, "SESSION_MISMATCH"))
    sock.sendto(err_pkt, client_addr)

# send a timeout-abort error for the given session
def send_timeout_abort(sock, client_addr, session_id):
    err_pkt = build_packet(MSG_ERROR, session_id, 0, 0,
                           build_err_payload(ERR_TIMEOUT_ABORT, "TIMEOUT_ABORT"))
    sock.sendto(err_pkt, client_addr)

# send an ack for the given sequence number
def send_ack(sock, client_addr, session_id, seq):
    ack_pkt = build_packet(MSG_ACK, session_id, 0, seq)
    if SIMULATE_LOSS and random.random() < LOSS_RATE:
        print(f"    [TEST] Intentionally dropped ACK {seq} to trigger retransmission.")
        return
    sock.sendto(ack_pkt, client_addr)

# generate a unique session ID that is not currently active
def generate_session_id():
    while True:
        session_id = random.randint(1, 2**32 - 1)
        if session_id not in active_sessions:
            return session_id

def start_server():
    global VERBOSE, SIMULATE_LOSS, LOSS_RATE

    print("Server startup:")
    print("    1. Localhost only (127.0.0.1)")
    print("    2. Local Network (0.0.0.0)")
    
    choice = input("Select binding mode (1 or 2): ").strip()
    VERBOSE = input("Enable verbose logging? (y/n): ").strip().lower() == 'y'
    SIMULATE_LOSS = input("Enable reliability test mode? (y/n): ").strip().lower() == 'y'
    if SIMULATE_LOSS:
        try:
            LOSS_RATE = float(input("Enter loss rate (0 - 1.0): ").strip())
            LOSS_RATE = max(0.0, min(1.0, LOSS_RATE))
            print(f"[TEST] Packet loss simulation enabled (LOSS_RATE={LOSS_RATE:.0%})")
        except ValueError:
            LOSS_RATE = 0.2
            print("[!] Invalid loss rate, defaulting to 0.2")
    
    # bind to all network interfaces for LAN access, or loopback for local-only access
    bind_ip = '0.0.0.0' if choice == '2' else '127.0.0.1'
    port = 8080

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_ip, port))
    if bind_ip == '0.0.0.0':
        local_ip = socket.gethostbyname(socket.gethostname())
        print(f"\nServer listening on {bind_ip}:{port}...")
        print(f"[*] Clients on your network should connect to: {local_ip}:{port}")
    else:
        print(f"\nServer listening on {bind_ip}:{port}...")
  
    try:
        while True:
            # wait for incoming packets
            packet, client_addr = sock.recvfrom(PACKET_SIZE)
            try:
                parsed = parse_packet(packet)
            except ValueError:
                send_bad_request(sock, client_addr)
                continue

            if parsed['type'] == MSG_SYN and parsed['session_id'] == 0:
                try:
                    syn_data = parse_syn_payload(parsed['payload'])
                except Exception:
                    continue  # drop malformed SYN payloads

                op = syn_data['op']
                requested_chunk = syn_data['chunk_size']
                chosen_chunk = min(PAYLOAD_SIZE, requested_chunk) if requested_chunk > 0 else PAYLOAD_SIZE
                
                safe_filename = os.path.basename(syn_data['filename'])
                filepath = os.path.join(SERVER_DIR, safe_filename)

                print(f"\n[!] Received SYN from {client_addr}: OP={'PUT' if op == 1 else 'GET'}, File={safe_filename}")

                # for get requests, return an error if the file does not exist
                if op == 0 and not os.path.exists(filepath):
                    print(f"[-] File '{safe_filename}' not found in {SERVER_DIR}/. Sending ERROR.")
                    err_payload = build_err_payload(ERR_FILE_NOT_FOUND, "FILE_NOT_FOUND")
                    err_packet = build_packet(MSG_ERROR, 0, 0, 0, err_payload)
                    sock.sendto(err_packet, client_addr)
                    continue

                # for handshake: create unique session_id and initial sequence number 
                session_id = generate_session_id()
                isn = int(time.time()) % (2**32)  
                active_sessions.add(session_id)

                syn_ack_payload = build_syn_ack_payload(0x00, chosen_chunk, isn)
                syn_ack_packet = build_packet(MSG_SYN_ACK, session_id, 0, 0, syn_ack_payload)

                # send SYN_ACK once, then the client will retransmit SYN on timeout
                sock.sendto(syn_ack_packet, client_addr)
                print(f"[+] Sent SYN_ACK. Session: {session_id}, ISN: {isn}")
                if VERBOSE:
                    print(f"    [Handshake] Op={'PUT' if op == 1 else 'GET'}, ChunkSize={chosen_chunk}B, ISN={isn}")
                    print(f"    [Session]   ID={session_id}, active_sessions={active_sessions}")

                # transfer state
                sock.settimeout(TIMEOUT)
                try:
                    if op == 0:
                        server_send_file(sock, client_addr, session_id, isn, filepath, syn_ack_packet, chosen_chunk)
                    elif op == 1:
                        server_receive_file(sock, client_addr, session_id, isn, filepath, syn_ack_packet)
                except socket.timeout:
                    print("[-] Transfer timed out. Session dropped.")
                    send_timeout_abort(sock, client_addr, session_id)

                active_sessions.discard(session_id)
                if VERBOSE:
                    print(f"    [Session]   {session_id} removed. Active sessions remaining: {len(active_sessions)}")
                sock.settimeout(None)  # reset to blocking mode for the next client

    finally:
        sock.close()

def server_send_file(sock, client_addr, session_id, isn, filepath, syn_ack_packet: bytes, chunk_size: int):
    print(f"[Transfer] Sending '{os.path.basename(filepath)}' to {client_addr}...")
    seq = isn

    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                
                # peek ahead to detect whether the next chunk is the last one
                pos = f.tell()
                nxt = f.read(1)
                is_last = (nxt == b"")
                f.seek(pos)

                # build data packet and mark eof on the final chunk
                flags = FLAG_EOF if is_last else FLAG_NONE
                if VERBOSE and is_last:
                    print(f"    [EOF] Final chunk at seq={seq}, FLAG_EOF set.")
                data_pkt = build_packet(MSG_DATA, session_id, seq, 0, chunk, flags=flags)

                # stop and wait logic: send one data packet and wait for matching ack
                acked = False

                for attempt in range(1, MAX_RETRIES + 1):
                    if VERBOSE:
                        print(f"    [SEND] Sending DATA seq={seq}, attempt {attempt}/{MAX_RETRIES}")
                    if SIMULATE_LOSS and random.random() < LOSS_RATE:
                        print(f"    [TEST] Intentionally dropped DATA {seq} to trigger timeout.")
                    else:
                        sock.sendto(data_pkt, client_addr)
                    try:
                        raw, _ = sock.recvfrom(PACKET_SIZE)
                        p = parse_packet(raw)
                    except socket.timeout:
                        if VERBOSE:
                            print(f"    [RETRY] Timeout on seq={seq}, attempt {attempt}/{MAX_RETRIES}")
                        continue 
                    except ValueError:
                        send_bad_request(sock, client_addr)
                        continue

                    # client may resend syn if syn_ack was lost, so reply with syn_ack again
                    if p["type"] == MSG_SYN and p["session_id"] == 0:
                        sock.sendto(syn_ack_packet, client_addr)
                        continue

                    # abort on packets from a different session
                    if p["session_id"] != session_id:
                        send_session_mismatch(sock, client_addr, p["session_id"])
                        return

                    # abort if the client reports an error
                    if p["type"] == MSG_ERROR:
                        err = parse_err_payload(p["payload"])
                        print(f"[-] Client sent ERROR {err['error_code']}: {err['msg']}")
                        return

                    # accept ack only if it matches the current sequence number
                    if p["type"] == MSG_ACK and p["ack"] == seq:
                        acked = True
                        break

                # abort transfer if ack is not received after all retries
                if not acked:
                    print("[-] MAX_RETRIES exceeded. Aborting transfer.")
                    send_timeout_abort(sock, client_addr, session_id)
                    return

                seq += 1

                if is_last:
                    break

        # for teardown: send fin and wait for fin_ack
        file_size = os.path.getsize(filepath)
        print(f"[File]     Sent '{os.path.basename(filepath)}' — {file_size} bytes to {client_addr}")
        print("[Teardown] File sent. Sending FIN...")
        fin_pkt = build_packet(MSG_FIN, session_id, 0, 0)
        
        for attempt in range(1, MAX_RETRIES + 1):
            if VERBOSE:
                print(f"    [SEND] Sending FIN, attempt {attempt}/{MAX_RETRIES}")
            sock.sendto(fin_pkt, client_addr)
            try:
                raw, _ = sock.recvfrom(PACKET_SIZE)
                p = parse_packet(raw)

                # client may resend syn if syn_ack was lost, reply with syn_ack again
                if p["type"] == MSG_SYN and p["session_id"] == 0:
                    sock.sendto(syn_ack_packet, client_addr)
                    continue
                
                # transfer is complete once matching fin_ack is received
                if p["session_id"] == session_id and p["type"] == MSG_FIN_ACK:
                    print(f"[OK] Transfer complete. FIN_ACK received from {client_addr}.")
                    return
            except (socket.timeout, OSError):
                continue 
            except ValueError:
                send_bad_request(sock, client_addr)
                continue

        print("[-] Teardown timeout: No FIN_ACK received, but file was sent successfully.")

    except Exception as e:
        print(f"[-] Internal error during send: {e}")
        err_pkt = build_packet(MSG_ERROR, session_id, 0, 0, build_err_payload(ERR_INTERNAL_ERROR, "Server fault"))
        sock.sendto(err_pkt, client_addr)

def server_receive_file(sock, client_addr, session_id, isn, filepath, syn_ack_packet: bytes):
    print(f"[Transfer] Receiving file to save as '{os.path.basename(filepath)}'...")
    expected = isn
    last_acked = (isn - 1) & 0xFFFFFFFF  

    try:
        with open(filepath, "wb") as f:
            while True:
                p = None
                for attempt in range(1, MAX_RETRIES + 1):
                    if VERBOSE:
                        print(f"    [RECV] Receiving DATA seq={expected}, attempt {attempt}/{MAX_RETRIES}")
                    try:
                        # wait for incoming packets
                        raw, _ = sock.recvfrom(PACKET_SIZE)
                        p = parse_packet(raw)
                        break
                    except socket.timeout:
                        if VERBOSE:
                            print(f"    [RETRY] Timeout on seq={expected}, attempt {attempt}/{MAX_RETRIES}")
                        continue
                    except ValueError:
                        send_bad_request(sock, client_addr)
                        continue

                if p is None:
                    print("[-] MAX_RETRIES exceeded while receiving. Aborting transfer.")
                    send_timeout_abort(sock, client_addr, session_id)
                    return

                if p["type"] == MSG_SYN and p["session_id"] == 0:
                    sock.sendto(syn_ack_packet, client_addr)
                    continue

                # abort on packets from a different session
                if p["session_id"] != session_id:
                    send_session_mismatch(sock, client_addr, p["session_id"])
                    return

                # abort if the client reports an error
                if p["type"] == MSG_ERROR:
                    err = parse_err_payload(p["payload"])
                    print(f"[-] Client sent ERROR {err['error_code']}: {err['msg']}")
                    return 

                # stop and wait receive logic
                if p["type"] == MSG_DATA:
                    seq = p["seq"]
                    
                    # for in order packet: write payload and ack it
                    if seq == expected:
                        f.write(p["payload"])
                        last_acked = seq
                        expected += 1
                        send_ack(sock, client_addr, session_id, last_acked)

                        if (p["flags"] & FLAG_EOF) != 0:
                            if VERBOSE:
                                print(f"    [EOF] FLAG_EOF received at seq={seq}, stopping receive loop.")
                            break
                            
                    # for duplicate packet: re-ack last accepted sequence number
                    elif seq < expected:
                        send_ack(sock, client_addr, session_id, last_acked)
                        
                    # out of order packet: ignore payload and re-ack last good packet
                    else:
                        send_ack(sock, client_addr, session_id, last_acked)

        # for teardown: send fin and wait for fin_ack
        print("[Teardown] File received. Sending FIN...")
        file_size = os.path.getsize(filepath)
        print(f"[File]     Saved '{os.path.basename(filepath)}' — {file_size} bytes written to {SERVER_DIR}/")
        fin_pkt = build_packet(MSG_FIN, session_id, 0, 0)
        
        for attempt in range(1, MAX_RETRIES + 1):
            if VERBOSE:
                print(f"    [SEND] Sending FIN, attempt {attempt}/{MAX_RETRIES}")
            sock.sendto(fin_pkt, client_addr)
            try:
                raw, _ = sock.recvfrom(PACKET_SIZE)
                p = parse_packet(raw)

                if p["type"] == MSG_SYN and p["session_id"] == 0:
                    sock.sendto(syn_ack_packet, client_addr)
                    continue

                # transfer is complete once matching fin_ack is received
                if p["session_id"] == session_id and p["type"] == MSG_FIN_ACK:
                    print(f"[OK] Transfer complete. File saved as '{os.path.basename(filepath)}'.")
                    return

                # if client retransmits lost ack, re-ack it
                if p["session_id"] == session_id and p["type"] == MSG_DATA:
                    send_ack(sock, client_addr, session_id, last_acked)

            except (socket.timeout, OSError):
                continue  # timeout waiting for fin_ack then resend fin

            except ValueError:
                send_bad_request(sock, client_addr)
                continue

        print("[-] Teardown timeout: No FIN_ACK received, but file was saved successfully.")

    except Exception as e:
        print(f"[-] Internal error during receive: {e}")
        err_pkt = build_packet(MSG_ERROR, session_id, 0, 0, build_err_payload(ERR_INTERNAL_ERROR, "Server fault"))
        sock.sendto(err_pkt, client_addr)

if __name__ == "__main__":
    start_server()