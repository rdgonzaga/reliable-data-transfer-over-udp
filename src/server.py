# logic:
# 1. nakalisten state yung server
# 2. pag dumating yung syn, parse payload to check if get or put 
#   2.1 pag get and file is missing, sends an error
#   2.2 pag no generate a session id and isn and magsesend ng syn ack
# then magloloop yung stop nd wait arq para makasend or receive ng files 
import socket
import os
import random
import time
from protocol import *

# SERVER_ADDR = ('127.0.0.1', 8080)
SERVER_DIR = "server_files"
if not os.path.exists(SERVER_DIR):
    os.makedirs(SERVER_DIR)

active_sessions = set()  # track active session_ids to avoid collisions

# generate a uniqued session id that is not used
def generate_session_id():
    while True:
        session_id = random.randint(1, 2**32 - 1)
        if session_id not in active_sessions:
            return session_id

def start_server():
    print("Server startup:")
    print("    1. Localhost only (127.0.0.1)")
    print("    2. Local Network (0.0.0.0)")
    choice = input("Select binding mode (1 or 2): ").strip()
    
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
            # listen state
            packet, client_addr = sock.recvfrom(PACKET_SIZE)
            try:
                parsed = parse_packet(packet)
            except ValueError:
                # continue  # drop corrupted / too small na packets
                # best effort BAD_REQUEST error, session_id unknown -> use 0
                err_payload = build_err_payload(ERR_BAD_REQUEST, "BAD_REQUEST")
                err_pkt = build_packet(MSG_ERROR, 0, 0, 0, err_payload)
                sock.sendto(err_pkt, client_addr)
                continue

            if parsed['type'] == MSG_SYN and parsed['session_id'] == 0:
                try:
                    syn_data = parse_syn_payload(parsed['payload'])
                except Exception:
                    continue  # drop malformed SYN payloads

                op = syn_data['op']
                
                # ensure the file stays inside server_dir
                safe_filename = os.path.basename(syn_data['filename'])
                filepath = os.path.join(SERVER_DIR, safe_filename)

                print(f"\n[!] Received SYN from {client_addr}: OP={'PUT' if op == 1 else 'GET'}, File={safe_filename}")

                # check if file exists for get requests
                if op == 0 and not os.path.exists(filepath):
                    print(f"[-] File '{safe_filename}' not found in {SERVER_DIR}/. Sending ERROR.")
                    err_payload = build_err_payload(0x01, "File not found")
                    err_packet = build_packet(MSG_ERROR, 0, 0, 0, err_payload)
                    sock.sendto(err_packet, client_addr)
                    continue

                # handshake state — generate unique session_id and ISN
                session_id = generate_session_id()
                isn = int(time.time()) % (2**32)    # time based ISN (based off of TCP)
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
                        server_send_file(sock, client_addr, session_id, isn, filepath, syn_ack_packet)
                    elif op == 1:
                        # PUT: server receives file
                        server_receive_file(sock, client_addr, session_id, isn, filepath, syn_ack_packet)
                except socket.timeout:
                    print("[-] Transfer timed out. Session dropped.")
                    err_payload = build_err_payload(ERR_TIMEOUT_ABORT, "Timeout abort")
                    err_packet = build_packet(MSG_ERROR, session_id, 0, 0, err_payload)
                    sock.sendto(err_packet, client_addr)

                active_sessions.discard(session_id)
                sock.settimeout(None)  # reset to blocking mode for the next client

    finally:
        sock.close()

def server_send_file(sock, client_addr, session_id, isn, filepath, syn_ack_packet: bytes):
    print(f"[Transfer] Sending '{os.path.basename(filepath)}' to {client_addr}...")
    seq = isn

    try:
        # 1. open file in 'rb' mode to read raw bytes
        with open(filepath, "rb") as f:
            # main loop
            while True:
                # 2. read chunks of PAYLOAD_SIZE
                chunk = f.read(PAYLOAD_SIZE)
                
                # peek 1 byte ahead to see if this is the final chunk (EOF)
                pos = f.tell()
                nxt = f.read(1)
                is_last = (nxt == b"")
                f.seek(pos)

                # 3. build msg_data packets
                flags = FLAG_EOF if is_last else FLAG_NONE
                data_pkt = build_packet(MSG_DATA, session_id, seq, 0, chunk, flags=flags)

                # 4. stop and wait logic (sender side)
                acked = False
                # try and send the data packet up to 10 times
                for attempt in range(1, MAX_RETRIES + 1):
                    sock.sendto(data_pkt, client_addr)
                    try:
                        # wait for the client to reply with ack
                        raw, _ = sock.recvfrom(PACKET_SIZE)
                        p = parse_packet(raw)
                    except socket.timeout:
                        # if nagtime out, loop back and retransmit
                        continue 
                    except ValueError:
                        # # if may error yung parse packet, like too short or corrupted, drop it
                        # continue 
                        # best effort BAD_REQUEST error, session_id unknown -> use 0
                        err_payload = build_err_payload(ERR_BAD_REQUEST, "BAD_REQUEST")
                        err_pkt = build_packet(MSG_ERROR, 0, 0, 0, err_payload)
                        sock.sendto(err_pkt, client_addr)
                        continue

                    # client may still resend SYN if SYN_ACK was dropped
                    # keep resending SYN_ACK during teardown so the client can sync
                    if p["type"] == MSG_SYN and p["session_id"] == 0:
                        sock.sendto(syn_ack_packet, client_addr)
                        continue

                    # drop packets that is not for this transfer
                    # changed: send best effort ERROR + abort as per RFC
                    if p["session_id"] != session_id:
                        err_pkt = build_packet(MSG_ERROR, p["session_id"], 0, 0,
                                            build_err_payload(ERR_SESSION_MISMATCH, "SESSION_MISMATCH"))
                        sock.sendto(err_pkt, client_addr)
                        return

                    # if client has an error, show error
                    if p["type"] == MSG_ERROR:
                        err = parse_err_payload(p["payload"])
                        print(f"[-] Client sent ERROR {err['error_code']}: {err['msg']}")
                        return # end na agad

                    # wait for msg_ack matching our seq
                    if p["type"] == MSG_ACK and p["ack"] == seq:
                        acked = True
                        break

                # if it looped 10 times but never get an ack, abort transfer
                if not acked:
                    print("[-] MAX_RETRIES exceeded. Aborting transfer.")
                    err_payload = build_err_payload(ERR_TIMEOUT_ABORT, "Timeout abort")
                    err_pkt = build_packet(MSG_ERROR, session_id, 0, 0, err_payload)
                    sock.sendto(err_pkt, client_addr)
                    return

                # increment seq for the next packet
                seq += 1
                
                # stop sending if EOF
                if is_last:
                    break

        # 5. teardown phase
        print("[Teardown] File sent. Sending FIN...")
        fin_pkt = build_packet(MSG_FIN, session_id, 0, 0)
        
        # try and send the fin packet up to 10 times
        for attempt in range(1, MAX_RETRIES + 1):
            sock.sendto(fin_pkt, client_addr)
            try:
                # wait for the client to reply with fin_ack
                raw, _ = sock.recvfrom(PACKET_SIZE)
                p = parse_packet(raw)

                # client may still resend SYN if SYN_ACK was dropped
                # keep resending SYN_ACK during teardown so the client can sync
                if p["type"] == MSG_SYN and p["session_id"] == 0:
                    sock.sendto(syn_ack_packet, client_addr)
                    continue
                
                # session over if nareceive na ng server yung fin_ack
                if p["session_id"] == session_id and p["type"] == MSG_FIN_ACK:
                    print(f"[OK] Transfer complete. FIN_ACK received from {client_addr}.")
                    return
            except (socket.timeout, OSError):
                continue 
            except ValueError:
                # best effort BAD_REQUEST error, session_id unknown -> use 0
                err_payload = build_err_payload(ERR_BAD_REQUEST, "BAD_REQUEST")
                err_pkt = build_packet(MSG_ERROR, 0, 0, 0, err_payload)
                sock.sendto(err_pkt, client_addr)
                continue

                
        # if it looped 10 times but never get a fin_ack, just print a warning since sent na yung file
        print("[-] Teardown timeout: No FIN_ACK received, but file was sent successfully.")

    except Exception as e:
        # error handling jic python crashed / system crashed
        print(f"[-] Internal error during send: {e}")
        err_pkt = build_packet(MSG_ERROR, session_id, 0, 0, build_err_payload(ERR_INTERNAL_ERROR, "Server fault"))
        sock.sendto(err_pkt, client_addr)

def server_receive_file(sock, client_addr, session_id, isn, filepath, syn_ack_packet: bytes):
    print(f"[Transfer] Receiving file to save as '{os.path.basename(filepath)}'...")
    expected = isn
    last_acked = (isn - 1) & 0xFFFFFFFF  # sentinel: no packet ACKed yet; using isn-1 avoids false ACK match if isn=0

    try:
        # 1. open file in 'wb' mode
        with open(filepath, "wb") as f:
            while True:
                try:
                    # 2. wait for incoming msg_data packets
                    raw, _ = sock.recvfrom(PACKET_SIZE)
                    p = parse_packet(raw)
                except socket.timeout:
                    # if nagtime out, do no thing, client dapat magreretransmit
                    continue
                except ValueError:
                    # # if may error yung parse packet, like too short or corrupted, drop it
                    # continue
                    # best effort BAD_REQUEST error, session_id unknown -> use 0
                    err_payload = build_err_payload(ERR_BAD_REQUEST, "BAD_REQUEST")
                    err_pkt = build_packet(MSG_ERROR, 0, 0, 0, err_payload)
                    sock.sendto(err_pkt, client_addr)
                    continue

                # client may still resend SYN if SYN_ACK was dropped
                # keep resending SYN_ACK during teardown so the client can sync
                if p["type"] == MSG_SYN and p["session_id"] == 0:
                    sock.sendto(syn_ack_packet, client_addr)
                    continue

                # drop packets that is not for this transfer
                # changed: send best effort ERROR + abort as per RFC
                if p["session_id"] != session_id:
                    err_pkt = build_packet(MSG_ERROR, p["session_id"], 0, 0,
                                        build_err_payload(ERR_SESSION_MISMATCH, "SESSION_MISMATCH"))
                    sock.sendto(err_pkt, client_addr)
                    return

                # if client has an error, show error
                if p["type"] == MSG_ERROR:
                    err = parse_err_payload(p["payload"])
                    print(f"[-] Client sent ERROR {err['error_code']}: {err['msg']}")
                    return # end na agad

                # 3. stop and wait logic
                if p["type"] == MSG_DATA:
                    seq = p["seq"]
                    
                    # first scenario, perfect packet
                    if seq == expected:
                        f.write(p["payload"])
                        last_acked = seq
                        expected += 1

                        # build and send the ack packet
                        ack_pkt = build_packet(MSG_ACK, session_id, 0, last_acked)
                        sock.sendto(ack_pkt, client_addr)
                        
                        # stop receiving if EOF flag
                        if (p["flags"] & FLAG_EOF) != 0:
                            break
                            
                    # second scenario, if may duplicate packet
                    elif seq < expected:
                        # resend ack so alam ng client na safe na mag send ulit
                        ack_pkt = build_packet(MSG_ACK, session_id, 0, last_acked)
                        sock.sendto(ack_pkt, client_addr)
                        
                    # third scenario, out of order packet
                    else:
                        # ignore payload since we only accept in-order data and 
                        # resend the ack for the last good packet
                        ack_pkt = build_packet(MSG_ACK, session_id, 0, last_acked)
                        sock.sendto(ack_pkt, client_addr)

        # 6. teardown phase
        print("[Teardown] File received. Sending FIN...")
        fin_pkt = build_packet(MSG_FIN, session_id, 0, 0)
        
        # try and send the fin packet up to 10 times
        for attempt in range(1, MAX_RETRIES + 1):
            sock.sendto(fin_pkt, client_addr)
            try:
                # wait for the client to reply with fin_ack
                raw, _ = sock.recvfrom(PACKET_SIZE)
                p = parse_packet(raw)

                # client may still resend SYN if SYN_ACK was dropped
                # keep resending SYN_ACK during teardown so the client can sync
                if p["type"] == MSG_SYN and p["session_id"] == 0:
                    sock.sendto(syn_ack_packet, client_addr)
                    continue

                # session over if nareceive na ng server yung fin_ack
                if p["session_id"] == session_id and p["type"] == MSG_FIN_ACK:
                    print(f"[OK] Transfer complete. File saved as '{os.path.basename(filepath)}'.")
                    return

                # if client retransmits the last DATA (because our ACK was lost),
                # re-ACK it so the client stops retransmitting and can receive our FIN
                if p["session_id"] == session_id and p["type"] == MSG_DATA:
                    ack_pkt = build_packet(MSG_ACK, session_id, 0, last_acked)
                    sock.sendto(ack_pkt, client_addr)

            except (socket.timeout, OSError):
                continue # if we timeout waiting for FIN_ACK, loop back and resend the FIN
            except ValueError:
                # best effort BAD_REQUEST error, session_id unknown -> use 0
                err_payload = build_err_payload(ERR_BAD_REQUEST, "BAD_REQUEST")
                err_pkt = build_packet(MSG_ERROR, 0, 0, 0, err_payload)
                sock.sendto(err_pkt, client_addr)
                continue


        # if it looped 10 times but never get a fin_ack, just print a warning since saved na yung file
        print("[-] Teardown timeout: No FIN_ACK received, but file was saved successfully.")

    except Exception as e:
        # error handling jic python crashed / system crashed
        print(f"[-] Internal error during receive: {e}")
        err_pkt = build_packet(MSG_ERROR, session_id, 0, 0, build_err_payload(ERR_INTERNAL_ERROR, "Server fault"))
        sock.sendto(err_pkt, client_addr)

if __name__ == "__main__":
    start_server()