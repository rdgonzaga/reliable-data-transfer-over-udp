import os
import socket
import sys
from protocol import *  # imports packet builders/parsers + constants like TIMEOUT/MAX_RETRIES/etc.

CLIENT_DIR = "client_files"
if not os.path.exists(CLIENT_DIR):
    os.makedirs(CLIENT_DIR)

# op codes used in the SYN payload (per RFC)
OP_GET = 0x00
OP_PUT = 0x01

# receive one UPD datagram and immediately parse it into a dict 
def recv_parsed(sock: socket.socket, max_packet: int) -> dict:
    raw, _ = sock.recvfrom(max_packet)        # max_packet is the largest packet we expect to receive
    return parse_packet(raw)                  # parse_packet() is from protocol.py

# 3 way-ish handshake:
# client sends SYN (op, proposed_chunk, filename) and then expects SYN_ACK with session_id, chosen_chunk_size, ISN
def handshake(sock: socket.socket, server_addr, op: int, filename: str, proposed_chunk: int):
    syn_payload = build_syn_payload(op, proposed_chunk, filename)
    syn_pkt = build_packet(MSG_SYN, 0, 0, 0, syn_payload)                # session_id=0 for initial SYN

    sock.settimeout(TIMEOUT)
    for attempt in range(1, MAX_RETRIES + 1):
        sock.sendto(syn_pkt, server_addr)
        try:
            # wdk server's negotiated 1 yet, so we allow a big buffer.
            p = recv_parsed(sock, HEADER_SIZE + max(proposed_chunk, 65535))
        except socket.timeout:
            continue

        if p["type"] == MSG_ERROR:
            err = parse_err_payload(p["payload"])
            raise RuntimeError(f"Server ERROR {err['error_code']}: {err['msg']}")

        if p["type"] == MSG_SYN_ACK:
            syn_ack = parse_syn_ack_payload(p["payload"])
            if syn_ack["status"] != 0x00:
                raise RuntimeError("Server rejected session.")
            # return negotiated values we need for the rest of the transfer
            return p["session_id"], syn_ack["chunk_size"], syn_ack["isn"]

    raise RuntimeError("Handshake failed: no SYN_ACK (timeout).")

def send_error_best_effort(sock: socket.socket, addr, session_id: int, err_code: int, msg: str) -> None:
    payload = build_err_payload(err_code, msg)
    pkt = build_packet(MSG_ERROR, session_id, 0, 0, payload)
    try:
        sock.sendto(pkt, addr)
    except OSError:
        pass

# GET = download: client asks for a remote file and writes received DATA payloads to disk
def client_get(server_ip: str, port: int, remote_name: str, out_path: str, proposed_chunk: int):
    server_addr = (server_ip, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("[Handshake] Negotiating session...")
    session_id, chunk_size, isn = handshake(sock, server_addr, OP_GET, remote_name, proposed_chunk)
    print(f"[Handshake] Session ID: {session_id} | Chunk Size: {chunk_size} | ISN: {isn}")
    print(f"[Transfer] Downloading '{remote_name}'")
    
    max_packet = HEADER_SIZE + chunk_size                                # max expected packet size for recvfrom()
    expected = isn                                                       # next expected seq number (in-order)
    last_acked = 0                                                       # most recent seq we've ACKed

    with open(out_path, "wb") as f:
        sock.settimeout(TIMEOUT)
        while True:
            try:
                p = recv_parsed(sock, max_packet)                        # wait for DATA/FIN/ERROR
            except socket.timeout:
                # for GET: server is the sender. if we timeout, we just keep waiting.
                # server should handle its own retransmission timer.
                continue
            
            if p["type"] == MSG_ERROR:
                err = parse_err_payload(p["payload"])
                raise RuntimeError(f"Server ERROR {err['error_code']}: {err['msg']}")

            if p["session_id"] != session_id:
                # protocol violation as per RFC
                send_error_best_effort(sock, server_addr, p["session_id"], ERR_SESSION_MISMATCH, "SESSION_MISMATCH")
                sock.close()
                raise RuntimeError("Session mismatch detected (sent ERROR 0x03, aborting).")

            if p["type"] != MSG_DATA:
                # if server ends transfer, it should send FIN.
                if p["type"] == MSG_FIN:
                    fin_ack = build_packet(MSG_FIN_ACK, session_id, 0, 0)
                    sock.sendto(fin_ack, server_addr)
                    break
                continue                                                     # ignore other message types

            seq = p["seq"]

            if seq == expected:
                # correct in-order packet: write and ACK it
                f.write(p["payload"])
                last_acked = seq
                ack_pkt = build_packet(MSG_ACK, session_id, 0, last_acked)
                sock.sendto(ack_pkt, server_addr)
                expected += 1

                # EOF just means "this was last data"; FIN still comes after to close session.
                if (p["flags"] & FLAG_EOF) != 0:
                    continue
            elif seq < expected:
                # dupe packet (likely retransmission): re-ACK last in-order packet
                ack_pkt = build_packet(MSG_ACK, session_id, 0, last_acked)
                sock.sendto(ack_pkt, server_addr)
            else:
                # out-of-order shouldn't happen in stop-and-wait, but implemented safety anyways
                ack_pkt = build_packet(MSG_ACK, session_id, 0, last_acked)
                sock.sendto(ack_pkt, server_addr)

    sock.close()
    print(f"[OK] Download complete: '{out_path}' saved.\n")

# PUT = upload: client reads local file, sends DATA chunks one at a time, waiting for ACK each time.
def client_put(server_ip: str, port: int, local_path: str, remote_name: str, proposed_chunk: int):
    server_addr = (server_ip, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("[Handshake] Negotiating session...")
    session_id, chunk_size, isn = handshake(sock, server_addr, OP_PUT, remote_name, proposed_chunk)
    print(f"[Handshake] Session ID: {session_id} | Chunk Size: {chunk_size} | ISN: {isn}")
    print(f"[Transfer] Uploading '{local_path}' as '{remote_name}'")

    max_packet = HEADER_SIZE + chunk_size
    seq = isn
    sock.settimeout(TIMEOUT)

    with open(local_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)                                   # read one "packet payload" worth                                

            # check if last chunk (peek 1 byte ahead)
            pos = f.tell()
            nxt = f.read(1)
            is_last = (nxt == b"")
            f.seek(pos)

            flags = FLAG_EOF if is_last else FLAG_NONE                   # mark last DATA packet using EOF flag
            data_pkt = build_packet(MSG_DATA, session_id, seq, 0, chunk, flags=flags)

            # stop-and-wauit
            for attempt in range(1, MAX_RETRIES + 1):
                sock.sendto(data_pkt, server_addr)
                try:
                    p = recv_parsed(sock, max_packet)
                except socket.timeout:
                    continue                                             # timeout -> retransmit

                if p["type"] == MSG_ERROR:
                    err = parse_err_payload(p["payload"])
                    raise RuntimeError(f"Server ERROR {err['error_code']}: {err['msg']}")

                if p["session_id"] != session_id:
                    send_error_best_effort(sock, server_addr, p["session_id"], ERR_SESSION_MISMATCH, "SESSION_MISMATCH")
                    sock.close()
                    raise RuntimeError("Session mismatch detected (sent ERROR 0x03, aborting).")

                # accept ACK only if it matches the seq we just sent
                if p["type"] == MSG_ACK and p["ack"] == seq:
                    break
            else:
                send_error_best_effort(sock, server_addr, session_id, ERR_TIMEOUT_ABORT, "TIMEOUT_ABORT")
                sock.close()
                raise RuntimeError("Upload failed: MAX_RETRIES exceeded (sent ERROR 0x04, aborting).")

            seq += 1
            
            # break here after the EOF packet is successfully sent and ACKed
            if is_last:
                break

    # bounded loop for FIN wait
    for attempt in range(MAX_RETRIES * 10):
        try:
            p = recv_parsed(sock, max_packet)
        except socket.timeout:
            continue                                                    

        if p["type"] == MSG_FIN and p["session_id"] == session_id:
            fin_ack = build_packet(MSG_FIN_ACK, session_id, 0, 0)
            sock.sendto(fin_ack, server_addr)
            break

        if p["type"] == MSG_ERROR:
            err = parse_err_payload(p["payload"])
            raise RuntimeError(f"Server ERROR {err['error_code']}: {err['msg']}")
    else:
        print("[-] Server FIN wait timed out, but upload was likely successful.")

    sock.close()
    print(f"[OK] Upload complete: '{local_path}' sent.\n")

def _print_help():
    print("Type commands like:\n")
    print("    get <filename>\n")                               # download from server
    print("    put <filename>\n")                               # upload to server
    print("    quit\n")
    print("Type 'help' to show commands again.\n")

def main():
    # prompt once
    ip = input("Server IP: ").strip()
    port_str = input("Server Port: ").strip()

    try:
        port = int(port_str)
    except ValueError:
        print("[ERROR] Port must be an integer.")
        return

    # probe socket
    probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"Connecting to {ip}:{port}...")
    
    # dummy handshake
    try:
        # MSG_SYN with op=0xFF (or any undefined op) just to get a response
        # NOTE that there will be no error printed in the client terminal here as all the error handling
        # is built into the get and put functions.
        # This is purely for probing and testing if the server is alive.
        syn_pkt = build_packet(MSG_SYN, 0, 0, 0, build_syn_payload(0x00, 1024, "PING"))
        probe_sock.sendto(syn_pkt, (ip, port))
        data, addr = probe_sock.recvfrom(PACKET_SIZE)           # wait for any reply
        print("[OK] Connected.\n")
    except Exception as e:
        print(f"[ERROR] Connection failed: {e} (Is the server running?)")
        return
    finally:
        probe_sock.close()

    _print_help()

    while True:
        try:
            line = input(f"client@{ip}:{port}> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            return

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()

        if cmd in ("quit", "exit"):
            print("Bye.")
            return

        if cmd == "help":
            _print_help()
            continue

        try:
            if cmd == "get":
                # get <filename> [chunk]
                if len(parts) not in (2, 3):
                    print("Usage: get <filename> [chunk]")
                    continue

                filename = parts[1]
                chunk = int(parts[2]) if len(parts) == 3 else PAYLOAD_SIZE

                # routed to client dir
                out_path = os.path.join(CLIENT_DIR, os.path.basename(filename))

                client_get(ip, port, filename, out_path, chunk)

            elif cmd == "put":
                # put <filename> [chunk]
                if len(parts) not in (2, 3):
                    print("Usage: put <filename> [chunk]")
                    continue

                # routed to client dir
                local_path = os.path.join(CLIENT_DIR, parts[1])
                
                # check if file exists before trying to upload
                if not os.path.exists(local_path):
                    print(f"[ERROR] '{parts[1]}' not found in {CLIENT_DIR}/")
                    continue

                chunk = int(parts[2]) if len(parts) == 3 else PAYLOAD_SIZE

                # remote name defaults to basename (so "folder/a.txt" becomes "a.txt" remotely)
                remote_name = os.path.basename(local_path)

                client_put(ip, port, local_path, remote_name, chunk)

            else:
                print("Unknown command. Type 'help'.")

        except Exception as e:
            print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()