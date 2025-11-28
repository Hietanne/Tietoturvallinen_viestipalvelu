import socket
import threading
import json
import struct


def send_frame(sock, data: bytes):
    length = len(data)
    header = struct.pack("!I", length)
    sock.sendall(header + data)


def recv_exact(sock, n: int):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_frame(sock):
    header = recv_exact(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack("!I", header)
    if length == 0:
        return b""
    return recv_exact(sock, length)


def relay_pair(a, b, addr_a, addr_b):
    def forward(src, dst, name):
        try:
            while True:
                frame = recv_frame(src)
                if frame is None:
                    break
                send_frame(dst, frame)
        except Exception:
            pass
        finally:
            try:
                src.close()
            except OSError:
                pass
            try:
                dst.close()
            except OSError:
                pass
            print(f"[INFO] Yhteys {name} suljettu.")

    t1 = threading.Thread(target=forward, args=(a, b, f"{addr_a} -> {addr_b}"), daemon=True)
    t2 = threading.Thread(target=forward, args=(b, a, f"{addr_b} -> {addr_a}"), daemon=True)
    t1.start()
    t2.start()


def handle_client(conn, addr, rooms, rooms_lock):
    try:
        first = recv_frame(conn)
        if first is None:
            print(f"[WARN] {addr} sulki yhteyden ennen join-viestiä.")
            conn.close()
            return
        try:
            msg = json.loads(first.decode("utf-8"))
        except Exception:
            print(f"[WARN] {addr} lähetti virheellisen join-viestin.")
            conn.close()
            return
        if msg.get("type") != "join":
            print(f"[WARN] {addr} lähetti vääräntyyppisen viestin: {msg.get('type')}")
            conn.close()
            return
        room = msg.get("room")
        if not isinstance(room, str) or not room:
            print(f"[WARN] {addr} lähetti virheellisen huonekoodin.")
            conn.close()
            return

        print(f"[INFO] {addr} liittyi huoneeseen '{room}'")

        with rooms_lock:
            if room not in rooms:
                rooms[room] = conn
                print(f"[INFO] Huone '{room}' odottaa toista osapuolta.")
                return
            else:
                other = rooms.pop(room)

        # Tässä vaiheessa huoneessa on kaksi osapuolta
        print(f"[INFO] Huone '{room}' täynnä, yhdistetään {addr} ja {other.getpeername()}")
        relay_pair(conn, other, addr, other.getpeername())

    except Exception as e:
        print(f"[ERROR] Virhe käsiteltäessä {addr}: {e}")
        try:
            conn.close()
        except OSError:
            pass


def main(host="0.0.0.0", port=9000):
    rooms = {}
    rooms_lock = threading.Lock()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)
    print(f"[INFO] Välipalvelin kuuntelee {host}:{port}")
    print("[INFO] Käytä tätä osoitetta client-sovelluksessa Proxy host -kentässä.")

    try:
        while True:
            conn, addr = srv.accept()
            print(f"[INFO] Uusi yhteys {addr}")
            t = threading.Thread(target=handle_client, args=(conn, addr, rooms, rooms_lock), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[INFO] Sammutetaan välipalvelin...")
    finally:
        srv.close()


if __name__ == "__main__":
    main()