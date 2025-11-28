import os
import socket
import struct
import threading
import time
import uuid
import json
import base64
import hashlib
import queue
from datetime import datetime

import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox

from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey, PublicKey, Box
from nacl.exceptions import BadSignatureError, CryptoError

IDENTITY_KEY_FILE = "id_ed25519.key"


# ---------- Perusapuja: identiteetti + frame-pohjainen viestitys ----------

def load_or_create_identity(path=IDENTITY_KEY_FILE):
    """Luo (tai lataa) pysyvän Ed25519-identiteettiavaimen ja palauttaa sormenjäljen."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            raw = base64.b64decode(f.read())
        sk = SigningKey(raw)
        created = False
    else:
        sk = SigningKey.generate()
        with open(path, "wb") as f:
            f.write(base64.b64encode(sk.encode()))
        created = True
    vk = sk.verify_key
    fp = hashlib.sha256(vk.encode()).hexdigest()
    return sk, vk, fp, created


def send_frame(sock, data: bytes):
    """Lähettää 4 tavun pituusheaderin + datan."""
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
    """Lukee yhden kehyksen (length + data)."""
    header = recv_exact(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack("!I", header)
    if length == 0:
        return b""
    return recv_exact(sock, length)


# ---------- Kättely: identiteetin varmistus + ephemeral avaimet ----------

def make_handshake_message(identity_sk: SigningKey, eph_sk: PrivateKey):
    eph_pk_bytes = eph_sk.public_key.encode()
    id_pk_bytes = identity_sk.verify_key.encode()
    payload = eph_pk_bytes + id_pk_bytes
    signature = identity_sk.sign(payload).signature
    msg = {
        "type": "handshake",
        "id_pk": base64.b64encode(id_pk_bytes).decode("ascii"),
        "ephemeral_pk": base64.b64encode(eph_pk_bytes).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return json.dumps(msg).encode("utf-8")


def parse_handshake_message(data: bytes):
    msg = json.loads(data.decode("utf-8"))
    if msg.get("type") != "handshake":
        raise ValueError("Invalid handshake message type")
    id_pk_bytes = base64.b64decode(msg["id_pk"])
    eph_pk_bytes = base64.b64decode(msg["ephemeral_pk"])
    signature = base64.b64decode(msg["signature"])
    vk = VerifyKey(id_pk_bytes)
    payload = eph_pk_bytes + id_pk_bytes
    try:
        vk.verify(payload, signature)
    except BadSignatureError as e:
        raise ValueError("Invalid handshake signature") from e

    peer_eph_pk = PublicKey(eph_pk_bytes)
    peer_fp = hashlib.sha256(id_pk_bytes).hexdigest()
    return peer_eph_pk, peer_fp


def perform_handshake_client(sock, identity_sk: SigningKey):
    eph_sk = PrivateKey.generate()
    # Lähetä meidän handshake
    outbound = make_handshake_message(identity_sk, eph_sk)
    send_frame(sock, outbound)
    # Vastaanota palvelimen handshake
    inbound = recv_frame(sock)
    if inbound is None:
        raise RuntimeError("Connection closed during handshake")
    peer_eph_pk, peer_fp = parse_handshake_message(inbound)
    box = Box(eph_sk, peer_eph_pk)
    return box, peer_fp


def perform_handshake_server(sock, identity_sk: SigningKey):
    eph_sk = PrivateKey.generate()
    # Vastaanota clientin handshake
    inbound = recv_frame(sock)
    if inbound is None:
        raise RuntimeError("Connection closed during handshake")
    peer_eph_pk, peer_fp = parse_handshake_message(inbound)
    # Lähetä meidän handshake
    outbound = make_handshake_message(identity_sk, eph_sk)
    send_frame(sock, outbound)
    box = Box(eph_sk, peer_eph_pk)
    return box, peer_fp


# ---------- Salattu viestintä ----------

def send_secure_message(sock, box: Box, msg_obj: dict):
    plaintext = json.dumps(msg_obj).encode("utf-8")
    ciphertext = box.encrypt(plaintext)  # sisältää noncen
    send_frame(sock, ciphertext)


def recv_secure_message(sock, box: Box):
    frame = recv_frame(sock)
    if frame is None:
        return None
    try:
        plaintext = box.decrypt(frame)
    except CryptoError:
        raise RuntimeError("Decryption failed – data may be corrupted or tampered with")
    msg_obj = json.loads(plaintext.decode("utf-8"))
    return msg_obj


# ---------- Ydinlogiikka: verkko + kryptografia + eventit GUI:lle ----------

class SecureChatCore:
    def __init__(self, event_queue: "queue.Queue"):
        self.event_queue = event_queue
        self.identity_sk, self.identity_vk, self.my_fingerprint, created = load_or_create_identity()
        self.sock = None
        self.box = None
        self.running = False
        self.pending = {}
        self.pending_lock = threading.Lock()
        self.sock_lock = threading.Lock()
        self.mode = None  # "host" tai "client"

        if created:
            self.event_queue.put(("status", "Luotiin uusi identiteetti."))
        else:
            self.event_queue.put(("status", "Käytetään olemassa olevaa identiteettiä."))

        self.event_queue.put(("my_fp", self.my_fingerprint))

    def stop(self):
        self.running = False
        with self.sock_lock:
            if self.sock:
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None
        self.event_queue.put(("status", "Yhteys suljettu."))
        self.event_queue.put(("disconnected", ""))

    def start_host(self, host: str, port: int):
        if self.running or self.sock is not None:
            self.event_queue.put(("error", "Yhteys on jo käynnissä."))
            return
        self.mode = "host"
        t = threading.Thread(target=self._host_thread, args=(host, port), daemon=True)
        t.start()

    def _host_thread(self, host: str, port: int):
        self.event_queue.put(("status", f"Kuunnellaan {host}:{port} ..."))
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((host, port))
            srv.listen(1)
            conn, addr = srv.accept()
            self.event_queue.put(("status", f"Yhteys vastaanotettu: {addr}"))
            with self.sock_lock:
                self.sock = conn
            try:
                box, peer_fp = perform_handshake_server(conn, self.identity_sk)
            except Exception as e:
                self.event_queue.put(("error", f"Kättely epäonnistui: {e}"))
                self.stop()
                return
            self.box = box
            self.running = True
            self.event_queue.put(("peer_fp", peer_fp))
            self.event_queue.put(("connected", "host"))
            self._recv_loop()
        finally:
            try:
                srv.close()
            except OSError:
                pass

    def start_client(self, host: str, port: int):
        if self.running or self.sock is not None:
            self.event_queue.put(("error", "Yhteys on jo käynnissä."))
            return
        self.mode = "client"
        t = threading.Thread(target=self._client_thread, args=(host, port), daemon=True)
        t.start()

    def _client_thread(self, host: str, port: int):
        self.event_queue.put(("status", f"Yhdistetään {host}:{port} ..."))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, port))
            self.event_queue.put(("status", "Yhteys muodostettu, suoritetaan kättely..."))
            with self.sock_lock:
                self.sock = sock
            try:
                box, peer_fp = perform_handshake_client(sock, self.identity_sk)
            except Exception as e:
                self.event_queue.put(("error", f"Kättely epäonnistui: {e}"))
                self.stop()
                return
            self.box = box
            self.running = True
            self.event_queue.put(("peer_fp", peer_fp))
            self.event_queue.put(("connected", "client"))
            self._recv_loop()
        except Exception as e:
            self.event_queue.put(("error", f"Yhteyden muodostus epäonnistui: {e}"))
            self.stop()

    def _recv_loop(self):
        self.event_queue.put(("status", "Viestien vastaanotto käynnissä."))
        try:
            while self.running:
                msg = recv_secure_message(self.sock, self.box)
                if msg is None:
                    break
                mtype = msg.get("type")
                if mtype == "msg":
                    mid = msg.get("id")
                    text = msg.get("text")
                    ts = msg.get("ts")
                    self.event_queue.put(("recv_msg", (text, ts)))
                    # lähetä luku-kuittaus
                    ack = {"type": "ack", "msg_id": mid, "ts": time.time()}
                    send_secure_message(self.sock, self.box, ack)
                elif mtype == "ack":
                    mid = msg.get("msg_id")
                    ack_ts = msg.get("ts")
                    with self.pending_lock:
                        orig = self.pending.pop(mid, None)
                    if orig:
                        self.event_queue.put(("ack", (orig.get("text"), orig.get("ts"), ack_ts)))
        except Exception as e:
            self.event_queue.put(("error", f"Vastaanottovirhe: {e}"))
        self.running = False
        self.event_queue.put(("status", "Yhteys katkaistu."))
        self.event_queue.put(("disconnected", ""))

    def send_text(self, text: str):
        if not self.running or not self.sock or not self.box:
            self.event_queue.put(("error", "Ei avointa yhteyttä."))
            return
        msg_id = uuid.uuid4().hex
        ts = time.time()
        msg = {"type": "msg", "id": msg_id, "text": text, "ts": ts}
        try:
            with self.pending_lock:
                self.pending[msg_id] = msg
            send_secure_message(self.sock, self.box, msg)
            self.event_queue.put(("sent_msg", (text, ts)))
        except Exception as e:
            self.event_queue.put(("error", f"Lähetysvirhe: {e}"))


# ---------- GUI: Tkinter-käyttöliittymä ----------

class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Tietoturvallinen P2P-viestintä (prototyyppi)")
        self.root.geometry("900x600")

        self.event_queue = queue.Queue()
        self.core = SecureChatCore(self.event_queue)

        self.connected = False

        self._build_ui()
        self.root.after(100, self._poll_events)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        mainframe = ttk.Frame(self.root, padding=10)
        mainframe.pack(fill="both", expand=True)

        # Otsikko
        title = ttk.Label(mainframe, text="Tietoturvallinen P2P-viestintä", font=("Segoe UI", 16, "bold"))
        title.pack(anchor="w", pady=(0, 5))

        # Oma identiteetti
        id_frame = ttk.LabelFrame(mainframe, text="Oma identiteetti")
        id_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(id_frame, text="Sormenjälki (SHA-256):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.fp_var = tk.StringVar(value="–")
        fp_entry = ttk.Entry(id_frame, textvariable=self.fp_var, width=70, state="readonly")
        fp_entry.grid(row=0, column=1, sticky="we", padx=5, pady=5)
        id_frame.columnconfigure(1, weight=1)

        # Yhteysasetukset
        conn_frame = ttk.LabelFrame(mainframe, text="Yhteys")
        conn_frame.pack(fill="x", pady=(0, 10))

        self.mode_var = tk.StringVar(value="host")
        host_rb = ttk.Radiobutton(conn_frame, text="Toimi palvelimena", variable=self.mode_var, value="host")
        client_rb = ttk.Radiobutton(conn_frame, text="Yhdistä toiseen", variable=self.mode_var, value="client")
        host_rb.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        client_rb.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(conn_frame, text="Osoite (client):").grid(row=1, column=0, sticky="e", padx=5, pady=2)
        self.host_var = tk.StringVar(value="127.0.0.1")
        host_entry = ttk.Entry(conn_frame, textvariable=self.host_var, width=25)
        host_entry.grid(row=1, column=1, sticky="w", padx=5, pady=2)

        ttk.Label(conn_frame, text="Portti:").grid(row=1, column=2, sticky="e", padx=5, pady=2)
        self.port_var = tk.StringVar(value="4444")
        port_entry = ttk.Entry(conn_frame, textvariable=self.port_var, width=8)
        port_entry.grid(row=1, column=3, sticky="w", padx=5, pady=2)

        self.connect_btn = ttk.Button(conn_frame, text="Käynnistä", command=self._on_connect_clicked)
        self.connect_btn.grid(row=1, column=4, sticky="w", padx=8, pady=2)

        conn_frame.columnconfigure(1, weight=1)

        # Vastapuoli
        peer_frame = ttk.LabelFrame(mainframe, text="Vastapuoli")
        peer_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(peer_frame, text="Vastapuolen sormenjälki:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.peer_fp_var = tk.StringVar(value="(ei vielä kättelyä)")
        peer_fp_entry = ttk.Entry(peer_frame, textvariable=self.peer_fp_var, state="readonly")
        peer_fp_entry.grid(row=0, column=1, sticky="we", padx=5, pady=5)
        peer_frame.columnconfigure(1, weight=1)

        # Chat-alue
        chat_frame = ttk.Frame(mainframe)
        chat_frame.pack(fill="both", expand=True, pady=(0, 5))
        self.chat = scrolledtext.ScrolledText(chat_frame, height=20, state="disabled", wrap="word", font=("Segoe UI", 10))
        self.chat.pack(fill="both", expand=True)
        self.chat.tag_config("me", foreground="blue")
        self.chat.tag_config("peer", foreground="green")
        self.chat.tag_config("system", foreground="gray")

        # Viestin syöttö
        msg_frame = ttk.Frame(mainframe)
        msg_frame.pack(fill="x")
        self.msg_var = tk.StringVar()
        msg_entry = ttk.Entry(msg_frame, textvariable=self.msg_var)
        msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        msg_entry.bind("<Return>", self._on_send)
        self.send_btn = ttk.Button(msg_frame, text="Lähetä", command=self._on_send)
        self.send_btn.pack(side="right")
        self.send_btn["state"] = "disabled"

        # Statuspalkki
        self.status_var = tk.StringVar(value="Valmis.")
        status_label = ttk.Label(self.root, textvariable=self.status_var, anchor="w", relief="sunken")
        status_label.pack(fill="x", side="bottom")

    def _on_connect_clicked(self):
        mode = self.mode_var.get()
        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("Virhe", "Portin on oltava numero.")
            return

        if mode == "host":
            host = "0.0.0.0"
            self.core.start_host(host, port)
            self._append_system(f"Aloitetaan kuuntelu portissa {port}.")
        else:
            host = self.host_var.get().strip()
            if not host:
                messagebox.showerror("Virhe", "Anna palvelimen osoite.")
                return
            self.core.start_client(host, port)
            self._append_system(f"Yhdistetään {host}:{port} ...")

        self.connect_btn["state"] = "disabled"

    def _on_send(self, event=None):
        text = self.msg_var.get().strip()
        if not text:
            return
        self.core.send_text(text)
        self.msg_var.set("")

    def _poll_events(self):
        try:
            while True:
                ev = self.event_queue.get_nowait()
                self._handle_event(ev)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_events)

    def _handle_event(self, ev):
        etype = ev[0]
        if etype == "status":
            self.status_var.set(ev[1])
        elif etype == "my_fp":
            self.fp_var.set(ev[1])
        elif etype == "peer_fp":
            self.peer_fp_var.set(ev[1])
            self._append_system("Kättely valmis. Vertailkaa sormenjäljet toista kanavaa pitkin.")
        elif etype == "connected":
            self.connected = True
            self.send_btn["state"] = "normal"
            self._append_system("Yhteys muodostettu ja salattu.")
        elif etype == "disconnected":
            if self.connected:
                self._append_system("Yhteys katkaistu.")
            self.connected = False
            self.send_btn["state"] = "disabled"
            self.connect_btn["state"] = "normal"
        elif etype == "system":
            self._append_system(ev[1])
        elif etype == "error":
            self._append_system("[Virhe] " + ev[1])
            self.status_var.set(ev[1])
            if not self.connected:
                self.connect_btn["state"] = "normal"
        elif etype == "recv_msg":
            text, ts = ev[1]
            t = datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "?"
            self._append_chat(f"[{t}] Vastapuoli: {text}\n", "peer")
        elif etype == "sent_msg":
            text, ts = ev[1]
            t = datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "?"
            self._append_chat(f"[{t}] Minä: {text}\n", "me")
        elif etype == "ack":
            orig_text, orig_ts, ack_ts = ev[1]
            t = datetime.fromtimestamp(ack_ts).strftime("%H:%M:%S") if ack_ts else "?"
            self._append_chat(f"[{t}] ✔ Viesti luettu: {orig_text}\n", "system")

    def _append_chat(self, text, tag=None):
        self.chat.configure(state="normal")
        if tag:
            self.chat.insert("end", text, tag)
        else:
            self.chat.insert("end", text)
        self.chat.see("end")
        self.chat.configure(state="disabled")

    def _append_system(self, text):
        self._append_chat("* " + text + "\n", "system")

    def _on_close(self):
        self.core.stop()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()
