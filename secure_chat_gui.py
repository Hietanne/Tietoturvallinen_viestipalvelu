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
from nacl.secret import SecretBox

# UPnP (porttien automaattinen avaus WAN-suoraa varten)
try:
    import miniupnpc
except ImportError:
    miniupnpc = None


class UpnpPortMapper:
    def __init__(self):
        self.upnp = None
        self.external_ip = None
        self.external_port = None
        self.internal_port = None

    def try_map(self, internal_port: int, description="SecureChat"):
        """Yritä avata TCP-portti reitittimestä UPnP:llä."""
        if miniupnpc is None:
            return None

        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 2000  # 2 s
        try:
            upnp.discover()
            upnp.selectigd()
        except Exception:
            return None

        self.upnp = upnp
        self.internal_port = internal_port

        try:
            external_port = internal_port
            upnp.addportmapping(
                external_port,
                'TCP',
                upnp.lanaddr,
                internal_port,
                description,
                ''
            )
            self.external_ip = upnp.externalipaddress()
            self.external_port = external_port
            return f"{self.external_ip}:{self.external_port}"
        except Exception:
            return None

    def remove_mapping(self):
        if self.upnp and self.external_port:
            try:
                self.upnp.deleteportmapping(self.external_port, 'TCP')
            except Exception:
                pass


IDENTITY_KEY_FILE = "id_ed25519.key"
KNOWN_PEERS_FILE = "known_peers.json"
CHAIN_NONCE = b"\x00" * 24  # ratchet-seedin kiinteä nonce (käytetään vain kerran)


# ---------- Identiteetti & tunnetut vastapuolet ----------

def load_or_create_identity(path=IDENTITY_KEY_FILE):
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


def load_known_peers(path=KNOWN_PEERS_FILE):
    """Palauttaa rakenteen: { 'proxy': {room: fp}, 'direct': {host:port: fp}, 'incoming': {...} }."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError
    except Exception:
        data = {"proxy": {}, "direct": {}, "incoming": {}}
    for key in ("proxy", "direct", "incoming"):
        data.setdefault(key, {})
    return data


def save_known_peers(data, path=KNOWN_PEERS_FILE):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


# ---------- Framit ----------

def send_frame(sock, data: bytes):
    header = struct.pack("!I", len(data))
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


# ---------- Kättely ----------

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


def perform_handshake(sock, identity_sk: SigningKey):
    """
    Symmetrinen kättely (molemmat tekevät saman):
      - generoi ephemeral-avaimen
      - lähettää oman handshake-viestin
      - lukee vastapuolen handshake-viestin
      - muodostaa Box-olion (ephemeral ECDH)
    """
    eph_sk = PrivateKey.generate()
    outbound = make_handshake_message(identity_sk, eph_sk)
    send_frame(sock, outbound)
    inbound = recv_frame(sock)
    if inbound is None:
        raise RuntimeError("Connection closed during handshake")
    peer_eph_pk, peer_fp = parse_handshake_message(inbound)
    box = Box(eph_sk, peer_eph_pk)
    return box, peer_fp


# ---------- Ratchet-session ----------

def derive_chain_root(box: Box):
    """
    Johdetaan yhteinen juuriavain käyttämällä Boxia deterministisen 'CHAIN_SEED' -salauksen kanssa
    kiinteällä nonce-arvolla (CHAIN_NONCE). Tätä ei käytetä viesteihin, vain avainjohdantaan.
    """
    seed_ct = box.encrypt(b"CHAIN_SEED", nonce=CHAIN_NONCE)
    return hashlib.sha256(seed_ct.ciphertext).digest()


class RatchetSession:
    """
    Yksinkertaistettu "Double Ratchet" -tyylinen ketju:

    - Kumpikin osapuoli laskee saman juuriavaimen (chain_root) Boxin avulla.
    - Sen jälkeen johdetaan erilliset lähetys- ja vastaanottoketjut:
        - osapuoli, jonka sormenjälki on "pienempi", käyttää:
          send = H(root + 'S'), recv = H(root + 'R')
        - toinen päinvastoin
    - Jokainen viesti:
        - käyttää uutta msg-key:tä ketjusta
        - sisältää seq-numeron
        - voidaan varmistaa replay-hyökkäyksiä vastaan
    """

    def __init__(self, send_ck: bytes, recv_ck: bytes):
        self.send_chain_key = send_ck
        self.recv_chain_key = recv_ck
        self.send_seq = 0
        self.recv_seq = 0

    @staticmethod
    def _kdf_chain(chain_key: bytes):
        h = hashlib.sha512(chain_key).digest()
        return h[:32], h[32:]  # msg_key, next_chain_key

    @classmethod
    def from_box(cls, box: Box, my_fp: str, peer_fp: str):
        root = derive_chain_root(box)
        if my_fp < peer_fp:
            send_ck = hashlib.sha256(root + b"S").digest()
            recv_ck = hashlib.sha256(root + b"R").digest()
        else:
            send_ck = hashlib.sha256(root + b"R").digest()
            recv_ck = hashlib.sha256(root + b"S").digest()
        return cls(send_ck, recv_ck)

    def encrypt_message(self, msg_obj: dict) -> bytes:
        """
        Lisää seq, tekee kevyen paddingin ja salaa viestin SecretBoxilla
        ratchet-ketjun seuraavalla avaimella.
        """
        self.send_seq += 1
        payload = dict(msg_obj)
        payload["seq"] = self.send_seq

        inner = json.dumps(payload).encode("utf-8")

        # Peruspadding: jos viesti on < 512 tavua, täytetään satunnaisella datalla
        if len(inner) < 512:
            pad_len = 512 - len(inner)
            pad = os.urandom(pad_len)
            outer = {
                "m": payload,
                "p": base64.b64encode(pad).decode("ascii")
            }
            plaintext = json.dumps(outer).encode("utf-8")
        else:
            plaintext = inner

        msg_key, self.send_chain_key = self._kdf_chain(self.send_chain_key)
        box = SecretBox(msg_key)
        ct = box.encrypt(plaintext)  # SecretBox generoi satunnaisen noncen
        return ct

    def decrypt_message(self, frame: bytes) -> dict:
        """
        Purkaa yhden viestin, tarkistaa seq-numeron ja replayn.
        """
        msg_key, self.recv_chain_key = self._kdf_chain(self.recv_chain_key)
        box = SecretBox(msg_key)
        try:
            plaintext = box.decrypt(frame)
        except CryptoError as e:
            raise RuntimeError("Decryption failed – possible tampering") from e

        data = json.loads(plaintext.decode("utf-8"))
        if "m" in data:
            payload = data["m"]
        else:
            payload = data

        seq = payload.get("seq")
        if not isinstance(seq, int):
            raise RuntimeError("Missing sequence number in message")
        if seq <= self.recv_seq:
            raise RuntimeError("Replay or out-of-order message detected")
        self.recv_seq = seq
        return payload


# ---------- Ydin: server + client + proxy ----------

class SecureChatCore:
    def __init__(self, event_queue: "queue.Queue"):
        self.event_queue = event_queue
        self.identity_sk, self.identity_vk, self.my_fingerprint, created = load_or_create_identity()

        self.listen_sock = None
        self.listen_thread = None
        self.listen_running = False

        self.sock = None
        self.session: RatchetSession | None = None
        self.recv_thread = None
        self.conn_active = False

        self.pending = {}
        self.pending_lock = threading.Lock()
        self.sock_lock = threading.Lock()

        # Identity pinning -konteksti
        self.context_type = None  # "direct", "proxy", "incoming"
        self.context_key = None   # esim. "ip:port" tai "huonekoodi"

        if created:
            self.event_queue.put(("status", "Luotiin uusi identiteetti tälle laitteelle."))
        else:
            self.event_queue.put(("status", "Käytetään olemassa olevaa identiteettiä."))
        self.event_queue.put(("my_fp", self.my_fingerprint))

    # ---- Kuuntelu (suora P2P) ----

    def start_listener(self, host: str, port: int):
        if self.listen_running:
            self.event_queue.put(("status", f"Kuuntelu on jo käynnissä portissa {port}."))
            return
        self.listen_running = True
        self.listen_thread = threading.Thread(target=self._listen_loop, args=(host, port), daemon=True)
        self.listen_thread.start()

    def _listen_loop(self, host: str, port: int):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock = srv
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((host, port))
            srv.listen(5)
            self.event_queue.put(("status", f"Kuunnellaan {host}:{port} (suora P2P / LAN / mahdollinen WAN)."))
            while self.listen_running:
                try:
                    srv.settimeout(1.0)
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                self.event_queue.put(("status", f"Saapuva suora yhteys {addr}"))
                if self.conn_active:
                    self.event_queue.put(("system", "Uusi saapuva yhteys hylätty (yhteys on jo aktiivinen)."))
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
                t = threading.Thread(target=self._handle_new_direct_connection, args=(conn, addr), daemon=True)
                t.start()
        except Exception as e:
            self.event_queue.put(("error", f"Kuunteluvirhe: {e}"))
        finally:
            try:
                srv.close()
            except OSError:
                pass
            self.listen_sock = None
            self.listen_running = False
            self.event_queue.put(("status", "Kuuntelu pysäytetty."))

    def _handle_new_direct_connection(self, conn: socket.socket, addr):
        with self.sock_lock:
            self.sock = conn
        self.context_type = "incoming"
        self.context_key = f"{addr[0]}:{addr[1]}"
        try:
            box, peer_fp = perform_handshake(conn, self.identity_sk)
            session = RatchetSession.from_box(box, self.my_fingerprint, peer_fp)
        except Exception as e:
            self.event_queue.put(("error", f"Kättely epäonnistui (saapuva suora): {e}"))
            self._clear_connection()
            return
        self.session = session
        self.conn_active = True
        self.event_queue.put(("peer_fp", (peer_fp, self.context_type, self.context_key)))
        self.event_queue.put(("connected", f"Suora saapuva yhteys {addr}"))
        self._start_recv_loop()

    # ---- Ulospäin yhdistäminen suoraan ----

    def connect_direct(self, host: str, port: int):
        if self.conn_active:
            self.event_queue.put(("error", "Yhteys on jo aktiivinen. Katkaise ensin."))
            return
        self.context_type = "direct"
        self.context_key = f"{host}:{port}"
        t = threading.Thread(target=self._connect_direct_thread, args=(host, port), daemon=True)
        t.start()

    def _connect_direct_thread(self, host: str, port: int):
        self.event_queue.put(("status", f"Yhdistetään suoraan {host}:{port} ..."))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, port))
            with self.sock_lock:
                self.sock = sock
            try:
                box, peer_fp = perform_handshake(sock, self.identity_sk)
                session = RatchetSession.from_box(box, self.my_fingerprint, peer_fp)
            except Exception as e:
                self.event_queue.put(("error", f"Kättely epäonnistui (lähtevä suora): {e}"))
                self._clear_connection()
                return
            self.session = session
            self.conn_active = True
            self.event_queue.put(("peer_fp", (peer_fp, self.context_type, self.context_key)))
            self.event_queue.put(("connected", f"Suora yhteys {host}:{port}"))
            self._start_recv_loop()
        except Exception as e:
            self.event_queue.put(("error", f"Suora yhteys epäonnistui: {e}"))
            self._clear_connection()

    # ---- Yhdistäminen välipalvelimen (proxy) kautta ----

    def connect_via_proxy(self, proxy_host: str, proxy_port: int, room: str):
        if self.conn_active:
            self.event_queue.put(("error", "Yhteys on jo aktiivinen. Katkaise ensin."))
            return
        self.context_type = "proxy"
        self.context_key = room
        t = threading.Thread(target=self._connect_proxy_thread, args=(proxy_host, proxy_port, room), daemon=True)
        t.start()

    def _connect_proxy_thread(self, proxy_host: str, proxy_port: int, room: str):
        self.event_queue.put(("status", f"Yhdistetään välipalvelimeen {proxy_host}:{proxy_port}, huone '{room}' ..."))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((proxy_host, proxy_port))
            join_msg = {"type": "join", "room": room}
            send_frame(sock, json.dumps(join_msg).encode("utf-8"))
            with self.sock_lock:
                self.sock = sock
            try:
                box, peer_fp = perform_handshake(sock, self.identity_sk)
                session = RatchetSession.from_box(box, self.my_fingerprint, peer_fp)
            except Exception as e:
                self.event_queue.put(("error", f"Kättely epäonnistui (proxy): {e}"))
                self._clear_connection()
                return
            self.session = session
            self.conn_active = True
            self.event_queue.put(("peer_fp", (peer_fp, self.context_type, self.context_key)))
            self.event_queue.put(("connected", f"Yhteys välipalvelimen kautta huoneessa '{room}'"))
            self._start_recv_loop()
        except Exception as e:
            self.event_queue.put(("error", f"Yhteys välipalvelimeen epäonnistui: {e}"))
            self._clear_connection()

    # ---- Vastaanottosilmukka ----

    def _start_recv_loop(self):
        self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self.recv_thread.start()

    def _recv_loop(self):
        self.event_queue.put(("status", "Viestien vastaanotto käynnissä."))
        try:
            while self.conn_active and self.sock and self.session:
                frame = recv_frame(self.sock)
                if frame is None:
                    break
                try:
                    msg = self.session.decrypt_message(frame)
                except Exception as e:
                    self.event_queue.put(("error", f"Vastaanottovirhe (salaus): {e}"))
                    break
                mtype = msg.get("type")
                if mtype == "msg":
                    mid = msg.get("id")
                    text = msg.get("text")
                    ts = msg.get("ts")
                    self.event_queue.put(("recv_msg", (text, ts)))
                    ack = {"type": "ack", "msg_id": mid, "ts": time.time()}
                    try:
                        ct = self.session.encrypt_message(ack)
                        send_frame(self.sock, ct)
                    except Exception as e:
                        self.event_queue.put(("error", f"Ack-lähetys epäonnistui: {e}"))
                elif mtype == "ack":
                    mid = msg.get("msg_id")
                    ack_ts = msg.get("ts")
                    with self.pending_lock:
                        orig = self.pending.pop(mid, None)
                    if orig:
                        self.event_queue.put(("ack", (orig.get("text"), orig.get("ts"), ack_ts)))
        except Exception as e:
            self.event_queue.put(("error", f"Vastaanottovirhe: {e}"))
        self.event_queue.put(("status", "Yhteys katkaistu."))
        self.event_queue.put(("disconnected", ""))
        self._clear_connection()

    # ---- Lähetys & katkaisu ----

    def send_text(self, text: str):
        if not self.conn_active or not self.sock or not self.session:
            self.event_queue.put(("error", "Ei aktiivista yhteyttä."))
            return
        msg_id = uuid.uuid4().hex
        ts = time.time()
        msg = {"type": "msg", "id": msg_id, "text": text, "ts": ts}
        try:
            with self.pending_lock:
                self.pending[msg_id] = msg
            ct = self.session.encrypt_message(msg)
            send_frame(self.sock, ct)
            self.event_queue.put(("sent_msg", (text, ts)))
        except Exception as e:
            self.event_queue.put(("error", f"Lähetysvirhe: {e}"))

    def disconnect(self):
        self.event_queue.put(("status", "Katkaistaan yhteys..."))
        self._clear_connection()
        self.event_queue.put(("disconnected", ""))

    def _clear_connection(self):
        self.conn_active = False
        self.session = None
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
        with self.pending_lock:
            self.pending.clear()

    def stop(self):
        self.listen_running = False
        if self.listen_sock:
            try:
                self.listen_sock.close()
            except OSError:
                pass
        self.disconnect()
        self.event_queue.put(("status", "Sovellus pysäytetty."))


# ---------- IP-osoitteiden selvittäminen ----------

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "tuntematon"


def get_wan_ip():
    try:
        import urllib.request
        urls = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
        ]
        for url in urls:
            try:
                with urllib.request.urlopen(url, timeout=3) as resp:
                    data = resp.read().decode("utf-8").strip()
                    if data:
                        return data
            except Exception:
                continue
    except Exception:
        pass
    return "tuntematon"


# ---------- GUI ----------

class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Tietoturvallinen P2P-viestintä (LAN + Proxy + UPnP + Ratchet)")
        self.root.geometry("1050x750")

        self.event_queue = queue.Queue()
        self.core = SecureChatCore(self.event_queue)

        self.connected = False
        self.upnp_mapper = UpnpPortMapper()

        self._build_ui()
        self.root.after(100, self._poll_events)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._update_ips_async()

    def _build_ui(self):
        mainframe = ttk.Frame(self.root, padding=10)
        mainframe.pack(fill="both", expand=True)

        title = ttk.Label(mainframe, text="Tietoturvallinen P2P-viestintä", font=("Segoe UI", 16, "bold"))
        title.pack(anchor="w", pady=(0, 5))

        subtitle = ttk.Label(
            mainframe,
            text="Vihje: LANissa käytä suoraa IP-yhteyttä. WANissa käytä mieluiten välipalvelinta (proxy). "
                 "UPnP yrittää avata automaattisesti WAN-suoran portin. Viestit ovat päästä päähän salattuja "
                 "ja käyttävät ratchet-avaimia (eri avain jokaiselle viestille).",
            wraplength=1000,
            foreground="gray"
        )
        subtitle.pack(anchor="w", pady=(0, 10))

        # Oma identiteetti
        id_frame = ttk.LabelFrame(mainframe, text="Oma identiteetti")
        id_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(id_frame, text="Sormenjälki (SHA-256):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.fp_var = tk.StringVar(value="–")
        fp_entry = ttk.Entry(id_frame, textvariable=self.fp_var, width=80, state="readonly")
        fp_entry.grid(row=0, column=1, sticky="we", padx=5, pady=5)
        hint = ttk.Label(
            id_frame,
            text="Vihje: Vertailkaa sormenjälkiä toista kanavaa pitkin (esim. puhelu/viesti) varmistaaksenne, "
                 "ettei kukaan ole välissä.",
            foreground="gray",
            wraplength=800
        )
        hint.grid(row=1, column=0, columnspan=2, sticky="w", padx=5, pady=(0, 5))
        id_frame.columnconfigure(1, weight=1)

        # Omat IP:t
        ip_frame = ttk.LabelFrame(mainframe, text="Omat osoitteet")
        ip_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(ip_frame, text="LAN IP (sisäverkko):").grid(row=0, column=0, sticky="e", padx=5, pady=2)
        self.lan_ip_var = tk.StringVar(value="(selvitetään...)")
        lan_entry = ttk.Entry(ip_frame, textvariable=self.lan_ip_var, state="readonly")
        lan_entry.grid(row=0, column=1, sticky="we", padx=5, pady=2)

        ttk.Label(ip_frame, text="WAN IP (julkinen):").grid(row=1, column=0, sticky="e", padx=5, pady=2)
        self.wan_ip_var = tk.StringVar(value="(selvitetään...)")
        wan_entry = ttk.Entry(ip_frame, textvariable=self.wan_ip_var, state="readonly")
        wan_entry.grid(row=1, column=1, sticky="we", padx=5, pady=2)

        ttk.Label(ip_frame, text="WAN-suora osoite (UPnP):").grid(row=2, column=0, sticky="e", padx=5, pady=2)
        self.wan_direct_var = tk.StringVar(value="(ei saatavilla)")
        wan_direct_entry = ttk.Entry(ip_frame, textvariable=self.wan_direct_var, state="readonly")
        wan_direct_entry.grid(row=2, column=1, sticky="we", padx=5, pady=2)

        self.ip_refresh_btn = ttk.Button(ip_frame, text="Päivitä osoitteet", command=self._update_ips_async)
        self.ip_refresh_btn.grid(row=0, column=2, rowspan=3, sticky="nsw", padx=5, pady=2)

        ip_hint = ttk.Label(
            ip_frame,
            text="LAN IP: käytä tätä osoitetta, kun toinen on samassa sisäverkossa.\n"
                 "WAN-suora (UPnP): jos tähän ilmestyy osoite, toinen voi yhdistää siihen suoraan myös Internetistä. "
                 "Muussa tapauksessa käytä Proxy-vaihtoehtoa WANissa.",
            foreground="gray",
            wraplength=800
        )
        ip_hint.grid(row=3, column=0, columnspan=3, sticky="w", padx=5, pady=(5, 2))

        ip_frame.columnconfigure(1, weight=1)

        # Yhteysasetukset
        conn_frame = ttk.LabelFrame(mainframe, text="Yhteysasetukset (LAN / WAN / Proxy)")
        conn_frame.pack(fill="x", pady=(0, 10))

        # Kuuntelu (suora)
        ttk.Label(conn_frame, text="Oma kuunteluportti (suora P2P):").grid(row=0, column=0, sticky="e", padx=5, pady=2)
        self.listen_port_var = tk.StringVar(value="4433")
        listen_port_entry = ttk.Entry(conn_frame, textvariable=self.listen_port_var, width=8)
        listen_port_entry.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        self.listen_btn = ttk.Button(conn_frame, text="Käynnistä kuuntelu", command=self._on_listen_clicked)
        self.listen_btn.grid(row=0, column=2, sticky="w", padx=5, pady=2)

        listen_hint = ttk.Label(
            conn_frame,
            text="Vihje: Paina 'Käynnistä kuuntelu' koneella, johon halutaan yhdistää. LANissa toinen käyttää "
                 "LAN IP:täsi. WANissa voit kokeilla WAN-suoraa (UPnP) tai käyttää Proxyä.",
            foreground="gray",
            wraplength=800
        )
        listen_hint.grid(row=1, column=0, columnspan=7, sticky="w", padx=5, pady=(0, 5))

        # Suora yhteys
        ttk.Label(conn_frame, text="Suora yhteys: IP:").grid(row=2, column=0, sticky="e", padx=5, pady=2)
        self.remote_host_var = tk.StringVar(value="127.0.0.1")
        remote_host_entry = ttk.Entry(conn_frame, textvariable=self.remote_host_var, width=20)
        remote_host_entry.grid(row=2, column=1, sticky="w", padx=5, pady=2)

        ttk.Label(conn_frame, text="Portti:").grid(row=2, column=2, sticky="e", padx=5, pady=2)
        self.remote_port_var = tk.StringVar(value="4433")
        remote_port_entry = ttk.Entry(conn_frame, textvariable=self.remote_port_var, width=8)
        remote_port_entry.grid(row=2, column=3, sticky="w", padx=5, pady=2)

        self.connect_direct_btn = ttk.Button(conn_frame, text="Yhdistä suoraan", command=self._on_connect_direct_clicked)
        self.connect_direct_btn.grid(row=2, column=4, sticky="w", padx=5, pady=2)

        direct_hint = ttk.Label(
            conn_frame,
            text="Vihje: Syötä toisen koneen LAN IP ja portti (esim. 4433) jos olette samassa verkossa. "
                 "Tai syötä WAN-suora osoite, jos UPnP on avannut portin.",
            foreground="gray",
            wraplength=800
        )
        direct_hint.grid(row=3, column=0, columnspan=7, sticky="w", padx=5, pady=(0, 5))

        # Proxy-yhteys
        ttk.Label(conn_frame, text="Välipalvelin (proxy) host:").grid(row=4, column=0, sticky="e", padx=5, pady=2)
        self.proxy_host_var = tk.StringVar(value="127.0.0.1")
        proxy_host_entry = ttk.Entry(conn_frame, textvariable=self.proxy_host_var, width=20)
        proxy_host_entry.grid(row=4, column=1, sticky="w", padx=5, pady=2)

        ttk.Label(conn_frame, text="Portti:").grid(row=4, column=2, sticky="e", padx=5, pady=2)
        self.proxy_port_var = tk.StringVar(value="9000")
        proxy_port_entry = ttk.Entry(conn_frame, textvariable=self.proxy_port_var, width=8)
        proxy_port_entry.grid(row=4, column=3, sticky="w", padx=5, pady=2)

        ttk.Label(conn_frame, text="Huonekoodi:").grid(row=4, column=4, sticky="e", padx=5, pady=2)
        self.room_var = tk.StringVar(value="huone1")
        room_entry = ttk.Entry(conn_frame, textvariable=self.room_var, width=15)
        room_entry.grid(row=4, column=5, sticky="w", padx=5, pady=2)

        self.connect_proxy_btn = ttk.Button(conn_frame, text="Yhdistä proxyllä", command=self._on_connect_proxy_clicked)
        self.connect_proxy_btn.grid(row=4, column=6, sticky="w", padx=5, pady=2)

        proxy_hint = ttk.Label(
            conn_frame,
            text="Vihje: Proxy on varmin tapa WAN-yhteyteen. Aja 'relay_server.py' jollain julkisella koneella "
                 "(esim. VPS), syötä sen IP/domain ja portti tähän. Molempien on käytettävä samaa huonekoodia.",
            foreground="gray",
            wraplength=800
        )
        proxy_hint.grid(row=5, column=0, columnspan=7, sticky="w", padx=5, pady=(0, 5))

        # Katkaise
        self.disconnect_btn = ttk.Button(conn_frame, text="Katkaise", command=self._on_disconnect_clicked)
        self.disconnect_btn.grid(row=6, column=6, sticky="w", padx=5, pady=2)
        self.disconnect_btn["state"] = "disabled"

        conn_frame.columnconfigure(1, weight=1)

        # Vastapuoli
        peer_frame = ttk.LabelFrame(mainframe, text="Vastapuoli")
        peer_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(peer_frame, text="Vastapuolen sormenjälki:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.peer_fp_var = tk.StringVar(value="(ei vielä kättelyä)")
        peer_fp_entry = ttk.Entry(peer_frame, textvariable=self.peer_fp_var, state="readonly")
        peer_fp_entry.grid(row=0, column=1, sticky="we", padx=5, pady=5)
        peer_hint = ttk.Label(
            peer_frame,
            text="Vihje: kun yhteys on muodostettu, varmista ääni- tai tekstiviestillä, että tämä sormenjälki "
                 "vastaa toisen näyttämää – näin havaitset mahdollisen hyökkääjän.",
            foreground="gray",
            wraplength=800
        )
        peer_hint.grid(row=1, column=0, columnspan=2, sticky="w", padx=5, pady=(0, 5))
        peer_frame.columnconfigure(1, weight=1)

        # Chat
        chat_frame = ttk.Frame(mainframe)
        chat_frame.pack(fill="both", expand=True, pady=(0, 5))
        self.chat = scrolledtext.ScrolledText(chat_frame, height=18, state="disabled", wrap="word", font=("Segoe UI", 10))
        self.chat.pack(fill="both", expand=True)
        self.chat.tag_config("me", foreground="blue")
        self.chat.tag_config("peer", foreground="green")
        self.chat.tag_config("system", foreground="gray")

        # Viesti
        msg_frame = ttk.Frame(mainframe)
        msg_frame.pack(fill="x")
        self.msg_var = tk.StringVar()
        msg_entry = ttk.Entry(msg_frame, textvariable=self.msg_var)
        msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        msg_entry.bind("<Return>", self._on_send)
        self.send_btn = ttk.Button(msg_frame, text="Lähetä", command=self._on_send)
        self.send_btn.pack(side="right")
        self.send_btn["state"] = "disabled"

        # Status
        self.status_var = tk.StringVar(value="Valmis.")
        status_label = ttk.Label(self.root, textvariable=self.status_var, anchor="w", relief="sunken")
        status_label.pack(fill="x", side="bottom")

    # ---- IP:n päivitys ----

    def _update_ips_async(self):
        def worker():
            lan = get_lan_ip()
            wan = get_wan_ip()
            self.event_queue.put(("ips", (lan, wan)))
        threading.Thread(target=worker, daemon=True).start()

    # ---- Button-handlerit ----

    def _on_listen_clicked(self):
        try:
            port = int(self.listen_port_var.get())
        except ValueError:
            messagebox.showerror("Virhe", "Portin on oltava numero.")
            return

        self.core.start_listener("0.0.0.0", port)
        self._append_system(f"Aloitettiin suora kuuntelu portissa {port}.")
        self.listen_btn["state"] = "disabled"

        # Yritä UPnP-portinavausta
        self._append_system("Yritetään automaattista UPnP-portinavausta WAN-suoraa varten...")
        direct = self.upnp_mapper.try_map(port, "SecureChat")
        if direct:
            self.wan_direct_var.set(direct)
            self._append_system(f"UPnP avasi WAN-suoran osoitteen: {direct}")
        else:
            self._append_system(
                "UPnP-portinavaus ei onnistunut (reititin ei tue, estetty tai CG-NAT). "
                "WANissa käytä tällöin välipalvelinta (proxy)."
            )

    def _on_connect_direct_clicked(self):
        host = self.remote_host_var.get().strip()
        if not host:
            messagebox.showerror("Virhe", "Anna IP-osoite.")
            return
        try:
            port = int(self.remote_port_var.get())
        except ValueError:
            messagebox.showerror("Virhe", "Portin on oltava numero.")
            return
        self.core.connect_direct(host, port)
        self._append_system(f"Yritetään suoraa yhteyttä {host}:{port} ...")
        self.connect_direct_btn["state"] = "disabled"

    def _on_connect_proxy_clicked(self):
        proxy_host = self.proxy_host_var.get().strip()
        if not proxy_host:
            messagebox.showerror("Virhe", "Anna välipalvelimen osoite.")
            return
        try:
            proxy_port = int(self.proxy_port_var.get())
        except ValueError:
            messagebox.showerror("Virhe", "Proxy-portin on oltava numero.")
            return
        room = self.room_var.get().strip()
        if not room:
            messagebox.showerror("Virhe", "Huonekoodi ei voi olla tyhjä.")
            return
        self.core.connect_via_proxy(proxy_host, proxy_port, room)
        self._append_system(f"Yritetään yhteyttä välipalvelimen kautta huoneeseen '{room}' ...")
        self.connect_proxy_btn["state"] = "disabled"

    def _on_disconnect_clicked(self):
        self.core.disconnect()

    def _on_send(self, event=None):
        text = self.msg_var.get().strip()
        if not text:
            return
        self.core.send_text(text)
        self.msg_var.set("")

    # ---- Event queue ----

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
            # (peer_fp, context_type, context_key)
            peer_fp, ctype, ckey = ev[1]
            self.peer_fp_var.set(peer_fp)
            self._append_system("Kättely valmis. Varmista sormenjäljet toista kanavaa pitkin.")

            # Identity pinning
            data = load_known_peers()
            changed = False
            prev_fp = None

            if ctype == "proxy":
                prev_fp = data.get("proxy", {}).get(ckey)
                if prev_fp and prev_fp != peer_fp:
                    changed = True
                data.setdefault("proxy", {})[ckey] = peer_fp
            elif ctype == "direct":
                prev_fp = data.get("direct", {}).get(ckey)
                if prev_fp and prev_fp != peer_fp:
                    changed = True
                data.setdefault("direct", {})[ckey] = peer_fp
            elif ctype == "incoming":
                prev_fp = data.get("incoming", {}).get(ckey)
                if prev_fp and prev_fp != peer_fp:
                    changed = True
                data.setdefault("incoming", {})[ckey] = peer_fp

            save_known_peers(data)

            if prev_fp is None:
                self._append_system("Uusi vastapuolen identiteetti tässä kontekstissa (huonekoodi/IP). "
                                    "Tallenetaan sormenjälki tunnetuksi.")
            elif changed:
                self._append_system("VAROITUS: tässä kontekstissa on aiemmin nähty eri sormenjälki. "
                                    "Voi olla uusi laite tai mahdollinen hyökkäys.")

        elif etype == "connected":
            self.connected = True
            self.send_btn["state"] = "normal"
            self.disconnect_btn["state"] = "normal"
            self._append_system("Yhteys muodostettu ja salattu ratchet-avaimilla. " + str(ev[1]))

        elif etype == "disconnected":
            if self.connected:
                self._append_system("Yhteys katkaistu.")
            self.connected = False
            self.send_btn["state"] = "disabled"
            self.disconnect_btn["state"] = "disabled"
            self.connect_direct_btn["state"] = "normal"
            self.connect_proxy_btn["state"] = "normal"

        elif etype == "system":
            self._append_system(ev[1])

        elif etype == "error":
            self._append_system("[Virhe] " + ev[1])
            self.status_var.set(ev[1])
            if not self.connected:
                self.connect_direct_btn["state"] = "normal"
                self.connect_proxy_btn["state"] = "normal"

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

        elif etype == "ips":
            lan, wan = ev[1]
            self.lan_ip_var.set(lan)
            self.wan_ip_var.set(wan)

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
        try:
            self.upnp_mapper.remove_mapping()
        except Exception:
            pass
        self.core.stop()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()