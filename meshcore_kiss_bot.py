#!/usr/bin/env python3
"""
meshcore_kiss_bot.py — Command bot for a MeshCore KISS-modem radio.

A dedicated MeshCore node flashed with the "KISS Modem" firmware sits on a
hashtag channel (e.g. "#bot"), watches for command messages ("!ping",
"!help", ...) and replies on the same channel. Because hashtag channel keys
are derived from the channel name, senders do not need to be contacts to use
the channel commands.

On every (re)connect the script first configures the radio's frequency /
bandwidth / spreading factor / coding rate / TX power over the KISS
SetHardware (0x06) channel, because the KISS modem firmware does NOT persist
radio settings across reboot. It then reads the modem's Ed25519 identity and
parses the KISS frame stream, answering commands.

HEARTBEATS (opt-in, per user, direct):
  !heartbeaton    start heartbeats for the sender, for up to 24 hours
                  (sending it again restarts the 24 hours; they never stack)
  !heartbeatoff   stop them
  !heartbeat      show whether they're on and how long is left
Heartbeats are NOT posted to the channel. Each one is a direct (DIRECT-routed,
end-to-end encrypted) MeshCore text message to that user, sent every
--heartbeat-interval seconds along the reverse of the repeater path the
user's last channel message arrived by. A final direct message tells the user
when the 24 hours run out. Subscriptions are stored in the SQLite database,
so they survive restarts.

How the bot reaches a user it has never met: it listens for signed ADVERT
packets on the air and remembers each chat node's name -> public key. When
"Alice" sends !heartbeaton, the bot looks up the key it heard advertised as
"Alice". If it hasn't heard one, it asks her to send an advert and try again.
For her node to accept and show the bot's direct messages, she normally has to
have the bot as a contact, so the bot also broadcasts its own signed advert
(at startup, every --advert-interval hours, and when someone enables
heartbeats). Delivery is best-effort: the bot does not process ACKs or retry.

MESSAGE LOGGING: every channel message heard, every message sent (channel
replies, direct heartbeats and adverts) is written to a SQLite database
(--db) with timestamp, sender, text, hop count, path, SNR/RSSI, the command
matched, and which received message a reply answers. A human-readable log can
also be written to a rotating file (--log-file). Query the database while the
bot runs (WAL mode), e.g.:

    sqlite3 -header -column meshbot_messages.db \\
        "select iso, direction, channel, sender, hops, snr, text from messages order by id desc limit 20"
    sqlite3 -header -column meshbot_messages.db "select * from hb_subs"

RADIO SETTINGS: --freq/--bw/--sf/--cr must match the mesh you want to talk
to (check with "get radio" on an existing node). --power is local to this
radio. Check your local regulations for frequency, power and duty cycle.

Usage:

  python3 meshcore_kiss_bot.py --serial /dev/ttyACM0 --channel "#bot" \\
      --name MeshBot --freq 910.525 --bw 62.5 --sf 7 --cr 5 --power 22 \\
      --db meshbot_messages.db --log-file meshbot.log

Requires: pip install pyserial cryptography --break-system-packages
"""

import argparse
import asyncio
import hashlib
import hmac
import logging
import logging.handlers
import random
import sqlite3
import struct
import sys
import time
from collections import OrderedDict, deque

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

log = logging.getLogger("meshcore_bot")

# --------------------------------------------------------------------------
# KISS framing + MeshCore SetHardware (0x06) extensions
# per https://docs.meshcore.io/kiss_modem_protocol/
# --------------------------------------------------------------------------

KISS_FEND = 0xC0
KISS_FESC = 0xDB
KISS_TFEND = 0xDC
KISS_TFESC = 0xDD

KISS_CMD_DATA = 0x00
KISS_CMD_SETHARDWARE = 0x06

# SetHardware sub-commands, host -> TNC
SUB_GET_IDENTITY = 0x01
SUB_SIGN_DATA = 0x04
SUB_KEY_EXCHANGE = 0x07
SUB_SET_RADIO = 0x09
SUB_SET_TXPOWER = 0x0A
SUB_GET_RADIO = 0x0B

# SetHardware sub-commands, TNC -> host
RESP_IDENTITY = 0x81
RESP_SIGNATURE = 0x84
RESP_SHARED_SECRET = 0x87
RESP_RADIO = 0x8B
RESP_OK = 0xF0
RESP_ERROR = 0xF1
RESP_TXDONE = 0xF8
RESP_RXMETA = 0xF9

ERR_TX_BUSY = 0x07


def kiss_encode(type_byte: int, payload: bytes = b"") -> bytes:
    """Wrap payload in a KISS frame, escaping FEND/FESC per the KISS spec."""
    escaped = bytearray()
    for b in payload:
        if b == KISS_FEND:
            escaped += bytes([KISS_FESC, KISS_TFEND])
        elif b == KISS_FESC:
            escaped += bytes([KISS_FESC, KISS_TFESC])
        else:
            escaped.append(b)
    return bytes([KISS_FEND, type_byte]) + bytes(escaped) + bytes([KISS_FEND])


class KissDecoder:
    """Incremental KISS frame decoder: feed() raw serial bytes, get back a
    list of (type_byte, payload) tuples for any frames completed."""

    def __init__(self):
        self._in_frame = False
        self._escaped = False
        self._type_byte = None
        self._buf = bytearray()

    def feed(self, data: bytes):
        frames = []
        for b in data:
            if b == KISS_FEND:
                if self._in_frame and self._type_byte is not None:
                    frames.append((self._type_byte, bytes(self._buf)))
                self._in_frame = True
                self._escaped = False
                self._type_byte = None
                self._buf = bytearray()
                continue
            if not self._in_frame:
                continue
            if self._escaped:
                if b == KISS_TFEND:
                    self._buf.append(KISS_FEND)
                elif b == KISS_TFESC:
                    self._buf.append(KISS_FESC)
                else:
                    self._buf.append(b)
                self._escaped = False
                continue
            if b == KISS_FESC:
                self._escaped = True
                continue
            if self._type_byte is None:
                self._type_byte = b
            else:
                self._buf.append(b)
        return frames


async def send_hw_command(ser, decoder: KissDecoder, sub_cmd: int, payload: bytes,
                          expected_resp_subs: set, timeout: float = 5.0):
    """Startup-time SetHardware request/response, used BEFORE the serial
    reader task exists (it reads the port itself). Returns (resp_sub, data)."""
    loop = asyncio.get_running_loop()
    frame = kiss_encode(KISS_CMD_SETHARDWARE, bytes([sub_cmd]) + payload)
    await loop.run_in_executor(None, ser.write, frame)

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        chunk = await loop.run_in_executor(None, ser.read, 256)
        if not chunk:
            continue
        for type_byte, data in decoder.feed(chunk):
            if (type_byte & 0x0F) != KISS_CMD_SETHARDWARE or not data:
                continue
            resp_sub = data[0]
            if resp_sub == RESP_ERROR:
                code = data[1] if len(data) > 1 else None
                raise RuntimeError(f"radio rejected command 0x{sub_cmd:02X} (error code {code})")
            if resp_sub in expected_resp_subs:
                return resp_sub, data[1:]
    raise TimeoutError(f"no response from radio to SetHardware sub-command 0x{sub_cmd:02X} within {timeout}s")


async def configure_radio(ser, decoder: KissDecoder, freq_hz: int, bw_hz: int, sf: int, cr: int, power_dbm: int):
    """Push radio settings to the modem. Required on every connection — the
    firmware does not persist them across reboot."""
    await send_hw_command(ser, decoder, SUB_SET_RADIO,
                          struct.pack("<II", freq_hz, bw_hz) + bytes([sf, cr]), {RESP_OK})
    await send_hw_command(ser, decoder, SUB_SET_TXPOWER, struct.pack("<b", power_dbm), {RESP_OK})
    _, data = await send_hw_command(ser, decoder, SUB_GET_RADIO, b"", {RESP_RADIO})
    got_freq, got_bw, got_sf, got_cr = struct.unpack("<IIBB", data[:10])
    log.info("radio confirmed freq=%.3fMHz bw=%.1fkHz sf=%d cr=%d power=%ddBm",
             got_freq / 1e6, got_bw / 1e3, got_sf, got_cr, power_dbm)
    if (got_freq, got_bw, got_sf, got_cr) != (freq_hz, bw_hz, sf, cr):
        log.warning("device-reported radio settings differ from requested "
                    "(requested freq=%.3fMHz bw=%.1fkHz sf=%d cr=%d)",
                    freq_hz / 1e6, bw_hz / 1e3, sf, cr)


# --------------------------------------------------------------------------
# MeshCore packets, channel crypto, direct messages, adverts
# --------------------------------------------------------------------------

ROUTE_TRANSPORT_FLOOD = 0
ROUTE_FLOOD = 1
ROUTE_DIRECT = 2
ROUTE_TRANSPORT_DIRECT = 3

PAYLOAD_TXT_MSG = 2
PAYLOAD_ADVERT = 4
PAYLOAD_GRP_TXT = 5

ADV_TYPE_CHAT = 1

# Payload max is 184 bytes: 3 bytes channel hash+MAC, then AES blocks holding
# 5 bytes (timestamp+flags) + text. 150 text bytes keeps us safely inside it.
MAX_TEXT_BYTES = 150


def encrypt_then_mac(secret32: bytes, plaintext: bytes):
    """MeshCore's AES-128-ECB (key = first 16 bytes of the secret, zero
    padded plaintext) + HMAC-SHA256 over the ciphertext (key = full 32-byte
    secret), MAC truncated to 2 bytes. Returns (mac, ciphertext)."""
    plaintext += b"\x00" * (-len(plaintext) % 16)
    enc = Cipher(algorithms.AES(secret32[:16]), modes.ECB()).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return hmac.new(secret32, ct, hashlib.sha256).digest()[:2], ct


class Channel:
    """A hashtag channel: key = first 16 bytes of SHA256("#name"); channel
    hash = first byte of SHA256(key)."""

    def __init__(self, name: str):
        name = name.strip().lower()
        self.name = name if name.startswith("#") else "#" + name
        self.secret = hashlib.sha256(self.name.encode()).digest()[:16]
        self.hash = hashlib.sha256(self.secret).digest()[0]
        self._key32 = self.secret + b"\x00" * 16

    def decrypt(self, payload: bytes):
        """payload = channel_hash(1) | mac(2) | ciphertext.
        Returns (sender_timestamp, flags, text) or None if not ours."""
        if len(payload) < 3 + 16 or payload[0] != self.hash:
            return None
        mac, ct = payload[1:3], payload[3:]
        good = hmac.new(self._key32, ct, hashlib.sha256).digest()[:2]
        if len(ct) % 16 or not hmac.compare_digest(mac, good):
            return None
        d = Cipher(algorithms.AES(self.secret), modes.ECB()).decryptor()
        pt = d.update(ct) + d.finalize()
        ts, flags = struct.unpack_from("<IB", pt)
        text = pt[5:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        return ts, flags, text

    def encrypt(self, text: str) -> bytes:
        raw = struct.pack("<IB", int(time.time()), 0) + text.encode("utf-8")
        mac, ct = encrypt_then_mac(self._key32, raw)
        return bytes([self.hash]) + mac + ct


def parse_packet(raw: bytes):
    """Returns dict(route, ptype, hops, plb, path, payload) or None.
    plb is the raw path-length byte (hop count + hash size), kept so a
    reverse path can be re-emitted in the same encoding."""
    if len(raw) < 2:
        return None
    header = raw[0]
    route = header & 0x03
    ptype = (header >> 2) & 0x0F
    i = 1
    if route in (ROUTE_TRANSPORT_FLOOD, ROUTE_TRANSPORT_DIRECT):
        i += 4  # two 16-bit transport codes
    if i >= len(raw):
        return None
    plb = raw[i]
    i += 1
    # Newer firmware: top 2 bits = (hash size - 1), low 6 bits = hop count.
    # Older firmware has the top bits at 0, so this is correct for both.
    hops = plb & 0x3F
    hash_size = (plb >> 6) + 1
    path_len = hops * hash_size
    if i + path_len > len(raw):
        return None
    return {"route": route, "ptype": ptype, "hops": hops, "plb": plb,
            "path": raw[i:i + path_len], "payload": raw[i + path_len:]}


def build_flood_grp_txt(payload: bytes) -> bytes:
    header = (PAYLOAD_GRP_TXT << 2) | ROUTE_FLOOD
    return bytes([header, 0x00]) + payload  # path_len = 0


def reverse_path(path: bytes, plb: int) -> bytes:
    """Reverse a repeater path hop-by-hop (hash groups, not raw bytes)."""
    size = (plb >> 6) + 1
    groups = [path[i:i + size] for i in range(0, len(path), size)]
    return b"".join(reversed(groups))


def build_direct_txt(dest_pub: bytes, src_pub: bytes, secret32: bytes, text: str,
                     path: bytes, plb: int) -> bytes:
    """A DIRECT-routed plain-text message (TXT_MSG) to dest_pub, sent back
    along the reverse of `path` (the path the recipient's packet arrived by).
    Payload: dest hash(1) | src hash(1) | MAC(2) | AES(timestamp|flags|text)."""
    raw = struct.pack("<IB", int(time.time()), 0) + text.encode("utf-8")  # flags 0 = plain text, attempt 0
    mac, ct = encrypt_then_mac(secret32, raw)
    payload = bytes([dest_pub[0], src_pub[0]]) + mac + ct
    header = (PAYLOAD_TXT_MSG << 2) | ROUTE_DIRECT
    return bytes([header, plb]) + reverse_path(path, plb) + payload


def parse_advert(payload: bytes):
    """Verify and decode an ADVERT payload: pubkey(32) | timestamp(4) |
    signature(64) | appdata. Returns (pubkey, adv_type, name) or None."""
    if len(payload) < 101:
        return None
    pub, ts, sig, app = payload[:32], payload[32:36], payload[36:100], payload[100:]
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, pub + ts + app)
    except (InvalidSignature, ValueError):
        return None
    flags = app[0]
    i = 1
    if flags & 0x10:
        i += 8      # lat + lon
    if flags & 0x20:
        i += 2      # feature 1
    if flags & 0x40:
        i += 2      # feature 2
    name = ""
    if flags & 0x80:
        name = app[i:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return pub, flags & 0x0F, name


def build_advert(pub: bytes, signature: bytes, ts: bytes, app: bytes) -> bytes:
    header = (PAYLOAD_ADVERT << 2) | ROUTE_FLOOD
    return bytes([header, 0x00]) + pub + ts + signature + app


# --------------------------------------------------------------------------
# persistent state (SQLite): message log, heard nodes, heartbeat subscriptions
# --------------------------------------------------------------------------

class BotDB:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          REAL    NOT NULL,   -- unix time logged by the bot
                iso         TEXT    NOT NULL,   -- same, ISO-8601 UTC
                direction   TEXT    NOT NULL,   -- 'rx' or 'tx'
                channel     TEXT    NOT NULL,   -- '#bot', 'dm:<name>' or 'advert'
                sender      TEXT,
                text        TEXT    NOT NULL,
                sender_ts   INTEGER,            -- timestamp inside the packet
                hops        INTEGER,
                path        TEXT,               -- hex of repeater hashes
                snr         REAL,               -- dB, as heard by this radio
                rssi        INTEGER,            -- dBm, as heard by this radio
                command     TEXT,               -- command matched, if any
                in_reply_to INTEGER,            -- id of the rx row answered
                status      TEXT                -- tx only: sent / failed / unconfirmed
            );
            CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts);
            CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);

            -- chat nodes whose signed adverts we have heard: name -> public key
            CREATE TABLE IF NOT EXISTS nodes (
                pubkey     TEXT PRIMARY KEY,    -- hex
                name       TEXT,
                adv_type   INTEGER,
                first_seen REAL,
                last_seen  REAL
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_name ON nodes(name);

            -- heartbeat subscriptions (one per user name); survive restarts
            CREATE TABLE IF NOT EXISTS hb_subs (
                name        TEXT PRIMARY KEY,
                pubkey      TEXT NOT NULL,      -- hex
                path        TEXT NOT NULL,      -- hex; path of their latest channel message
                plb         INTEGER NOT NULL,   -- raw path-length byte for that path
                enabled_at  REAL NOT NULL,
                expires_at  REAL NOT NULL
            );
        """)
        self.db.commit()

    # ---- message log
    def add(self, **f) -> int:
        now = time.time()
        row = {
            "ts": now,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "sender": None, "sender_ts": None, "hops": None, "path": None,
            "snr": None, "rssi": None, "command": None, "in_reply_to": None,
            "status": None,
        }
        row.update(f)
        cols = ", ".join(row)
        qs = ", ".join("?" for _ in row)
        cur = self.db.execute(f"INSERT INTO messages ({cols}) VALUES ({qs})", list(row.values()))
        self.db.commit()
        return cur.lastrowid

    def set_status(self, row_id: int, status: str):
        self.db.execute("UPDATE messages SET status=? WHERE id=?", (status, row_id))
        self.db.commit()

    def summary(self):
        rx, senders = self.db.execute(
            "SELECT COUNT(*), COUNT(DISTINCT sender) FROM messages WHERE direction='rx'").fetchone()
        tx = self.db.execute("SELECT COUNT(*) FROM messages WHERE direction='tx'").fetchone()[0]
        return rx, senders, tx

    # ---- heard nodes
    def note_node(self, pubkey: bytes, name: str, adv_type: int):
        now = time.time()
        self.db.execute(
            """INSERT INTO nodes (pubkey, name, adv_type, first_seen, last_seen) VALUES (?,?,?,?,?)
               ON CONFLICT(pubkey) DO UPDATE SET name=excluded.name, adv_type=excluded.adv_type,
                                                 last_seen=excluded.last_seen""",
            (pubkey.hex(), name, adv_type, now, now))
        self.db.commit()

    def keys_for_name(self, name: str):
        """Public keys of chat nodes advertised under this name. Keys not
        heard from for a week while a newer one has been (e.g. a node that
        reset its identity) are ignored, so a stale key doesn't make the name
        ambiguous forever."""
        rows = self.db.execute(
            "SELECT pubkey, last_seen FROM nodes WHERE name=? AND adv_type=? ORDER BY last_seen DESC",
            (name, ADV_TYPE_CHAT)).fetchall()
        if not rows:
            return []
        newest = rows[0]["last_seen"]
        return [bytes.fromhex(r["pubkey"]) for r in rows if r["last_seen"] >= newest - 7 * 86400]

    # ---- heartbeat subscriptions
    def upsert_sub(self, name, pubkey: bytes, path: bytes, plb: int, expires_at: float):
        self.db.execute(
            """INSERT INTO hb_subs (name, pubkey, path, plb, enabled_at, expires_at) VALUES (?,?,?,?,?,?)
               ON CONFLICT(name) DO UPDATE SET pubkey=excluded.pubkey, path=excluded.path, plb=excluded.plb,
                                               enabled_at=excluded.enabled_at, expires_at=excluded.expires_at""",
            (name, pubkey.hex(), path.hex(), plb, time.time(), expires_at))
        self.db.commit()

    def refresh_sub_path(self, name, path: bytes, plb: int):
        self.db.execute("UPDATE hb_subs SET path=?, plb=? WHERE name=?", (path.hex(), plb, name))
        self.db.commit()

    def get_sub(self, name):
        return self.db.execute("SELECT * FROM hb_subs WHERE name=?", (name,)).fetchone()

    def remove_sub(self, name) -> bool:
        cur = self.db.execute("DELETE FROM hb_subs WHERE name=?", (name,))
        self.db.commit()
        return cur.rowcount > 0

    def active_subs(self, now):
        return self.db.execute("SELECT * FROM hb_subs WHERE expires_at > ?", (now,)).fetchall()

    def expired_subs(self, now):
        return self.db.execute("SELECT * FROM hb_subs WHERE expires_at <= ?", (now,)).fetchall()

    def count_active_subs(self, now, excluding=None):
        return self.db.execute(
            "SELECT COUNT(*) FROM hb_subs WHERE expires_at > ? AND name IS NOT ?",
            (now, excluding)).fetchone()[0]


def fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


# --------------------------------------------------------------------------
# the bot
# --------------------------------------------------------------------------

TX_DONE_TIMEOUT = 20.0   # seconds to wait for the modem's TxDone event
MAX_QUEUED_TX = 8
ADVERT_MIN_GAP = 600     # never advert more often than this (seconds)


class Bot:
    def __init__(self, args, db: BotDB):
        self.args = args
        self.db = db
        self.chan = Channel(args.channel)
        self.name = args.name
        self.start = time.time()

        self.seen = OrderedDict()        # dedupe: same packet arrives via many paths
        self.last_reply = {}             # per-sender cooldown
        self.reply_times = deque()       # global reply rate limit
        self.tx_queue = asyncio.Queue()
        self.tx_done = asyncio.Event()
        self.tx_ok = None

        self.write_lock = asyncio.Lock()   # one serial write at a time
        self.hw_lock = asyncio.Lock()      # one SetHardware request at a time
        self.hw_waiter = None              # (expected response subs, future)
        self.advert_now = asyncio.Event()
        self.last_advert = 0.0

        self.ser = None
        self.decoder = None
        self.pubkey = None                 # modem identity, read on connect
        self.secrets = {}                  # remote pubkey -> shared secret

        # command table: "!cmd" -> handler(ctx) -> reply text
        self.commands = {
            "!ping": self.cmd_ping,
            "!help": lambda c: "Commands: !ping !time !uptime !stats !echo <text> !heartbeaton !heartbeatoff !heartbeat",
            "!time": lambda c: time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "!uptime": lambda c: f"up {fmt_duration(time.time() - self.start)}",
            "!stats": self.cmd_stats,
            "!echo": lambda c: c["args"][:100] if c["args"] else "usage: !echo <text>",
            "!heartbeaton": self.cmd_heartbeat_on,
            "!heartbeatoff": self.cmd_heartbeat_off,
            "!heartbeat": self.cmd_heartbeat_status,
        }

    # ---- commands
    def cmd_ping(self, c):
        hops = c["hops"]
        out = f"pong @{c['sender']} ({hops} hop{'s' if hops != 1 else ''}"
        if c["snr"] is not None:
            out += f", SNR {c['snr']:.1f}dB RSSI {c['rssi']}dBm"
        return out + ")"

    def cmd_stats(self, c):
        rx, senders, tx = self.db.summary()
        return f"heard {rx} msgs from {senders} senders, sent {tx}"

    def cmd_heartbeat_on(self, c):
        name, now = c["sender"], time.time()
        keys = self.db.keys_for_name(name)
        if not keys:
            # we can't encrypt to someone whose public key we've never heard
            self.advert_now.set()
            return (f"@{name} I haven't heard an advert from you. Send an advert (flood), "
                    f"add me as a contact, then try !heartbeaton again")
        if len(keys) > 1:
            return f"@{name} several nodes advertise the name '{name}', so I can't tell which is you"
        if self.db.count_active_subs(now, excluding=name) >= self.args.max_heartbeat_subs:
            return f"@{name} all heartbeat slots are in use right now, try again later"
        hours = self.args.heartbeat_hours
        renewing = self.db.get_sub(name) is not None
        self.db.upsert_sub(name, keys[0], c["path"], c["plb"], now + hours * 3600)
        self.advert_now.set()  # make sure they can find/add the bot as a contact
        return (f"@{name} heartbeat {'renewed' if renewing else 'ON'} for {hours:g}h: direct msgs every "
                f"{self.args.heartbeat_interval:g}s. Add me as a contact. !heartbeatoff to stop")

    def cmd_heartbeat_off(self, c):
        if self.db.remove_sub(c["sender"]):
            return f"@{c['sender']} heartbeat OFF"
        return f"@{c['sender']} heartbeat wasn't on"

    def cmd_heartbeat_status(self, c):
        sub = self.db.get_sub(c["sender"])
        if sub and sub["expires_at"] > time.time():
            return f"@{c['sender']} heartbeat ON, {fmt_duration(sub['expires_at'] - time.time())} left"
        return f"@{c['sender']} heartbeat OFF (!heartbeaton to start)"

    # ---- dedupe
    def seen_before(self, key: bytes) -> bool:
        if key in self.seen:
            return True
        self.seen[key] = time.time()
        while len(self.seen) > 1024:
            self.seen.popitem(last=False)
        return False

    # ---- TX plumbing
    async def serial_write(self, frame: bytes):
        async with self.write_lock:  # pyserial writes from threads aren't atomic
            await asyncio.get_running_loop().run_in_executor(None, self.ser.write, frame)

    def enqueue(self, text, *, packet=None, label=None, reply_to=None, cmd=None, jitter=True):
        """Queue something for transmission. packet=None means 'post `text`
        to the channel'; otherwise packet is a ready-built raw MeshCore packet
        (a direct message or advert) and text/label are just for the log."""
        self.tx_queue.put_nowait({"text": text, "packet": packet, "label": label,
                                  "reply_to": reply_to, "cmd": cmd, "jitter": jitter})

    async def hw_request(self, sub_cmd: int, payload: bytes, expected_resp: int, timeout: float = 5.0):
        """SetHardware request issued while the serial reader task owns the
        port: the reader hands us the matching response."""
        async with self.hw_lock:
            fut = asyncio.get_running_loop().create_future()
            self.hw_waiter = ({expected_resp}, fut)
            try:
                await self.serial_write(kiss_encode(KISS_CMD_SETHARDWARE, bytes([sub_cmd]) + payload))
                return await asyncio.wait_for(fut, timeout)
            finally:
                self.hw_waiter = None

    async def shared_secret(self, remote_pub: bytes) -> bytes:
        """X25519 shared secret with a remote node, computed inside the
        modem (its private key never leaves it). Cached per connection."""
        secret = self.secrets.get(remote_pub)
        if secret is None:
            secret = await self.hw_request(SUB_KEY_EXCHANGE, remote_pub, RESP_SHARED_SECRET)
            self.secrets[remote_pub] = secret
        return secret

    # ---- RX
    def handle_advert(self, payload: bytes):
        if self.seen_before(hashlib.sha256(payload).digest()):
            return
        parsed = parse_advert(payload)
        if not parsed:
            log.debug("ignored advert that failed signature/format check")
            return
        pub, adv_type, name = parsed
        if pub == self.pubkey or not name:
            return
        self.db.note_node(pub, name, adv_type)
        log.debug("heard advert: %s (type %d) %s", name, adv_type, pub.hex()[:12])

    def handle_rx(self, raw: bytes, meta):
        """raw = one received MeshCore packet; meta = (snr, rssi) or None."""
        snr, rssi = meta if meta else (None, None)
        log.debug("rx packet %d bytes: %s", len(raw), raw.hex())
        pkt = parse_packet(raw)
        if not pkt:
            return
        if pkt["ptype"] == PAYLOAD_ADVERT:
            self.handle_advert(pkt["payload"])
            return
        if pkt["ptype"] != PAYLOAD_GRP_TXT:
            return
        payload = pkt["payload"]
        if self.seen_before(hashlib.sha256(payload).digest()):
            return
        result = self.chan.decrypt(payload)
        if not result:
            return  # other channel or failed MAC
        sender_ts, _flags, text = result

        # Channel text arrives as "SenderName: message"
        sender, sep, msg = text.partition(": ")
        if not sep:
            sender, msg = None, text
        if sender == self.name:
            return  # an echo of our own transmission
        msg = msg.strip()

        # A subscriber just spoke: the path this packet took is the freshest
        # route back to them, so heartbeats follow it in reverse.
        if sender:
            self.db.refresh_sub_path(sender, pkt["path"], pkt["plb"])

        cmd, _, args = msg.partition(" ")
        cmd = cmd.lower()
        handler = self.commands.get(cmd)

        row_id = self.db.add(
            direction="rx", channel=self.chan.name, sender=sender, text=msg,
            sender_ts=sender_ts, hops=pkt["hops"], path=pkt["path"].hex(),
            snr=snr, rssi=rssi, command=cmd if handler else None)
        log.info("RX [%d hops%s] %s: %s", pkt["hops"],
                 f", SNR {snr:.1f} RSSI {rssi}" if snr is not None else "", sender or "?", msg)

        if not handler or sender is None:
            return

        now = time.time()
        if now - self.last_reply.get(sender, 0) < self.args.cooldown:
            log.info("rate-limited %s", sender)
            return
        while self.reply_times and now - self.reply_times[0] > 60:
            self.reply_times.popleft()
        if len(self.reply_times) >= self.args.max_replies_per_min:
            log.warning("global reply limit reached; ignoring %s from %s", cmd, sender)
            return
        if self.tx_queue.qsize() >= MAX_QUEUED_TX:
            log.warning("TX queue full; ignoring %s from %s", cmd, sender)
            return

        self.last_reply[sender] = now
        self.reply_times.append(now)
        ctx = {"sender": sender, "args": args.strip(), "hops": pkt["hops"], "snr": snr, "rssi": rssi,
               "path": pkt["path"], "plb": pkt["plb"]}
        try:
            reply = handler(ctx)
        except Exception:
            log.exception("command %s failed", cmd)
            return
        self.enqueue(reply, reply_to=row_id, cmd=cmd)

    # ---- serial tasks
    async def serial_reader(self):
        loop = asyncio.get_running_loop()
        # Per the protocol, RxMeta (SNR/RSSI) is sent AFTER the Data frame it
        # describes, so hold each packet until its RxMeta arrives (or until
        # something else shows the meta isn't coming).
        pending = None
        while True:
            chunk = await loop.run_in_executor(None, self.ser.read, 4096)
            if not chunk:
                if pending is not None:
                    self.handle_rx(pending, None)
                    pending = None
                continue
            for type_byte, payload in self.decoder.feed(chunk):
                cmd = type_byte & 0x0F
                if cmd == KISS_CMD_SETHARDWARE and payload and payload[0] == RESP_RXMETA and len(payload) >= 3:
                    snr = struct.unpack("b", payload[1:2])[0] / 4.0
                    rssi = struct.unpack("b", payload[2:3])[0]
                    if pending is not None:
                        self.handle_rx(pending, (snr, rssi))
                        pending = None
                    continue

                if pending is not None:
                    self.handle_rx(pending, None)
                    pending = None

                if cmd == KISS_CMD_DATA and payload:
                    pending = payload
                elif cmd == KISS_CMD_SETHARDWARE and payload:
                    sub = payload[0]
                    if sub == RESP_TXDONE and len(payload) >= 2:
                        self.tx_ok = payload[1] == 0x01
                        self.tx_done.set()
                    elif sub == RESP_ERROR:
                        code = payload[1] if len(payload) > 1 else None
                        if code == ERR_TX_BUSY:
                            log.warning("radio reported TX busy")
                            self.tx_ok = False
                            self.tx_done.set()
                        elif self.hw_waiter and not self.hw_waiter[1].done():
                            self.hw_waiter[1].set_exception(RuntimeError(f"radio error code {code}"))
                        else:
                            log.warning("radio reported error code %s", code)
                    elif self.hw_waiter and sub in self.hw_waiter[0] and not self.hw_waiter[1].done():
                        self.hw_waiter[1].set_result(payload[1:])

    async def tx_worker(self):
        """Sends queued packets one at a time (the modem only accepts one
        pending packet) and waits for the TxDone event before the next."""
        while True:
            item = await self.tx_queue.get()
            if item["jitter"]:
                # replies wait a moment so we don't collide with repeaters
                # echoing the request
                await asyncio.sleep(random.uniform(self.args.delay_min, self.args.delay_max))

            if item["packet"] is None:      # channel message
                full = f"{self.name}: {item['text']}"
                full = full.encode("utf-8")[:MAX_TEXT_BYTES].decode("utf-8", errors="ignore")
                payload = self.chan.encrypt(full)
                self.seen_before(hashlib.sha256(payload).digest())  # ignore repeater echoes of ours
                packet = build_flood_grp_txt(payload)
                label, logged = self.chan.name, full.partition(": ")[2]
            else:                           # prebuilt: direct message / advert
                packet, label, logged = item["packet"], item["label"], item["text"]

            self.tx_done.clear()
            self.tx_ok = None
            await self.serial_write(kiss_encode(KISS_CMD_DATA, packet))
            row = self.db.add(direction="tx", channel=label, sender=self.name, text=logged,
                              command=item["cmd"], in_reply_to=item["reply_to"], status="sent")
            log.info("TX [%s]: %s", label, logged)
            try:
                await asyncio.wait_for(self.tx_done.wait(), TX_DONE_TIMEOUT)
                if not self.tx_ok:
                    log.warning("modem reported TX failure")
                    self.db.set_status(row, "failed")
            except asyncio.TimeoutError:
                log.warning("no TxDone from modem within %.0fs", TX_DONE_TIMEOUT)
                self.db.set_status(row, "unconfirmed")

    # ---- heartbeats (direct, opt-in, per user)
    async def send_direct(self, sub, text: str, cmd: str):
        """Build and queue a DIRECT-routed message to a subscriber."""
        try:
            secret = await self.shared_secret(bytes.fromhex(sub["pubkey"]))
        except Exception as e:
            log.warning("can't send to %s: key exchange failed (%s)", sub["name"], e)
            return
        packet = build_direct_txt(bytes.fromhex(sub["pubkey"]), self.pubkey, secret, text,
                                  bytes.fromhex(sub["path"]), sub["plb"])
        self.enqueue(text, packet=packet, label=f"dm:{sub['name']}", cmd=cmd, jitter=False)

    async def heartbeat(self):
        """Every --heartbeat-interval seconds, send a direct heartbeat to each
        active subscriber; when a subscription hits its time limit, send one
        last direct message and remove it."""
        interval = self.args.heartbeat_interval
        if interval <= 0:
            return
        next_at = time.monotonic() + interval
        while True:
            await asyncio.sleep(max(0.0, next_at - time.monotonic()))
            next_at += interval  # fixed schedule, no drift from TX time
            now = time.time()

            for sub in self.db.expired_subs(now):
                self.db.remove_sub(sub["name"])
                log.info("heartbeat for %s expired", sub["name"])
                if self.tx_queue.qsize() < MAX_QUEUED_TX:
                    await self.send_direct(
                        sub, f"heartbeats ended after {self.args.heartbeat_hours:g}h. "
                             f"Send !heartbeaton in {self.chan.name} for another {self.args.heartbeat_hours:g}h",
                        "heartbeat_end")

            stamp = time.strftime("%H:%M:%S UTC", time.gmtime(now))
            for sub in self.db.active_subs(now):
                if self.tx_queue.qsize() >= MAX_QUEUED_TX:
                    log.warning("TX queue backed up; skipping remaining heartbeats this round")
                    break
                left = fmt_duration(sub["expires_at"] - now)
                await self.send_direct(sub, f"heartbeat {stamp} ({left} left)", "heartbeat")

    # ---- our own advert, so users can add the bot as a contact
    async def send_advert(self):
        ts = struct.pack("<I", int(time.time()))
        app = bytes([0x80 | ADV_TYPE_CHAT]) + self.name.encode("utf-8")[:32]  # chat node, has name
        sig = await self.hw_request(SUB_SIGN_DATA, self.pubkey + ts + app, RESP_SIGNATURE)
        self.last_advert = time.time()
        self.enqueue(f"advert as '{self.name}'", packet=build_advert(self.pubkey, sig, ts, app),
                     label="advert", cmd="advert", jitter=False)

    async def advert_task(self):
        """Advertise at startup, every --advert-interval hours (0 = never
        again), and whenever someone enables heartbeats."""
        await asyncio.sleep(3)
        self.advert_now.set()
        period = self.args.advert_interval * 3600 or None
        while True:
            try:
                await asyncio.wait_for(self.advert_now.wait(), timeout=period)
            except asyncio.TimeoutError:
                pass
            self.advert_now.clear()
            if time.time() - self.last_advert < ADVERT_MIN_GAP:
                continue
            try:
                await self.send_advert()
            except Exception as e:
                log.warning("couldn't send advert: %s", e)

    # ---- connection lifecycle
    async def run_once(self):
        import serial  # imported here so --help works without pyserial

        a = self.args
        self.ser = serial.Serial(a.serial, baudrate=a.baud, timeout=0.2)
        self.decoder = KissDecoder()
        self.secrets.clear()
        self.hw_waiter = None
        log.info("opened serial %s @ %d baud", a.serial, a.baud)

        try:
            # Radio settings do not survive a modem reboot, so push them on
            # every (re)connect.
            await configure_radio(self.ser, self.decoder, round(a.freq * 1_000_000),
                                  round(a.bw * 1_000), a.sf, a.cr, a.power)
            _, ident = await send_hw_command(self.ser, self.decoder, SUB_GET_IDENTITY, b"", {RESP_IDENTITY})
            self.pubkey = ident[:32]
            log.info("modem identity %s (hash 0x%02x)", self.pubkey.hex(), self.pubkey[0])
            log.info("listening on %s (channel hash 0x%02x) as '%s'",
                     self.chan.name, self.chan.hash, self.name)
            tasks = [asyncio.create_task(self.serial_reader()),
                     asyncio.create_task(self.tx_worker()),
                     asyncio.create_task(self.heartbeat()),
                     asyncio.create_task(self.advert_task())]
            try:
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
                for t in done:
                    t.result()
            finally:
                for t in tasks:
                    t.cancel()
        finally:
            self.ser.close()

    async def run(self):
        STABLE_SECONDS = 60
        backoff = 2
        while True:
            start = time.monotonic()
            try:
                await self.run_once()
            except Exception as e:
                elapsed = time.monotonic() - start
                if elapsed >= STABLE_SECONDS:
                    backoff = 2
                log.warning("modem link dropped after %.1fs (%s), reconnecting in %ds", elapsed, e, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

async def amain(args):
    db = BotDB(args.db)
    log.info("database: %s", args.db)
    await Bot(args, db).run()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--serial", required=True, help="serial device, e.g. /dev/ttyACM0 or COM3")
    p.add_argument("--baud", type=int, default=115200, help="serial baud rate (default 115200)")
    p.add_argument("--channel", required=True, help='hashtag channel to serve, e.g. "#bot"')
    p.add_argument("--name", default="MeshBot", help="name the bot posts and advertises under (default MeshBot)")

    p.add_argument("--freq", type=float, required=True, help="radio frequency in MHz, e.g. 910.525")
    p.add_argument("--bw", type=float, required=True, help="bandwidth in kHz, e.g. 62.5")
    p.add_argument("--sf", type=int, required=True, choices=range(5, 13), help="spreading factor 5-12")
    p.add_argument("--cr", type=int, required=True, choices=range(5, 9), help="coding rate 5-8")
    p.add_argument("--power", type=int, required=True, help="TX power in dBm for this radio")

    p.add_argument("--db", default="meshbot_messages.db",
                   help="SQLite database: message log, heard nodes, heartbeat subscriptions "
                        "(default meshbot_messages.db)")
    p.add_argument("--log-file", help="also write the text log to this file (rotating, 5 x 2 MB)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging, including raw packet hex")

    p.add_argument("--cooldown", type=float, default=5.0, help="seconds between replies to the same sender (default 5)")
    p.add_argument("--max-replies-per-min", type=int, default=10, help="global reply cap per minute (default 10)")
    p.add_argument("--delay-min", type=float, default=1.0, help="min seconds before replying (default 1)")
    p.add_argument("--delay-max", type=float, default=3.0, help="max seconds before replying (default 3)")

    p.add_argument("--heartbeat-interval", type=float, default=60.0,
                   help="seconds between direct heartbeats to each subscriber (default 60, 0 disables heartbeats)")
    p.add_argument("--heartbeat-hours", type=float, default=24.0,
                   help="how long one !heartbeaton lasts before it must be renewed (default 24)")
    p.add_argument("--max-heartbeat-subs", type=int, default=5,
                   help="max users with heartbeats on at once, to protect airtime (default 5)")
    p.add_argument("--advert-interval", type=float, default=12.0,
                   help="hours between the bot's own adverts; 0 = only at startup and on demand (default 12)")
    args = p.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.handlers.RotatingFileHandler(
            args.log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8"))
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", handlers=handlers)

    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
