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
heartbeats).

ACKs and flood fallback: every direct message is tracked until the
recipient's ACK comes back. If it doesn't (out of range, or a repeater on the
path is gone), the bot does what MeshCore companion clients do: it forgets
that route and resends the message once by FLOOD. The recipient answers a
flood with a PATH packet carrying the ACK and the route the flood took, which
becomes the new direct route. Until a route is learned again (or the user
next speaks in the channel), heartbeats are flooded, backing off (2x, 4x, 8x...
the interval, up to --flood-backoff-max minutes) while floods go unanswered,
since each flood costs airtime across the whole mesh. The bot also sends each
user's node a PATH packet with the route back to the bot, so their ACKs come
back direct instead of being flooded. --ack-timeout overrides
the airtime-based ACK wait.

DIRECT MESSAGES TO THE BOT: the same commands work in a DM to the bot's name
(the "!" is optional there). The sender is identified from the adverts the
bot has heard (so they must have sent one), the message is ACKed the way
MeshCore firmware does, and the reply comes back as a direct message, with
the same ACK tracking and flood fallback as heartbeats. A DM proves who sent
it, unlike a name in the channel.

TELEMETRY / PATH DISCOVERY: the bot answers telemetry requests like a companion
node: battery voltage (a full 4.20 V, shown as 100 %) and, if --lat/--lon are
given, a fixed GPS position. A companion app's "path discovery" is a flooded
telemetry request; the answer goes back inside a PATH packet that carries the
route the request took, which is what the app needs.

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

Requires: pip install pyserial cryptography tzdata --break-system-packages
"""

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import logging.handlers
import math
import os
import random
import sqlite3
import struct
import sys
import time
import urllib.parse
import urllib.request
from collections import OrderedDict, deque
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

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

PAYLOAD_REQ = 0
PAYLOAD_RESPONSE = 1
PAYLOAD_TXT_MSG = 2
PAYLOAD_ACK = 3
PAYLOAD_ADVERT = 4
PAYLOAD_GRP_TXT = 5
PAYLOAD_PATH = 8
PAYLOAD_MULTIPART = 10

ADV_TYPE_CHAT = 1
ADV_TYPE_REPEATER = 2

# Requests (REQ payloads) and telemetry, as in the MeshCore companion firmware
REQ_GET_TELEMETRY = 0x03
TELEM_PERM_BASE = 0x01      # 'base' telemetry: the node's own battery
TELEM_PERM_LOCATION = 0x02  # its position
TELEM_CHANNEL_SELF = 1      # CayenneLPP channel for the node itself
LPP_VOLTAGE = 116           # 2 bytes, 0.01 V
LPP_GPS = 136               # 3+3+3 bytes signed: lat, lon (0.0001 deg), alt (0.01 m)

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


def mac_then_decrypt(secret32: bytes, mac: bytes, ct: bytes):
    """Inverse of encrypt_then_mac. Returns the (zero padded) plaintext, or
    None if the MAC doesn't match."""
    if not ct or len(ct) % 16:
        return None
    if not hmac.compare_digest(mac, hmac.new(secret32, ct, hashlib.sha256).digest()[:2]):
        return None
    d = Cipher(algorithms.AES(secret32[:16]), modes.ECB()).decryptor()
    return d.update(ct) + d.finalize()


def lora_airtime(n_bytes: int, sf: int, bw_hz: float, cr: int, preamble: int = 16) -> float:
    """Approximate LoRa time on air in seconds (explicit header, CRC on, `cr`
    in its 5-8 form). MeshCore uses a 16-symbol preamble."""
    tsym = (1 << sf) / bw_hz
    ldro = 1 if tsym > 0.016 else 0
    n = 8 + max(math.ceil((8 * n_bytes - 4 * sf + 44) / (4 * (sf - 2 * ldro))) * cr, 0)
    return (preamble + 4.25 + n) * tsym


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


def build_txt_msg(dest_pub: bytes, src_pub: bytes, secret32: bytes, text: str, ts: int,
                  attempt: int, path: bytes = None, plb: int = 0):
    """A plain-text message (TXT_MSG) to dest_pub. With a `path` (the path
    the recipient's packet arrived by) it is DIRECT-routed back along the
    reverse of it; with path=None it is flooded.
    Payload: dest hash(1) | src hash(1) | MAC(2) | AES(timestamp|flags|text).
    Returns (packet, expected_ack): the recipient ACKs with the first 4 bytes
    of SHA256(timestamp | flags | text | sender pubkey)."""
    raw = struct.pack("<IB", ts, attempt & 0x03) + text.encode("utf-8")  # flags: plain text, attempt no.
    ack = hashlib.sha256(raw + src_pub).digest()[:4]
    mac, ct = encrypt_then_mac(secret32, raw)
    payload = bytes([dest_pub[0], src_pub[0]]) + mac + ct
    if path is None:
        return bytes([(PAYLOAD_TXT_MSG << 2) | ROUTE_FLOOD, 0x00]) + payload, ack
    header = (PAYLOAD_TXT_MSG << 2) | ROUTE_DIRECT
    return bytes([header, plb]) + reverse_path(path, plb) + payload, ack


def build_path_return(dest_pub: bytes, src_pub: bytes, secret32: bytes, route_to_us: bytes,
                      route_plb: int, path: bytes = None, plb: int = 0,
                      extra_type: int = None, extra: bytes = b"") -> bytes:
    """A PATH packet telling dest_pub how to reach us (`route_to_us`, in
    from-them-to-us order), so they can message/ACK us direct instead of
    flooding. Sent back along the reverse of `path` like build_txt_msg, or
    flooded if path is None. `extra` piggybacks e.g. an ACK; without it,
    0xFF + 4 random bytes (as the firmware does) keeps the packet unique."""
    tail = b"\xff" + os.urandom(4) if extra_type is None else bytes([extra_type]) + extra
    data = bytes([route_plb]) + route_to_us + tail
    mac, ct = encrypt_then_mac(secret32, data)
    payload = bytes([dest_pub[0], src_pub[0]]) + mac + ct
    if path is None:
        return bytes([(PAYLOAD_PATH << 2) | ROUTE_FLOOD, 0x00]) + payload
    header = (PAYLOAD_PATH << 2) | ROUTE_DIRECT
    return bytes([header, plb]) + reverse_path(path, plb) + payload


def build_response(dest_pub: bytes, src_pub: bytes, secret32: bytes, data: bytes,
                   path: bytes = None, plb: int = 0) -> bytes:
    """A RESPONSE packet (answer to a REQ): dest hash | src hash | MAC |
    AES(data). DIRECT back along the reverse of `path`, or flooded."""
    mac, ct = encrypt_then_mac(secret32, data)
    payload = bytes([dest_pub[0], src_pub[0]]) + mac + ct
    if path is None:
        return bytes([(PAYLOAD_RESPONSE << 2) | ROUTE_FLOOD, 0x00]) + payload
    return bytes([(PAYLOAD_RESPONSE << 2) | ROUTE_DIRECT, plb]) + reverse_path(path, plb) + payload


def lpp_telemetry(location=None) -> bytes:
    """CayenneLPP telemetry (channel | type | big-endian value) shaped like a
    companion node's, everything on channel 1: battery voltage (the bot has
    no battery, so a full 4.20 V; apps show it as 100 %) and, if `location`
    = (lat, lon, alt) is given, a GPS reading."""
    out = bytes([TELEM_CHANNEL_SELF, LPP_VOLTAGE]) + struct.pack(">H", 420)
    if location is not None:
        lat, lon, alt = location
        out += bytes([TELEM_CHANNEL_SELF, LPP_GPS]) + b"".join(
            int(round(v * mult)).to_bytes(3, "big", signed=True)
            for v, mult in ((lat, 10000), (lon, 10000), (alt, 100)))
    return out


def build_ack(ack: bytes, path: bytes = None, plb: int = 0) -> bytes:
    """An ACK packet (payload = the 4-byte ACK): DIRECT back along the
    reverse of `path`, or flooded if path is None."""
    if path is None:
        return bytes([(PAYLOAD_ACK << 2) | ROUTE_FLOOD, 0x00]) + ack
    return bytes([(PAYLOAD_ACK << 2) | ROUTE_DIRECT, plb]) + reverse_path(path, plb) + ack


def parse_path_return(plaintext: bytes):
    """Decrypted PATH payload: path-length byte | path | extra type | extra.
    The path is the route a flood from us took to reach the sender, i.e. the
    route to use for direct messages to them. Returns (path, plb,
    extra_type, extra) or None."""
    if not plaintext:
        return None
    plb = plaintext[0]
    n = (plb & 0x3F) * ((plb >> 6) + 1)
    if len(plaintext) < 1 + n + 1:
        return None
    return plaintext[1:1 + n], plb, plaintext[1 + n] & 0x0F, plaintext[2 + n:]


def parse_advert(payload: bytes):
    """Verify and decode an ADVERT payload: pubkey(32) | timestamp(4) |
    signature(64) | appdata. Returns (pubkey, adv_type, name, location) or
    None; location is (lat, lon) in degrees, or None if not advertised."""
    if len(payload) < 101:
        return None
    pub, ts, sig, app = payload[:32], payload[32:36], payload[36:100], payload[100:]
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, pub + ts + app)
    except (InvalidSignature, ValueError):
        return None
    flags = app[0]
    i = 1
    location = None
    if flags & 0x10 and len(app) >= 9:
        lat, lon = struct.unpack_from("<ii", app, 1)   # millionths of a degree
        if (lat, lon) != (0, 0):                        # 0,0 = no position set
            location = (lat / 1e6, lon / 1e6)
        i += 8
    if flags & 0x20:
        i += 2      # feature 1
    if flags & 0x40:
        i += 2      # feature 2
    name = ""
    if flags & 0x80:
        name = app[i:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return pub, flags & 0x0F, name, location


def km_between(a, b) -> float:
    """Great-circle distance in km between two (lat, lon) points."""
    (la1, lo1), (la2, lo2) = [(math.radians(x), math.radians(y)) for x, y in (a, b)]
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(h))


def path_hashes(path: bytes, plb: int):
    """Split a path into its per-hop repeater hashes (1-3 bytes each)."""
    size = (plb >> 6) + 1
    return [path[i:i + size] for i in range(0, len(path), size)]


def build_advert(pub: bytes, signature: bytes, ts: bytes, app: bytes) -> bytes:
    header = (PAYLOAD_ADVERT << 2) | ROUTE_FLOOD
    return bytes([header, 0x00]) + pub + ts + signature + app


# --------------------------------------------------------------------------
# persistent state (SQLite): message log, heard nodes, heartbeat subscriptions
# --------------------------------------------------------------------------

class BotDB:
    def __init__(self, path: str, tz=timezone.utc):
        self.tz = tz                    # zone for the human-readable iso column
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          REAL    NOT NULL,   -- unix time logged by the bot
                iso         TEXT    NOT NULL,   -- same, ISO-8601 local time with UTC offset
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
                status      TEXT                -- tx only: sent / failed / unconfirmed;
                                                -- direct msgs also: acked / no_ack / acked_late
            );
            CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts);
            CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);

            -- nodes whose signed adverts we have heard: name -> public key (and position)
            CREATE TABLE IF NOT EXISTS nodes (
                pubkey     TEXT PRIMARY KEY,    -- hex
                name       TEXT,
                adv_type   INTEGER,
                first_seen REAL,
                last_seen  REAL,
                lat        REAL,                -- advertised position, if any
                lon        REAL
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_name ON nodes(name);

            -- heartbeat subscriptions (one per user name); survive restarts
            CREATE TABLE IF NOT EXISTS hb_subs (
                name        TEXT PRIMARY KEY,
                pubkey      TEXT NOT NULL,      -- hex
                path        TEXT NOT NULL,      -- hex; path from them to us (sent along in reverse)
                plb         INTEGER NOT NULL,   -- raw path-length byte for that path; -1 = no
                                                -- known route, heartbeats are flooded
                enabled_at  REAL NOT NULL,
                expires_at  REAL NOT NULL
            );
        """)
        cols = {r["name"] for r in self.db.execute("PRAGMA table_info(nodes)")}
        for col in ("lat", "lon"):          # databases made before positions were kept
            if col not in cols:
                self.db.execute(f"ALTER TABLE nodes ADD COLUMN {col} REAL")
        self.db.commit()

    # ---- message log
    def add(self, **f) -> int:
        now = time.time()
        row = {
            "ts": now,
            "iso": datetime.fromtimestamp(now, self.tz).isoformat(timespec="seconds"),
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
    def note_node(self, pubkey: bytes, name: str, adv_type: int, location=None):
        now = time.time()
        lat, lon = location if location else (None, None)
        self.db.execute(
            """INSERT INTO nodes (pubkey, name, adv_type, first_seen, last_seen, lat, lon) VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(pubkey) DO UPDATE SET name=excluded.name, adv_type=excluded.adv_type,
                                                 last_seen=excluded.last_seen,
                                                 lat=excluded.lat, lon=excluded.lon""",
            (pubkey.hex(), name, adv_type, now, now, lat, lon))
        self.db.commit()

    def repeater_location(self, h: bytes):
        """Position of the repeater whose public key starts with path hash h,
        if exactly one such repeater is known and it advertised a position."""
        rows = self.db.execute(
            "SELECT lat, lon FROM nodes WHERE substr(pubkey, 1, ?)=? AND adv_type=?",
            (len(h) * 2, h.hex(), ADV_TYPE_REPEATER)).fetchall()
        if len(rows) == 1 and rows[0]["lat"] is not None:
            return rows[0]["lat"], rows[0]["lon"]
        return None

    def nodes_with_hash(self, h: int):
        """Chat nodes (heard advertising) whose public key starts with byte h:
        the candidates for the sender of a direct message."""
        return self.db.execute(
            "SELECT pubkey, name FROM nodes WHERE substr(pubkey, 1, 2)=? AND adv_type=? AND name != ''",
            (f"{h:02x}", ADV_TYPE_CHAT)).fetchall()

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

    def sub_name_for_key(self, pubkey: bytes):
        row = self.db.execute("SELECT name FROM hb_subs WHERE pubkey=?", (pubkey.hex(),)).fetchone()
        return row["name"] if row else None

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
# !wx: East Sooke weather from Open-Meteo (free, no key; https://open-meteo.com)
# --------------------------------------------------------------------------

WX_PLACE = "East Sooke, BC"
WX_LAT, WX_LON = 48.37, -123.68    # the East Sooke community, not anyone's node
# Environment Canada's GEM models (HRDPS 2.5 km where available), metric units
WX_URL = ("https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}"
          "&current=temperature_2m,relative_humidity_2m,dew_point_2m,pressure_msl,"
          "wind_speed_10m,wind_direction_10m,wind_gusts_10m,weather_code,is_day"
          "&hourly=temperature_2m,weather_code,wind_speed_10m,wind_direction_10m"
          "&timezone={tz}&forecast_days=2&models=gem_seamless&wind_speed_unit=kmh")
WX_CACHE_SECONDS = 600             # one fetch serves every !wx for 10 minutes

# WMO weather codes -> (text, day emoji, night emoji)
WX_CODES = {
    0: ("Clear", "\u2600\ufe0f", "\U0001f319"),
    1: ("Mainly Clear", "\U0001f324\ufe0f", "\U0001f319"),
    2: ("Partly Cloudy", "\u26c5", "\u2601\ufe0f"),
    3: ("Overcast", "\u2601\ufe0f", "\u2601\ufe0f"),
    45: ("Fog", "\U0001f32b\ufe0f", None), 48: ("Freezing Fog", "\U0001f32b\ufe0f", None),
    51: ("Lt Drizzle", "\U0001f326\ufe0f", "\U0001f327\ufe0f"), 53: ("Drizzle", "\U0001f327\ufe0f", None),
    55: ("Hvy Drizzle", "\U0001f327\ufe0f", None),
    56: ("Frz Drizzle", "\U0001f9ca", None), 57: ("Frz Drizzle", "\U0001f9ca", None),
    61: ("Lt Rain", "\U0001f326\ufe0f", "\U0001f327\ufe0f"), 63: ("Rain", "\U0001f327\ufe0f", None),
    65: ("Hvy Rain", "\U0001f327\ufe0f", None),
    66: ("Frz Rain", "\U0001f9ca", None), 67: ("Frz Rain", "\U0001f9ca", None),
    71: ("Lt Snow", "\U0001f328\ufe0f", None), 73: ("Snow", "\U0001f328\ufe0f", None),
    75: ("Hvy Snow", "\u2744\ufe0f", None), 77: ("Snow Grains", "\U0001f328\ufe0f", None),
    80: ("Lt Showers", "\U0001f326\ufe0f", "\U0001f327\ufe0f"), 81: ("Showers", "\U0001f327\ufe0f", None),
    82: ("Hvy Showers", "\U0001f327\ufe0f", None),
    85: ("Snow Showers", "\U0001f328\ufe0f", None), 86: ("Snow Showers", "\U0001f328\ufe0f", None),
    95: ("T-Storm", "\u26c8\ufe0f", None), 96: ("T-Storm", "\u26c8\ufe0f", None),
    99: ("T-Storm", "\u26c8\ufe0f", None),
}


def wx_round(x: float) -> int:
    return int(math.floor(x + 0.5))   # round half up, not Python's round-half-even


def wx_sky(code: int, day: bool) -> str:
    text, day_emoji, night_emoji = WX_CODES.get(code, ("?", "", None))
    return (day_emoji if day or not night_emoji else night_emoji) + text


def wx_wind(speed: float, direction: float, gust: float = 0.0) -> str:
    if wx_round(speed) == 0:
        return "Calm"
    points = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"]
    out = f"{points[wx_round(direction / 45) % 8]}{wx_round(speed)}"
    return out + (f"G{wx_round(gust)}" if gust >= speed + 10 else "")


def format_wx(d: dict, max_bytes: int) -> str:
    """Open-Meteo JSON -> one line like the owner's example, metric:
    'East Sooke, BC: Mon: <sky> 13°C 💨SW6 55%RH 💧4° 📊1018hPa | Tonight: <sky> L:6°C 💨SW4'.
    Wind is km/h; Tonight covers the rest of the night until 06:00. Optional
    parts are dropped if the line wouldn't fit in max_bytes."""
    c = d["current"]
    now = datetime.fromisoformat(c["time"])
    head = f"{WX_PLACE}: {now:%a}: {wx_sky(c['weather_code'], c['is_day'])} {wx_round(c['temperature_2m'])}\u00b0C"
    parts = [
        ("wind", "\U0001f4a8" + wx_wind(c["wind_speed_10m"], c["wind_direction_10m"], c.get("wind_gusts_10m") or 0)),
        ("rh", f"{wx_round(c['relative_humidity_2m'])}%RH"),
        ("dew", f"\U0001f4a7{wx_round(c['dew_point_2m'])}\u00b0"),
        ("hpa", f"\U0001f4ca{wx_round(c['pressure_msl'])}hPa"),
    ]

    # tonight: from 18:00 (or now, if later) until 06:00
    h = d["hourly"]
    start = now if (now.hour >= 18 or now.hour < 6) else now.replace(hour=18, minute=0)
    end = start.replace(hour=6, minute=0) + (timedelta(days=1) if start.hour >= 6 else timedelta())
    night = [i for i, t in enumerate(h["time"])
             if start - timedelta(hours=1) < datetime.fromisoformat(t) < end]
    tonight = ""
    if night:
        codes = [h["weather_code"][i] for i in night]
        code = max(set(codes), key=lambda k: (codes.count(k), k))   # most common; ties -> worse
        low = min(h["temperature_2m"][i] for i in night)
        speed = sum(h["wind_speed_10m"][i] for i in night) / len(night)
        x = sum(math.sin(math.radians(h["wind_direction_10m"][i])) for i in night)
        y = sum(math.cos(math.radians(h["wind_direction_10m"][i])) for i in night)
        tonight = (f" | Tonight: {wx_sky(code, False)} L:{wx_round(low)}\u00b0C "
                   f"\U0001f4a8{wx_wind(speed, math.degrees(math.atan2(x, y)) % 360)}")

    def line(ps):
        return " ".join([head] + [t for _, t in ps]) + tonight
    for drop in ("dew", "hpa", "rh"):   # least useful first
        if len(line(parts).encode("utf-8")) <= max_bytes:
            break
        parts = [pt for pt in parts if pt[0] != drop]
    return line(parts)


# --------------------------------------------------------------------------
# the bot
# --------------------------------------------------------------------------

TX_DONE_TIMEOUT = 20.0   # seconds to wait for the modem's TxDone event
MAX_QUEUED_TX = 8
ADVERT_MIN_GAP = 600     # never advert more often than this (seconds)

# How long to wait for a direct message's ACK, modelled on the companion
# firmware: base + factor x packet airtime (per hop for direct routes).
ACK_BASE = 0.5
ACK_FLOOD_FACTOR = 16.0
ACK_DIRECT_HOP_FACTOR = 6.0
ACK_DIRECT_HOP_EXTRA = 0.25


class Bot:
    def __init__(self, args, db: BotDB):
        self.args = args
        self.db = db
        self.chan = Channel(args.channel)
        self.name = args.name
        self.start = time.time()
        self.tz = ZoneInfo(args.timezone)

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
        self.pending_acks = {}             # expected ACK -> direct message awaiting it
        self.expired_acks = OrderedDict()  # ACKs we gave up on: ack -> (name, tx row id)
        self.route_shared = {}             # name -> (path hex, plb) we last told them reaches us
        self.flood_backoff = {}            # name -> (unACKed floods in a row, monotonic time of next flood)
        self.routes = {}                   # pubkey -> (path hex, plb) from them to us, for non-subscribers
        self.dm_queue = asyncio.Queue()    # received direct messages awaiting dm_worker
        self.recent_dms = OrderedDict()    # (pubkey, ts, text) of DMs already answered
        self.wx_cache = None               # (monotonic time, Open-Meteo JSON)
        self.bg_tasks = set()              # replies still being worked out (e.g. !wx fetching)

        # command table: "!cmd" -> handler(ctx) -> reply text (or a coroutine for slow
        # commands like !wx; the reply is then sent when it finishes)
        self.commands = {
            "!ping": self.cmd_ping,
            "!help": lambda c: ("Commands: !ping !wx !time !uptime !stats !echo <text> !heartbeaton "
                                "!heartbeatoff !heartbeat. These commands also work by DM to me."),
            "!time": lambda c: datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S %Z"),
            "!uptime": lambda c: f"up {fmt_duration(time.time() - self.start)}",
            "!stats": self.cmd_stats,
            "!echo": lambda c: c["args"][:100] if c["args"] else "usage: !echo <text>",
            "!heartbeaton": self.cmd_heartbeat_on,
            "!heartbeatoff": self.cmd_heartbeat_off,
            "!heartbeat": self.cmd_heartbeat_status,
            "!wx": self.cmd_wx,
        }

    # ---- commands
    async def cmd_wx(self, c):
        try:
            if self.wx_cache is None or time.monotonic() - self.wx_cache[0] > WX_CACHE_SECONDS:
                data = await asyncio.get_running_loop().run_in_executor(None, self.fetch_wx)
                self.wx_cache = (time.monotonic(), data)
            # leave room for "<bot name>: " in front when posted to the channel
            return format_wx(self.wx_cache[1], MAX_TEXT_BYTES - len(self.name.encode("utf-8")) - 2)
        except Exception as e:
            log.warning("weather fetch failed: %s", e)
            return "weather unavailable right now, try again later"

    def fetch_wx(self) -> dict:
        """Blocking HTTP GET (run in a thread). Replaced by a stub in the tests."""
        url = WX_URL.format(lat=WX_LAT, lon=WX_LON, tz=urllib.parse.quote(self.args.timezone, safe=""))
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.load(r)

    def send_later(self, reply, send):
        """Finish a slow command's reply (a coroutine) in the background, then
        hand the text to send() (which may itself be async)."""
        async def finish():
            text = await reply
            if text:
                result = send(text)
                if asyncio.iscoroutine(result):
                    await result
        task = asyncio.get_running_loop().create_task(finish())
        self.bg_tasks.add(task)
        task.add_done_callback(self.bg_tasks.discard)

    def cmd_ping(self, c):
        """pong @name | 88,77,89 (3 hops) | SNR: -1.5 dB | RSSI: -118 dBm |
        51.3km (2 segs) | 815ms | Rx'd: 10:17:42. Distance adds up the legs
        between consecutive repeaters on the path whose positions we've heard
        advertised; the ms are from the sender's timestamp to our receiving it
        (only meaningful if both clocks are right). Parts are shortened or
        dropped to fit one message."""
        plb, hops = c["plb"], c["hops"]
        hashes = path_hashes(c["path"], plb) if plb is not None and plb >= 0 else None
        if hashes is None:
            route_full = route_short = "route unknown"
        elif not hashes:
            route_full = route_short = "direct (0 hops)"
        else:
            n = f" ({len(hashes)} hop{'s' if len(hashes) != 1 else ''})"
            route_full = ",".join(h.hex() for h in hashes) + n
            route_short = ",".join(h[:1].hex() for h in hashes) + n   # 1st byte only, if space is short

        parts = [("route", route_full)]
        if c["snr"] is not None:
            parts += [("snr", f"SNR: {c['snr']:.1f} dB"), ("rssi", f"RSSI: {c['rssi']} dBm")]
        if hashes:
            spots = [self.db.repeater_location(h) for h in hashes]
            legs = [km_between(a, b) for a, b in zip(spots, spots[1:]) if a and b]
            if legs:
                parts.append(("km", f"{sum(legs):.1f}km ({len(legs)} seg{'s' if len(legs) != 1 else ''})"))
        rx_time = c.get("rx_time") or time.time()
        if c.get("sender_ts"):
            ms = int((rx_time - c["sender_ts"]) * 1000)
            if 0 <= ms < 3_600_000:          # otherwise a clock is off; don't show nonsense
                parts.append(("ms", f"{ms}ms"))
        parts.append(("rx", "Rx'd: " + datetime.fromtimestamp(rx_time, self.tz).strftime("%H:%M:%S")))

        limit = MAX_TEXT_BYTES - len(self.name.encode("utf-8")) - 2   # room for "<bot name>: "

        def line():
            return " | ".join([f"pong @{c['sender']}"] + [t for _, t in parts])
        for step in ("short", "rx", "ms", "rssi"):
            if len(line().encode("utf-8")) <= limit:
                break
            if step == "short":
                parts[0] = ("route", route_short)
            else:
                parts = [pt for pt in parts if pt[0] != step]
        return line()

    def cmd_stats(self, c):
        rx, senders, tx = self.db.summary()
        return f"heard {rx} msgs from {senders} senders, sent {tx}"

    def cmd_heartbeat_on(self, c):
        name, now = c["sender"], time.time()
        # by DM the sender's key is proven by the message itself; in the channel, go by name
        keys = [c["pubkey"]] if c.get("pubkey") else self.db.keys_for_name(name)
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
        self.flood_backoff.pop(name, None)
        self.advert_now.set()  # make sure they can find/add the bot as a contact
        return (f"@{name} heartbeat {'renewed' if renewing else 'ON'} for {hours:g}h: direct msgs every "
                f"{self.args.heartbeat_interval:g}s. Add me as a contact. !heartbeatoff to stop")

    def cmd_heartbeat_off(self, c):
        self.flood_backoff.pop(c["sender"], None)
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

    def enqueue(self, text, *, packet=None, label=None, reply_to=None, cmd=None, jitter=True,
                dm=None, route=None):
        """Queue something for transmission. packet=None means 'post `text`
        to the channel'; otherwise packet is a ready-built raw MeshCore packet
        (a direct message or advert) and text/label are just for the log.
        dm is the ACK-tracking record of a direct message (see send_direct)."""
        self.tx_queue.put_nowait({"text": text, "packet": packet, "label": label,
                                  "reply_to": reply_to, "cmd": cmd, "jitter": jitter,
                                  "dm": dm, "route": route})

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
        pub, adv_type, name, location = parsed
        if pub == self.pubkey or not name:
            return
        self.db.note_node(pub, name, adv_type, location)
        log.debug("heard advert: %s (type %d) %s", name, adv_type, pub.hex()[:12])

    def handle_ack(self, ack: bytes):
        dm = self.pending_acks.pop(ack, None)
        if dm is None:
            late = self.expired_acks.pop(ack, None)
            if late:  # it did get there, we just stopped waiting too soon
                name, row = late
                self.db.set_status(row, "acked_late")
                log.info("late ACK from %s; if this happens often, raise --ack-timeout", name)
            return  # otherwise: someone else's ACK, or a duplicate copy
        if dm["row"] is not None:
            self.db.set_status(dm["row"], "acked")
        if self.flood_backoff.pop(dm["sub"]["name"], None):
            log.info("%s is reachable again; flood backoff reset", dm["sub"]["name"])
        log.info("ACK from %s (%s)", dm["sub"]["name"], "flood" if dm["hops"] is None else "direct")

    def handle_path(self, payload: bytes):
        """A PATH packet: someone answering one of our flooded messages with
        the route it took to reach them (and, inside, their ACK)."""
        if len(payload) < 4 + 16 or payload[0] != self.pubkey[0]:
            return
        if self.seen_before(hashlib.sha256(payload).digest()):
            return
        # only nodes we've messaged can be answering us, so their secret is cached
        for pub, secret in list(self.secrets.items()):
            if pub[0] != payload[1]:
                continue
            parsed = parse_path_return(mac_then_decrypt(secret, payload[2:4], payload[4:]))
            if not parsed:
                continue
            path, plb, extra_type, extra = parsed
            self.routes[pub] = (reverse_path(path, plb).hex(), plb)
            name = self.db.sub_name_for_key(pub)
            if name:
                # stored in from-them-to-us orientation, like a channel path
                self.db.refresh_sub_path(name, reverse_path(path, plb), plb)
                log.info("learned new route to %s: %d hop(s) %s", name, plb & 0x3F, path.hex() or "(direct)")
            if extra_type == PAYLOAD_ACK and len(extra) >= 4:
                self.handle_ack(extra[:4])
            return

    def handle_rx(self, raw: bytes, meta):
        """raw = one received MeshCore packet; meta = (snr, rssi) or None."""
        snr, rssi = meta if meta else (None, None)
        rx_time = time.time()
        log.debug("rx packet %d bytes: %s", len(raw), raw.hex())
        pkt = parse_packet(raw)
        if not pkt:
            return
        if pkt["ptype"] == PAYLOAD_ADVERT:
            self.handle_advert(pkt["payload"])
            return
        if pkt["ptype"] == PAYLOAD_ACK:
            self.handle_ack(pkt["payload"][:4])
            return
        if pkt["ptype"] == PAYLOAD_MULTIPART:
            # newer firmware sends extra ACK copies as MULTIPART: (remaining << 4 | type) | ack
            if pkt["payload"] and pkt["payload"][0] & 0x0F == PAYLOAD_ACK:
                self.handle_ack(pkt["payload"][1:5])
            return
        if pkt["ptype"] == PAYLOAD_PATH:
            self.handle_path(pkt["payload"])
            return
        if pkt["ptype"] in (PAYLOAD_TXT_MSG, PAYLOAD_REQ):
            pl = pkt["payload"]
            if (len(pl) >= 4 + 16 and pl[0] == self.pubkey[0]
                    and not self.seen_before(hashlib.sha256(pl).digest())):
                if self.dm_queue.qsize() < 16:
                    self.dm_queue.put_nowait((pkt, snr, rssi, rx_time))  # decrypting needs the modem
                else:
                    log.warning("too many direct packets waiting; dropped one")
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
            self.flood_backoff.pop(sender, None)

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
        reply = self.run_command(handler, cmd, {
            "sender": sender, "args": args.strip(), "hops": pkt["hops"], "snr": snr, "rssi": rssi,
            "path": pkt["path"], "plb": pkt["plb"], "sender_ts": sender_ts, "rx_time": rx_time})
        if asyncio.iscoroutine(reply):
            self.send_later(reply, lambda text: self.enqueue(text, reply_to=row_id, cmd=cmd))
        elif reply is not None:
            self.enqueue(reply, reply_to=row_id, cmd=cmd)

    def reply_allowed(self, sender, what, per_sender=True) -> bool:
        """The airtime limits: per-sender cooldown (optional), global replies
        per minute, TX queue cap. Counts the reply if allowed."""
        now = time.time()
        if per_sender and now - self.last_reply.get(sender, 0) < self.args.cooldown:
            log.info("rate-limited %s", sender)
            return False
        while self.reply_times and now - self.reply_times[0] > 60:
            self.reply_times.popleft()
        if len(self.reply_times) >= self.args.max_replies_per_min:
            log.warning("global reply limit reached; ignoring %s from %s", what, sender)
            return False
        if self.tx_queue.qsize() >= MAX_QUEUED_TX:
            log.warning("TX queue full; ignoring %s from %s", what, sender)
            return False
        if per_sender:
            self.last_reply[sender] = now
        self.reply_times.append(now)
        return True

    def run_command(self, handler, cmd, ctx):
        """Apply the airtime limits, then run a command. Returns the reply
        text, or None if it was rate-limited or failed."""
        if not self.reply_allowed(ctx["sender"], cmd):
            return None
        try:
            return handler(ctx)
        except Exception:
            log.exception("command %s failed", cmd)
            return None

    # ---- direct messages to the bot
    def peer(self, name: str, pub: bytes):
        """Who to send a direct message to, and by which route: their
        heartbeat subscription if they have one (it holds the freshest route),
        otherwise the route we last learned for them (plb -1 = flood)."""
        sub = self.db.get_sub(name)
        if sub is not None and sub["pubkey"] == pub.hex():
            return sub
        path, plb = self.routes.get(pub, ("", -1))
        return {"name": name, "pubkey": pub.hex(), "path": path, "plb": plb}

    async def dm_worker(self):
        while True:
            pkt, snr, rssi, rx_time = await self.dm_queue.get()
            try:
                await self.handle_dm(pkt, snr, rssi, rx_time)
            except Exception:
                log.exception("failed to handle a direct message")

    async def handle_dm(self, pkt, snr, rssi, rx_time=None):
        """A TXT_MSG or REQ addressed to us: dest hash | src hash | MAC |
        AES(...). The src hash only narrows down the sender; the MAC proves
        which advertised node it is."""
        payload = pkt["payload"]
        for node in self.db.nodes_with_hash(payload[1]):
            pub = bytes.fromhex(node["pubkey"])
            try:
                secret = await self.shared_secret(pub)
            except Exception as e:
                log.warning("key exchange with %s failed (%s)", node["name"], e)
                continue
            pt = mac_then_decrypt(secret, payload[2:4], payload[4:])
            if pt is not None:
                break
        else:
            log.info("direct %s from an unknown node (hash 0x%02x); it needs to send an advert first",
                     "request" if pkt["ptype"] == PAYLOAD_REQ else "message", payload[1])
            return
        if pkt["ptype"] == PAYLOAD_REQ:
            self.handle_request(pkt, snr, rssi, node["name"], pub, secret, pt)
        else:
            await self.handle_text(pkt, snr, rssi, node["name"], pub, secret, pt, rx_time)

    def note_inbound_route(self, name: str, pub: bytes, pkt):
        """Something flooded reached us from them: the path it took is their
        route to us, and our flooded PATH reply will tell them so. Its
        reverse is our route to them."""
        self.routes[pub] = (pkt["path"].hex(), pkt["plb"])
        sub = self.db.get_sub(name)
        if sub is not None and sub["pubkey"] == pub.hex():
            self.db.refresh_sub_path(name, pkt["path"], pkt["plb"])
        self.route_shared[name] = (pkt["path"].hex(), pkt["plb"])
        self.flood_backoff.pop(name, None)

    def handle_request(self, pkt, snr, rssi, name: str, pub: bytes, secret: bytes, pt: bytes):
        """A REQ: AES(tag(4) | request type | ...). Only telemetry is
        answered: a companion app's "path discovery" is a flooded telemetry
        request, and our answer, a flooded PATH carrying the route the request
        took plus the RESPONSE (tag echoed back | telemetry), gives the app the
        route both ways. Asked direct, we answer with a RESPONSE packet."""
        if len(pt) < 5 or pt[4] != REQ_GET_TELEMETRY:
            log.debug("ignored request type %s from %s", pt[4] if len(pt) > 4 else None, name)
            return
        # the byte after the type is an inverse mask of the telemetry wanted (0 = everything)
        wanted = ~pt[5] & 0xFF if len(pt) > 5 else 0xFF
        if not wanted & TELEM_PERM_BASE:
            log.debug("telemetry request from %s excludes base telemetry; not answering", name)
            return
        location = None
        if wanted & TELEM_PERM_LOCATION and self.args.lat is not None:
            location = (self.args.lat, self.args.lon, self.args.alt)
        flooded = pkt["route"] in (ROUTE_FLOOD, ROUTE_TRANSPORT_FLOOD)
        row_id = self.db.add(
            direction="rx", channel=f"dm:{name}", sender=name, text="[telemetry request]",
            sender_ts=struct.unpack_from("<I", pt)[0], hops=pkt["hops"], path=pkt["path"].hex(),
            snr=snr, rssi=rssi, command="telemetry")
        log.info("RX telemetry request [%s, %d hops] from %s", "flood" if flooded else "direct",
                 pkt["hops"], name)
        # no per-sender cooldown: path discovery often follows a DM within seconds
        if not self.reply_allowed(name, "telemetry", per_sender=False):
            return
        reply = pt[:4] + lpp_telemetry(location)
        if flooded:
            self.note_inbound_route(name, pub, pkt)
            packet = build_path_return(pub, self.pubkey, secret, pkt["path"], pkt["plb"],
                                       extra_type=PAYLOAD_RESPONSE, extra=reply)
        else:
            to = self.peer(name, pub)
            packet = build_response(pub, self.pubkey, secret, reply,
                                    *((bytes.fromhex(to["path"]), to["plb"]) if to["plb"] >= 0 else ()))
        # no jitter: the app is timing the round trip
        where = f", location {location[0]:.4f},{location[1]:.4f} @ {location[2]:g}m" if location else ""
        self.enqueue(f"telemetry: 4.20V (100%){where}", packet=packet,
                     label=f"dm:{name}", reply_to=row_id, cmd="telemetry", jitter=False)

    async def handle_text(self, pkt, snr, rssi, name: str, pub: bytes, secret: bytes, pt: bytes,
                          rx_time=None):
        """A TXT_MSG: AES(ts | flags | text). ACK it as the firmware would,
        then answer it like a channel command, by direct message."""
        ts, flags = struct.unpack_from("<IB", pt)
        if flags >> 2:
            log.debug("ignored non-plain-text direct message (type %d) from %s", flags >> 2, name)
            return
        text_b = pt[5:].split(b"\x00", 1)[0]
        ack = hashlib.sha256(pt[:5] + text_b + pub).digest()[:4]
        flooded = pkt["route"] in (ROUTE_FLOOD, ROUTE_TRANSPORT_FLOOD)

        if flooded:
            # Answer like the firmware: a flooded PATH carrying the route it
            # took (so their next messages and ACKs come direct) plus our ACK.
            self.note_inbound_route(name, pub, pkt)
            packet = build_path_return(pub, self.pubkey, secret, pkt["path"], pkt["plb"],
                                       extra_type=PAYLOAD_ACK, extra=ack)
        else:
            to = self.peer(name, pub)   # they reached us direct; ACK the same way if we can
            packet = build_ack(ack, *((bytes.fromhex(to["path"]), to["plb"]) if to["plb"] >= 0 else ()))
        self.enqueue(f"ack {ack.hex()}", packet=packet, label=f"dm:{name}", cmd="ack", jitter=False)

        # their app retries (attempt+1, same timestamp) if our ACK was lost:
        # ACK every copy, but only answer once
        key = (pub, ts, text_b)
        if key in self.recent_dms:
            log.info("repeat of a direct message from %s; ACKed again", name)
            return
        self.recent_dms[key] = True
        while len(self.recent_dms) > 128:
            self.recent_dms.popitem(last=False)

        msg = text_b.decode("utf-8", errors="replace").strip()
        cmd, _, args = msg.partition(" ")
        cmd = cmd.lower()
        if cmd and not cmd.startswith("!"):
            cmd = "!" + cmd     # "!" is optional in a DM
        handler = self.commands.get(cmd)
        row_id = self.db.add(
            direction="rx", channel=f"dm:{name}", sender=name, text=msg, sender_ts=ts,
            hops=pkt["hops"], path=pkt["path"].hex(), snr=snr, rssi=rssi,
            command=cmd if handler else None)
        log.info("RX DM [%s, %d hops%s] %s: %s", "flood" if flooded else "direct", pkt["hops"],
                 f", SNR {snr:.1f} RSSI {rssi}" if snr is not None else "", name, msg)

        if not handler:
            cmd, handler = "!help", self.commands["!help"]  # unknown text gets help, logged as such
        # A direct-routed packet arrives with its path used up; the route it
        # took is the one we hold for them (which we told them to use).
        to = self.peer(name, pub)
        reply = self.run_command(handler, cmd, {
            "sender": name, "args": args.strip(), "snr": snr, "rssi": rssi,
            "hops": to["plb"] & 0x3F if to["plb"] >= 0 else None,
            "path": bytes.fromhex(to["path"]), "plb": to["plb"], "pubkey": pub,
            "sender_ts": ts, "rx_time": rx_time})
        def send(text):
            text = text.encode("utf-8")[:MAX_TEXT_BYTES].decode("utf-8", errors="ignore")
            return self.send_direct(self.peer(name, pub), text, cmd, reply_to=row_id, jitter=True)
        if asyncio.iscoroutine(reply):
            self.send_later(reply, send)
        elif reply is not None:
            await send(reply)

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
            dm = item["dm"]

            self.tx_done.clear()
            self.tx_ok = None
            await self.serial_write(kiss_encode(KISS_CMD_DATA, packet))
            row = self.db.add(direction="tx", channel=label, sender=self.name, text=logged,
                              command=item["cmd"], in_reply_to=item["reply_to"], status="sent",
                              hops=dm["hops"] if dm else None, path=dm["out_path"] if dm else None)
            if dm:
                dm["row"] = row
            log.info("TX [%s%s]: %s", label, f", {item['route']}" if item["route"] else "", logged)
            status = "sent"
            try:
                await asyncio.wait_for(self.tx_done.wait(), TX_DONE_TIMEOUT)
                if not self.tx_ok:
                    log.warning("modem reported TX failure")
                    status = "failed"
            except asyncio.TimeoutError:
                log.warning("no TxDone from modem within %.0fs", TX_DONE_TIMEOUT)
                status = "unconfirmed"
            if status != "sent":
                self.db.set_status(row, status)
            if dm:
                # the ACK clock starts once the packet is actually on air
                dm["status"] = status
                dm["deadline"] = time.monotonic() + self.ack_timeout(len(packet), dm["hops"])

    # ---- heartbeats (direct, opt-in, per user)
    async def send_direct(self, sub, text: str, cmd: str, *, ts=None, attempt=0, flood=None,
                          reply_to=None, jitter=False):
        """Build and queue a text message to a subscriber (or peer(), for a
        DM reply): DIRECT along their known route, or flooded if the route is
        unknown (plb < 0) or flood=True. It is then tracked until its ACK
        arrives (ack_monitor)."""
        pub = bytes.fromhex(sub["pubkey"])
        try:
            secret = await self.shared_secret(pub)
        except Exception as e:
            log.warning("can't send to %s: key exchange failed (%s)", sub["name"], e)
            return
        if flood is None:
            flood = sub["plb"] < 0
        ts = int(time.time()) if ts is None else ts
        path = None if flood else bytes.fromhex(sub["path"])
        if not flood and self.route_shared.get(sub["name"]) != (sub["path"], sub["plb"]):
            # Their node knows us only from our advert, so it would flood its
            # ACKs. Tell it the route to us first (the path we hold is the one
            # from them to us) so the ACKs come back direct.
            self.route_shared[sub["name"]] = (sub["path"], sub["plb"])
            hops = sub["plb"] & 0x3F
            self.enqueue(f"route to me: {sub['path'] or 'direct'} ({hops} hop{'s' if hops != 1 else ''})",
                         packet=build_path_return(pub, self.pubkey, secret, path, sub["plb"], path, sub["plb"]),
                         label=f"dm:{sub['name']}", cmd="path", jitter=False)
        packet, ack = build_txt_msg(pub, self.pubkey, secret, text, ts, attempt, path, sub["plb"])
        hops = None if flood else sub["plb"] & 0x3F
        dm = {"sub": sub, "text": text, "cmd": cmd, "ts": ts, "attempt": attempt, "hops": hops,
              "out_path": None if flood else reverse_path(path, sub["plb"]).hex(),
              "row": None, "status": None, "deadline": None}
        self.pending_acks[ack] = dm
        route = "flood" if flood else f"direct, {hops} hop{'s' if hops != 1 else ''}"
        if attempt:
            route += ", retry"
        self.enqueue(text, packet=packet, label=f"dm:{sub['name']}", cmd=cmd, jitter=jitter,
                     dm=dm, route=route, reply_to=reply_to)

    def ack_timeout(self, packet_len: int, hops) -> float:
        """Seconds to wait for an ACK; hops=None means the message was flooded."""
        if self.args.ack_timeout > 0:
            return self.args.ack_timeout
        air = lora_airtime(packet_len, self.args.sf, self.args.bw * 1000, self.args.cr)
        if hops is None:
            return ACK_BASE + ACK_FLOOD_FACTOR * air
        return ACK_BASE + (ACK_DIRECT_HOP_FACTOR * air + ACK_DIRECT_HOP_EXTRA) * (hops + 1)

    async def ack_monitor(self):
        """Direct messages whose ACK doesn't arrive in time go to dm_unacked."""
        while True:
            await asyncio.sleep(0.1)
            now = time.monotonic()
            for ack, dm in list(self.pending_acks.items()):
                if dm["deadline"] is not None and now >= dm["deadline"] and self.pending_acks.pop(ack, None):
                    self.expired_acks[ack] = (dm["sub"]["name"], dm["row"])
                    while len(self.expired_acks) > 64:
                        self.expired_acks.popitem(last=False)
                    await self.dm_unacked(dm)

    async def dm_unacked(self, dm):
        """No ACK. Like the MeshCore companion clients: a direct route that
        went unanswered is presumed broken, so forget it and resend once by
        flood. The recipient answers a flood with a PATH packet carrying a
        fresh route (and the ACK); until one arrives or they next speak in
        the channel, heartbeats are flooded. A flood that goes unanswered
        is not retried; instead flooded heartbeats back off (flood_delay)."""
        sub, name = dm["sub"], dm["sub"]["name"]
        if dm["status"] == "sent":
            self.db.set_status(dm["row"], "no_ack")
        if dm["hops"] is None:
            misses = self.flood_backoff.get(name, (0, 0))[0] + 1
            delay = self.flood_delay(misses)
            self.flood_backoff[name] = (misses, time.monotonic() + delay)
            log.warning("no ACK from %s for flooded message either; they may be out of range. "
                        "Next flooded heartbeat in %s", name, fmt_duration(delay))
            return
        current = self.db.get_sub(name)
        self.route_shared.pop(name, None)  # the route we gave them may be stale too: re-share
        # don't throw away a route that was refreshed after this message went out
        if current is not None and (current["path"], current["plb"]) == (sub["path"], sub["plb"]):
            self.db.refresh_sub_path(name, b"", -1)
        pub = bytes.fromhex(sub["pubkey"])
        if self.routes.get(pub) == (sub["path"], sub["plb"]):
            del self.routes[pub]
        if current is None and dm["cmd"] == "heartbeat":
            return  # heartbeats were turned off in the meantime
        if self.tx_queue.qsize() >= MAX_QUEUED_TX:
            log.warning("no ACK from %s via direct route; TX queue full, not retrying", name)
            return
        log.info("no ACK from %s via direct route; retrying by flood", name)
        await self.send_direct(sub, dm["text"], dm["cmd"], ts=dm["ts"], attempt=dm["attempt"] + 1, flood=True)

    def flood_delay(self, misses: int) -> float:
        """Seconds to hold off flooding someone after `misses` unACKed floods
        in a row: 2, 4, 8... heartbeat intervals, capped at
        --flood-backoff-max minutes. Each flood costs airtime across the
        whole mesh, so an out-of-range user mustn't get one every interval."""
        return min(self.args.heartbeat_interval * 2 ** misses, self.args.flood_backoff_max * 60)

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

            stamp = datetime.fromtimestamp(now, self.tz).strftime("%H:%M:%S %Z")
            for sub in self.db.active_subs(now):
                if self.tx_queue.qsize() >= MAX_QUEUED_TX:
                    log.warning("TX queue backed up; skipping remaining heartbeats this round")
                    break
                if sub["plb"] < 0 and time.monotonic() < self.flood_backoff.get(sub["name"], (0, 0))[1]:
                    continue  # no route, and recent floods went unanswered: backing off
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
        self.pending_acks.clear()
        self.dm_queue = asyncio.Queue()
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
                     asyncio.create_task(self.ack_monitor()),
                     asyncio.create_task(self.dm_worker()),
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
    db = BotDB(args.db, ZoneInfo(args.timezone))
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
    p.add_argument("--timezone", default="America/Los_Angeles",
                   help="time zone for !time, heartbeats and the database's iso column "
                        "(default America/Los_Angeles, i.e. Pacific; PST/PDT handled automatically)")
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
    p.add_argument("--ack-timeout", type=float, default=0.0,
                   help="seconds to wait for a direct message's ACK before retrying by flood; "
                        "0 = estimate from packet airtime like the companion firmware (default 0)")
    p.add_argument("--flood-backoff-max", type=float, default=30.0,
                   help="when a subscriber is out of range, flooded heartbeats back off (2x, 4x, 8x... "
                        "the interval) up to this many minutes apart (default 30)")
    p.add_argument("--lat", type=float, help="latitude to report in telemetry, e.g. 48.3566 (with --lon)")
    p.add_argument("--lon", type=float, help="longitude to report in telemetry, e.g. -123.6465 (with --lat)")
    p.add_argument("--alt", type=float, default=0.0, help="altitude in metres to report with --lat/--lon (default 0)")
    p.add_argument("--advert-interval", type=float, default=12.0,
                   help="hours between the bot's own adverts; 0 = only at startup and on demand (default 12)")
    args = p.parse_args()
    if (args.lat is None) != (args.lon is None):
        p.error("--lat and --lon must be given together")
    if args.lat is not None and not (-90 <= args.lat <= 90 and -180 <= args.lon <= 180):
        p.error("--lat must be -90..90 and --lon -180..180")
    try:
        ZoneInfo(args.timezone)
    except (ZoneInfoNotFoundError, ValueError):
        p.error(f"unknown time zone {args.timezone!r} (on Windows, run: pip install tzdata)")

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
