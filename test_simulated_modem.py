#!/usr/bin/env python3
"""
End-to-end test of meshcore_kiss_bot.py against a SIMULATED KISS modem.

No radio needed. A fake `serial` module stands in for the modem: it answers
the SetHardware requests (radio config, identity, signing, key exchange),
acknowledges transmissions with TxDone, and lets the test inject received
packets (each followed by an RxMeta frame, as the real modem does).

What it proves: the bot's KISS framing, packet parsing, channel crypto, advert
signing/verification, direct-message building, heartbeat lifecycle and slot cap
are internally consistent. What it does NOT prove: that real MeshCore firmware
agrees with the packet layouts. Run:  python3 test_simulated_modem.py
"""

import argparse
import asyncio
import hashlib
import hmac
import re
import sqlite3
import tempfile
import os
import struct
import sys
import threading
import time
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

import meshcore_kiss_bot as m  # noqa: E402


def raw_pub(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class FakeModem:
    """Stands in for serial.Serial."""
    port = "fake"
    inst = None

    def __init__(self, *a, **k):
        self.out = bytearray()
        self.lock = threading.Lock()
        self.dec = m.KissDecoder()
        self.key = Ed25519PrivateKey.generate()
        self.pub = raw_pub(self.key)
        self.sent = []                      # raw MeshCore packets the bot transmitted
        self.sent_at = []                   # time.monotonic() of each
        self.on_tx = None                   # callback(packet): other radios reacting to it
        FakeModem.inst = self

    def _feed(self, frame):
        with self.lock:
            self.out += frame

    def inject(self, packet, snr=6.0, rssi=-90):
        """Deliver a received packet, followed by its RxMeta frame."""
        self._feed(m.kiss_encode(0, packet))
        self._feed(m.kiss_encode(6, bytes([0xF9, int(snr * 4) & 0xFF, rssi & 0xFF])))

    def read(self, n):
        with self.lock:
            if self.out:
                data = bytes(self.out[:n])
                del self.out[:n]
                return data
        time.sleep(0.02)
        return b""

    def write(self, data):
        for type_byte, p in self.dec.feed(data):
            cmd = type_byte & 0x0F
            if cmd == 0:                                    # packet to transmit
                self.sent.append(p)
                self.sent_at.append(time.monotonic())
                self._feed(m.kiss_encode(6, bytes([0xF8, 1])))   # TxDone, success
                if self.on_tx:
                    self.on_tx(p)
            elif cmd == 6:                                  # SetHardware request
                sub, body = p[0], p[1:]
                resp = {
                    0x09: bytes([0xF0]),                                            # SetRadio -> OK
                    0x0A: bytes([0xF0]),                                            # SetTxPower -> OK
                    0x0B: bytes([0x8B]) + struct.pack("<IIBB", 910525000, 62500, 7, 5),
                    0x01: bytes([0x81]) + self.pub,                                 # identity
                    0x04: bytes([0x84]) + self.key.sign(body),                      # signature
                    0x07: bytes([0x87]) + hashlib.sha256(body).digest(),            # "shared secret"
                }[sub]
                self._feed(m.kiss_encode(6, resp))

    def close(self):
        pass


fake_serial = types.ModuleType("serial")
fake_serial.Serial = FakeModem
sys.modules["serial"] = fake_serial


# ---- helpers that play the part of other people's radios ----

chan = m.Channel("#bot")
_ts = [int(time.time())]


def chan_pkt(text, path=b""):
    """A flood group-text packet as heard from another node (unique timestamp
    each time, or the bot's dedupe would drop repeats of the same text)."""
    _ts[0] += 1
    raw = struct.pack("<IB", _ts[0], 0) + text.encode()
    mac, ct = m.encrypt_then_mac(chan._key32, raw)
    return bytes([(m.PAYLOAD_GRP_TXT << 2) | m.ROUTE_FLOOD, len(path)]) + path + bytes([chan.hash]) + mac + ct


def make_advert(key, name, adv_type=m.ADV_TYPE_CHAT, loc=None):
    """A signed advert; loc = (lat, lon) adds a position (millionths of a degree)."""
    pub = raw_pub(key)
    ts = struct.pack("<I", int(time.time()))
    app = bytes([0x80 | (0x10 if loc else 0) | adv_type])
    if loc:
        app += struct.pack("<ii", round(loc[0] * 1e6), round(loc[1] * 1e6))
    app += name.encode()
    return m.build_advert(pub, key.sign(pub + ts + app), ts, app)


def channel_replies(modem):
    return [chan.decrypt(m.parse_packet(s)["payload"])[2]
            for s in modem.sent if m.parse_packet(s)["ptype"] == m.PAYLOAD_GRP_TXT]


def open_dm(packet, secret):
    """Decrypt a text message the bot sent (direct or flood); returns
    (parsed, dest_hash, src_hash, body) where body = ts | flags | text."""
    p = m.parse_packet(packet)
    pl = p["payload"]
    assert p["ptype"] == m.PAYLOAD_TXT_MSG
    mac, ct = pl[2:4], pl[4:]
    assert hmac.compare_digest(mac, hmac.new(secret, ct, hashlib.sha256).digest()[:2]), "bad MAC"
    pt = Cipher(algorithms.AES(secret[:16]), modes.ECB()).decryptor().update(ct)
    return p, pl[0], pl[1], pt[:5] + pt[5:].split(b"\0", 1)[0]


def decode_dm(packet, secret):
    """Decrypt a DIRECT message the bot sent; returns (parsed, dest_hash, src_hash, text)."""
    p, dest, src, body = open_dm(packet, secret)
    assert p["route"] == m.ROUTE_DIRECT
    return p, dest, src, body[5:].decode()


def dms_in(modem, start, secret):
    """(parsed, attempt, text) for each text message the bot sent since modem.sent[start]."""
    out = []
    for s in modem.sent[start:]:
        if m.parse_packet(s)["ptype"] == m.PAYLOAD_TXT_MSG:
            p, _, _, body = open_dm(s, secret)
            out.append((p, body[4] & 3, body[5:].decode()))
    return out


class RemoteNode:
    """Plays a user's node answering the bot's text messages as MeshCore
    firmware does: a direct message gets a plain ACK; a flood gets a PATH
    packet carrying the route the flood took to reach it, plus the ACK."""

    def __init__(self, modem, pub, secret, route_from_bot):
        self.modem, self.pub, self.secret = modem, pub, secret
        self.route_from_bot = route_from_bot   # path a flood from the bot takes to get here
        self.reachable = True
        self.dead_paths = set()                # direct routes that no longer get through
        self.route_to_bot = None               # learned from the bot's PATH packets
        self.ack_routes = []                   # route type of each ACK she sent
        self.acks_received = []                # (ack, route type) of ACKs the bot sent her
        self.responses = []                    # (data, route type, PATH route or None) of RESPONSEs to her

    def send_req(self, tag, inv_mask=0xFE, path=b"", direct=False):
        """Her app's telemetry request, as the companion firmware builds it
        for "path discovery": AES(tag | 0x03 | inverse permission mask
        (0xFE = base telemetry only) | 3 reserved | 4 random)."""
        data = struct.pack("<I", tag) + bytes([0x03, inv_mask, 0, 0, 0]) + os.urandom(4)
        mac, ct = m.encrypt_then_mac(self.secret, data)
        payload = bytes([self.modem.pub[0], self.pub[0]]) + mac + ct
        if direct:
            pkt = bytes([(m.PAYLOAD_REQ << 2) | m.ROUTE_DIRECT, 0]) + payload
        else:   # transport-flood with region codes, as her real app sends it
            pkt = bytes([(m.PAYLOAD_REQ << 2) | m.ROUTE_TRANSPORT_FLOOD]) + b"\xe1\x23\x00\x00" \
                + bytes([len(path)]) + path + payload
        self.modem.inject(pkt)

    def send_dm(self, text, ts, attempt=0, path=b"", direct=False):
        """She sends the bot a direct message: flooded (arriving with `path`)
        or, once she has a route, direct (repeaters strip the path on the way).
        Returns the ACK she expects back."""
        pkt, ack = m.build_txt_msg(self.modem.pub, self.pub, self.secret, text, ts, attempt)
        if direct:
            pkt = bytes([(m.PAYLOAD_TXT_MSG << 2) | m.ROUTE_DIRECT, 0]) + pkt[2:]
        else:
            pkt = bytes([pkt[0], len(path)]) + path + pkt[2:]
        self.modem.inject(pkt)
        return ack

    def __call__(self, packet):
        p = m.parse_packet(packet)
        if p["ptype"] == m.PAYLOAD_ACK:     # ACK packets carry no address
            if self.reachable:
                self.acks_received.append((p["payload"][:4], p["route"]))
            return
        if p["ptype"] not in (m.PAYLOAD_TXT_MSG, m.PAYLOAD_PATH, m.PAYLOAD_RESPONSE) or p["payload"][0] != self.pub[0]:
            return
        flood = p["route"] == m.ROUTE_FLOOD
        if not self.reachable or (not flood and p["path"] in self.dead_paths):
            return
        if p["ptype"] == m.PAYLOAD_PATH:   # the bot telling her how to reach it
            pl = p["payload"]
            path, plb, extra_type, extra = m.parse_path_return(m.mac_then_decrypt(self.secret, pl[2:4], pl[4:]))
            self.route_to_bot = path
            if extra_type == m.PAYLOAD_ACK:
                self.acks_received.append((extra[:4], p["route"]))
            elif extra_type == m.PAYLOAD_RESPONSE:
                self.responses.append((extra, p["route"], path))
            return
        if p["ptype"] == m.PAYLOAD_RESPONSE:
            pl = p["payload"]
            self.responses.append((m.mac_then_decrypt(self.secret, pl[2:4], pl[4:]), p["route"], None))
            return
        body = open_dm(packet, self.secret)[3]
        ack = hashlib.sha256(body + self.modem.pub).digest()[:4]
        if flood:
            data = bytes([len(self.route_from_bot)]) + self.route_from_bot + bytes([m.PAYLOAD_ACK]) + ack
            mac, ct = m.encrypt_then_mac(self.secret, data)
            reply = (bytes([(m.PAYLOAD_PATH << 2) | m.ROUTE_FLOOD, 0, self.modem.pub[0], self.pub[0]])
                     + mac + ct)
        elif self.route_to_bot is not None:
            # direct: each repeater strips its hash, so it arrives with an empty path
            reply = bytes([(m.PAYLOAD_ACK << 2) | m.ROUTE_DIRECT, 0]) + ack
        else:
            reply = bytes([(m.PAYLOAD_ACK << 2) | m.ROUTE_FLOOD, 0]) + ack
        self.ack_routes.append(m.parse_packet(reply)["route"])
        self.modem.inject(reply)


def decode_lpp(buf):
    """Minimal CayenneLPP reader for the types the bot sends: {(channel, type): value}.
    Unknown types end the read, so any leftover bytes show up as ('rest', ...)."""
    sizes = {116: 2, 136: 9}
    out, i = {}, 0
    while i + 2 <= len(buf) and buf[i + 1] in sizes:
        ch, t, n = buf[i], buf[i + 1], sizes[buf[i + 1]]
        v = buf[i + 2:i + 2 + n]
        if t == 136:   # GPS: lat, lon (0.0001 deg), alt (0.01 m), 3 bytes signed each
            out[(ch, t)] = tuple(int.from_bytes(v[k:k + 3], "big", signed=True) / d
                                 for k, d in ((0, 10000), (3, 10000), (6, 100)))
        else:
            out[(ch, t)] = int.from_bytes(v, "big")
        i += 2 + n
    if buf[i:].rstrip(bytes(1)):   # trailing zeros are just AES block padding
        out["rest"] = buf[i:].hex()
    return out


def sample_wx():
    """Canned Open-Meteo answer (the tests never touch the internet): Monday
    15:45, clear, 13.2 C, SW 6 km/h; tonight (18:00-06:00) mostly overcast,
    low 6 C, W 4 km/h."""
    times = [f"2026-10-{12 + h // 24}T{h % 24:02d}:00" for h in range(48)]
    night = set(range(18, 30))
    return {
        "current": {"time": "2026-10-12T15:45", "temperature_2m": 13.2, "relative_humidity_2m": 55,
                    "dew_point_2m": 4.4, "pressure_msl": 1017.5, "wind_speed_10m": 6.1,
                    "wind_direction_10m": 235, "wind_gusts_10m": 7.9, "weather_code": 0, "is_day": 1},
        "hourly": {"time": times,
                   "temperature_2m": [6.0 if 24 <= h < 30 else 9.0 if h in night else 12.0 for h in range(48)],
                   "weather_code": [3 if 18 <= h < 25 else 0 for h in range(48)],
                   "wind_speed_10m": [4.0] * 48, "wind_direction_10m": [270] * 48},
    }


WX_EXPECTED = ("East Sooke, BC: Mon: \u2600\ufe0fClear 13\u00b0C \U0001f4a8SW6 55%RH \U0001f4a74\u00b0 "
               "\U0001f4ca1018hPa | Tonight: \u2601\ufe0fOvercast L:6\u00b0C \U0001f4a8W4")


def check(cond, label):
    print(("PASS  " if cond else "FAIL  ") + label)
    if not cond:
        raise AssertionError(label)


async def main():
    alice_key = Ed25519PrivateKey.generate()
    alice_pub = raw_pub(alice_key)
    alice_secret = hashlib.sha256(alice_pub).digest()   # what FakeModem's key exchange returns

    args = argparse.Namespace(
        serial="x", baud=1, channel="#bot", name="MeshBot", freq=910.525, bw=62.5, sf=7, cr=5, power=22,
        cooldown=0, max_replies_per_min=100, delay_min=0, delay_max=0,
        heartbeat_interval=0.5, heartbeat_hours=2.2 / 3600,   # 2.2 s "24 hours" so expiry is testable
        max_heartbeat_subs=1, advert_interval=0, ack_timeout=0.15, timezone="America/Los_Angeles",
        flood_backoff_max=0.05,                               # 3 s cap so the backoff is testable
        lat=49.2827, lon=-123.1207, alt=70.5)                 # made-up fixed position for telemetry
    db = m.BotDB(":memory:")
    bot = m.Bot(args, db)
    wx_calls = []

    def fake_fetch_wx():
        wx_calls.append(1)
        if bot.wx_fail:
            raise OSError("network down")
        return sample_wx()
    bot.wx_fail = False
    bot.fetch_wx = fake_fetch_wx
    run = asyncio.create_task(bot.run_once())
    await asyncio.sleep(0.5)
    modem = FakeModem.inst
    alice = RemoteNode(modem, alice_pub, alice_secret, route_from_bot=b"\x55\x66")
    modem.on_tx = alice
    await asyncio.sleep(3.2)        # the bot's startup advert fires 3 s after connect

    # --- startup advert is signed correctly and verifies
    adverts = [s for s in modem.sent if m.parse_packet(s)["ptype"] == m.PAYLOAD_ADVERT]
    check(bool(adverts), "bot broadcast an advert at startup")
    pub, adv_type, name, _loc = m.parse_advert(m.parse_packet(adverts[0])["payload"])
    check((pub, adv_type, name) == (modem.pub, m.ADV_TYPE_CHAT, "MeshBot"), "bot advert verifies and carries its name")

    # --- channel command: !ping
    modem.inject(chan_pkt("Carol: !ping", b"\x44"))
    await asyncio.sleep(0.4)
    ping = [r for r in channel_replies(modem) if "pong" in r]
    check(bool(ping) and "@Carol" in ping[-1] and "1 hop" in ping[-1], f"!ping answered with hop count ({ping[-1] if ping else None})")

    # --- !ping over several repeaters, with distance (repeaters' positions from their adverts)
    reps = []
    while len({raw_pub(k)[0] for k in reps}) < 4:
        reps = [Ed25519PrivateKey.generate() for _ in range(4)]
    spots = [(48.0, -123.0), (48.5, -123.0), (49.0, -123.0), None]   # the 4th never gave a position
    for i, (k, loc) in enumerate(zip(reps, spots)):
        modem.inject(make_advert(k, f"Rpt{i}", m.ADV_TYPE_REPEATER, loc))
    await asyncio.sleep(0.3)
    check(db.repeater_location(raw_pub(reps[0])[:1]) == (48.0, -123.0)
          and db.repeater_location(raw_pub(reps[3])[:1]) is None,
          "repeater positions are kept from their adverts")
    _ts[0] = int(time.time()) - 3                     # sent ~2 s ago, by the sender's clock
    path1 = bytes(raw_pub(k)[0] for k in reps)
    modem.inject(chan_pkt("Dave: !ping", path1))
    await asyncio.sleep(0.4)
    reply = channel_replies(modem)[-1]
    hashes = ",".join(f"{b:02x}" for b in path1)
    check(re.fullmatch(rf"MeshBot: pong @Dave \| {hashes} \(4 hops\) \| SNR: 6\.0 dB \| RSSI: -90 dBm \| "
                       rf"111\.2km \(2 segs\) \| [23]\d\d\dms \| Rx'd: \d\d:\d\d:\d\d", reply) is not None,
          f"multi-hop !ping: path, signal, distance over known legs, latency, time ({reply})")

    # 3-byte repeater IDs (as on the owner's mesh): full IDs shown, distance still found
    path3 = b"".join(raw_pub(k)[:3] for k in reps)
    raw = struct.pack("<IB", int(time.time()) - 5, 0) + b"Dave: !ping"   # own timestamp, or it's a duplicate
    mac, ct = m.encrypt_then_mac(chan._key32, raw)
    modem.inject(bytes([(m.PAYLOAD_GRP_TXT << 2) | m.ROUTE_FLOOD, 0x80 | 4]) + path3 + bytes([chan.hash]) + mac + ct)
    await asyncio.sleep(0.4)
    reply = channel_replies(modem)[-1]
    check(",".join(raw_pub(k)[:3].hex() for k in reps) + " (4 hops)" in reply and "111.2km (2 segs)" in reply,
          f"3-byte repeater IDs shown in full, distance found ({reply})")

    # a long name: the line is shortened to fit one message, keeping the key facts
    long_name = "Somebody-With-A-Very-Long-Name"
    _ts[0] = int(time.time()) - 3
    raw = struct.pack("<IB", _ts[0] + 1, 0) + f"{long_name}: !ping".encode()
    mac, ct = m.encrypt_then_mac(chan._key32, raw)
    modem.inject(bytes([(m.PAYLOAD_GRP_TXT << 2) | m.ROUTE_FLOOD, 0x80 | 4]) + path3 + bytes([chan.hash]) + mac + ct)
    await asyncio.sleep(0.4)
    reply = channel_replies(modem)[-1]
    check(len(reply.encode()) <= m.MAX_TEXT_BYTES and f"{hashes} (4 hops)" in reply
          and "111.2km" in reply and "SNR" in reply,
          f"long !ping line shortened to fit ({len(reply.encode())} bytes: {reply})")

    # --- same packet arriving twice is processed once
    dup = chan_pkt("Carol: !time")
    modem.inject(dup)
    modem.inject(dup)
    await asyncio.sleep(0.4)
    check(sum(1 for s in db.db.execute("SELECT 1 FROM messages WHERE command='!time' AND direction='rx'")) == 1,
          "duplicate packet logged and answered once")
    reply = channel_replies(modem)[-1]
    check(reply.endswith((" PST", " PDT")), f"!time answers in Pacific time ({reply})")

    # --- !wx (East Sooke weather; the fetch is stubbed with sample data)
    modem.inject(chan_pkt("Carol: !wx"))
    await asyncio.sleep(0.5)
    reply = channel_replies(modem)[-1]
    check(reply == "MeshBot: " + WX_EXPECTED, f"!wx answers in the channel, metric, owner's format ({reply})")
    check(len(reply.encode("utf-8")) <= m.MAX_TEXT_BYTES, f"!wx fits in one message ({len(reply.encode())} bytes)")
    modem.inject(chan_pkt("Carol: !wx"))
    await asyncio.sleep(0.5)
    check(len(wx_calls) == 1 and channel_replies(modem)[-1] == "MeshBot: " + WX_EXPECTED,
          "a second !wx within 10 minutes is answered from the cache (one fetch)")
    trimmed = m.format_wx(sample_wx(), 100)
    check(len(trimmed.encode()) <= 100 and "Tonight" in trimmed and "\U0001f4a7" not in trimmed,
          f"if space is short, the least useful parts are dropped first ({len(trimmed.encode())} bytes)")
    bot.wx_cache, bot.wx_fail = None, True
    modem.inject(chan_pkt("Carol: !wx"))
    await asyncio.sleep(0.5)
    check("weather unavailable" in channel_replies(modem)[-1], "!wx says so if the weather service can't be reached")
    bot.wx_fail = False

    # --- !heartbeaton before any advert has been heard
    modem.inject(chan_pkt("Alice: !heartbeaton", b"\x11\x22"))
    await asyncio.sleep(0.4)
    check(db.get_sub("Alice") is None and "haven't heard an advert" in channel_replies(modem)[-1],
          "!heartbeaton without a known key is refused and asks for an advert")

    # --- Alice's advert is heard, then she enables heartbeats
    modem.inject(make_advert(alice_key, "Alice"))
    await asyncio.sleep(0.2)
    check(db.keys_for_name("Alice") == [alice_pub], "advert from Alice stored (name -> public key)")
    modem.inject(chan_pkt("Alice: !heartbeaton", b"\x11\x22"))
    await asyncio.sleep(0.4)
    sub = db.get_sub("Alice")
    check(sub is not None and bytes.fromhex(sub["pubkey"]) == alice_pub, "subscription created")

    # --- heartbeat is DIRECT, along the reversed path, decryptable by Alice
    n0 = len(modem.sent)
    await asyncio.sleep(0.8)
    dms = [s for s in modem.sent[n0:] if m.parse_packet(s)["ptype"] == m.PAYLOAD_TXT_MSG]
    check(bool(dms), "heartbeat sent as a direct message (not a channel post)")
    p, dest, src, text = decode_dm(dms[0], alice_secret)
    check(p["path"] == b"\x22\x11", "direct route follows the reverse of the inbound path")
    check(dest == alice_pub[0] and src == modem.pub[0], "destination and source hashes correct")
    check(text.startswith("heartbeat "), f"heartbeat text decrypts for the recipient ({text!r})")

    # --- reciprocal path: before the first heartbeat she's told the route to the bot, so ACKs come back direct
    paths = [s for s in modem.sent if m.parse_packet(s)["ptype"] == m.PAYLOAD_PATH]
    check(bool(paths) and m.parse_packet(paths[0])["route"] == m.ROUTE_DIRECT
          and modem.sent.index(paths[0]) < modem.sent.index(dms[0]),
          "bot sends her a direct PATH packet ahead of the first heartbeat")
    check(alice.route_to_bot == b"\x11\x22", "PATH tells her the route her own message took to the bot")
    check(alice.ack_routes and set(alice.ack_routes) == {m.ROUTE_DIRECT}, "her ACKs come back direct, not flooded")
    check(len(paths) == 1, "route is shared once, not with every heartbeat")

    # --- ACK handling (keep the sub alive for these; it normally lasts 2.2 s here)
    db.db.execute("UPDATE hb_subs SET expires_at=?", (time.time() + 60,))
    await asyncio.sleep(0.3)
    check(db.db.execute("SELECT COUNT(*) FROM messages WHERE command='heartbeat' AND status='acked'").fetchone()[0] > 0
          and not db.db.execute("SELECT 1 FROM messages WHERE status='no_ack'").fetchall(),
          "ACKed direct heartbeats are marked acked, nothing falls back to flood")

    # --- a repeater on her route disappears: no ACK -> flood retry -> PATH return gives a new route
    alice.dead_paths.add(b"\x22\x11")
    n = len(modem.sent)
    await asyncio.sleep(1.3)
    sent = dms_in(modem, n, alice_secret)
    lost = [t for p, a, t in sent if p["route"] == m.ROUTE_DIRECT and p["path"] == b"\x22\x11"]
    retries = [t for p, a, t in sent if p["route"] == m.ROUTE_FLOOD and a == 1]
    check(bool(lost) and retries and retries[0] == lost[0],
          "unACKed direct heartbeat is resent by flood (same text, attempt 1)")
    check(db.get_sub("Alice")["path"] == "6655" and sent[-1][0]["path"] == b"\x55\x66"
          and sent[-1][0]["route"] == m.ROUTE_DIRECT,
          "route learned from the PATH reply; later heartbeats go direct along it")
    check(alice.route_to_bot == b"\x66\x55", "new route back to the bot shared with her")
    check(db.db.execute("SELECT COUNT(*) FROM messages WHERE command='heartbeat' AND path='5566' "
                        "AND status='acked'").fetchone()[0] > 0,
          "heartbeats on the new route are ACKed")

    # --- she goes out of range completely: route forgotten, heartbeats flood, no endless retries
    alice.reachable = False
    n = len(modem.sent)
    await asyncio.sleep(5.5)
    sent = dms_in(modem, n, alice_secret)
    check(db.get_sub("Alice")["plb"] == -1, "unreachable user: stored route reset")
    check(sum(1 for p, a, t in sent if p["route"] == m.ROUTE_DIRECT) == 1
          and sum(1 for p, a, t in sent if a == 1) == 1,
          "after the failed direct heartbeat, one flood retry, and a failed flood is not retried")
    floods = [modem.sent_at[i] for i in range(n, len(modem.sent))
              if m.parse_packet(modem.sent[i])["ptype"] == m.PAYLOAD_TXT_MSG
              and m.parse_packet(modem.sent[i])["route"] == m.ROUTE_FLOOD]
    gaps = [round(b - a, 2) for a, b in zip(floods, floods[1:])]
    # interval 0.5 s: unanswered floods are followed by waits of 1 s, then 2 s (instead of every 0.5 s)
    check(len(floods) == 3 and gaps[0] >= 1.0 and gaps[1] >= 2.0,
          f"flooded heartbeats back off while unanswered (gaps between floods: {gaps} s)")
    check([bot.flood_delay(k) for k in (1, 2, 3, 6)] == [1.0, 2.0, 3.0, 3.0],
          "backoff doubles each time and stops at --flood-backoff-max")

    # --- back in range: the next flooded heartbeat's PATH reply restores a direct route
    alice.reachable = True
    for _ in range(50):
        await asyncio.sleep(0.1)
        if db.get_sub("Alice")["plb"] == 2:
            break
    await asyncio.sleep(0.6)
    check(db.get_sub("Alice")["plb"] == 2 and dms_in(modem, n, alice_secret)[-1][0]["route"] == m.ROUTE_DIRECT
          and "Alice" not in bot.flood_backoff,
          "back in range: route relearned, backoff reset, direct heartbeats resume")

    # --- path refresh when she speaks again by a different route
    modem.inject(chan_pkt("Alice: hi", b"\x33"))
    await asyncio.sleep(0.2)
    check(bytes.fromhex(db.get_sub("Alice")["path"]) == b"\x33", "stored path refreshed from her latest message")

    # --- status, then off stops DMs
    modem.inject(chan_pkt("Alice: !heartbeat"))
    await asyncio.sleep(0.3)
    check("ON" in channel_replies(modem)[-1], "!heartbeat reports ON")
    modem.inject(chan_pkt("Alice: !heartbeatoff"))
    await asyncio.sleep(0.3)
    n1 = len(modem.sent)
    await asyncio.sleep(1.2)
    check(db.get_sub("Alice") is None and not [s for s in modem.sent[n1:] if m.parse_packet(s)["ptype"] == m.PAYLOAD_TXT_MSG],
          "!heartbeatoff removes the subscription and stops direct messages")

    # --- renewal expires: final notice, then subscription removed
    modem.inject(chan_pkt("Alice: !heartbeaton", b"\x11"))
    await asyncio.sleep(0.3)
    n2 = len(modem.sent)
    await asyncio.sleep(3.2)
    texts = [decode_dm(s, alice_secret)[3] for s in modem.sent[n2:] if m.parse_packet(s)["ptype"] == m.PAYLOAD_TXT_MSG]
    check(len(texts) >= 2 and texts[-1].startswith("heartbeats ended") and db.get_sub("Alice") is None,
          f"subscription expires with a final direct notice ({len(texts)} DMs, last: {texts[-1][:30] if texts else None!r}...)")

    # --- slot cap: with 1 slot used, a second user is refused
    modem.inject(chan_pkt("Alice: !heartbeaton", b"\x11"))
    await asyncio.sleep(0.3)
    bob_key = Ed25519PrivateKey.generate()
    modem.inject(make_advert(bob_key, "Bob"))
    await asyncio.sleep(0.2)
    modem.inject(chan_pkt("Bob: !heartbeaton"))
    await asyncio.sleep(0.3)
    check(db.get_sub("Bob") is None and "slots" in channel_replies(modem)[-1], "slot cap (--max-heartbeat-subs) enforced")

    # --- tampered advert is rejected
    bad = bytearray(make_advert(Ed25519PrivateKey.generate(), "Mallory"))
    bad[-1] ^= 1
    modem.inject(bytes(bad))
    await asyncio.sleep(0.2)
    check(not db.keys_for_name("Mallory"), "advert with a bad signature is ignored")

    # --- other channel's traffic is ignored
    other = m.Channel("#other")
    modem.inject(bytes([(m.PAYLOAD_GRP_TXT << 2) | m.ROUTE_FLOOD, 0]) + other.encrypt("Eve: !ping"))
    await asyncio.sleep(0.2)
    check(not db.db.execute("SELECT 1 FROM messages WHERE sender='Eve'").fetchall(), "messages for a different channel are ignored")

    # --- direct messages to the bot (Alice's heartbeats off, so only DM traffic is on air)
    db.remove_sub("Alice")
    await asyncio.sleep(0.6)
    n = len(modem.sent)
    ts = int(time.time()) + 1000
    ack = alice.send_dm("!ping", ts, path=b"\x77")
    await asyncio.sleep(0.5)
    check((ack, m.ROUTE_FLOOD) in alice.acks_received and alice.route_to_bot == b"\x77",
          "flooded DM is ACKed with a PATH reply giving her the route to the bot")
    pongs = [p for p, a, t in dms_in(modem, n, alice_secret) if "pong" in t]
    check(len(pongs) == 1 and pongs[0]["route"] == m.ROUTE_DIRECT and pongs[0]["path"] == b"\x77",
          "!ping by DM is answered by direct message along the reverse of her path")
    check(db.db.execute("SELECT 1 FROM messages WHERE direction='rx' AND channel='dm:Alice' "
                        "AND command='!ping'").fetchone() is not None, "DM logged as channel dm:Alice")

    n, before = len(modem.sent), len(alice.acks_received)
    ack2 = alice.send_dm("!ping", ts, attempt=1, path=b"\x77")   # her app retrying
    await asyncio.sleep(0.5)
    check(ack2 in [a for a, r in alice.acks_received[before:]]
          and not [t for p, a, t in dms_in(modem, n, alice_secret) if "pong" in t],
          "a retried DM is ACKed again but answered only once")

    n, before = len(modem.sent), len(alice.acks_received)
    ack3 = alice.send_dm("time", ts + 1, direct=True)
    await asyncio.sleep(0.5)
    check((ack3, m.ROUTE_DIRECT) in alice.acks_received[before:], "DM that arrived direct is ACKed direct")
    check([t for p, a, t in dms_in(modem, n, alice_secret) if t.endswith((" PST", " PDT"))],
          "'time' without the ! works by DM")

    n = len(modem.sent)
    alice.send_dm("wx", ts + 4, direct=True)
    await asyncio.sleep(0.5)
    check(WX_EXPECTED in [t for p, a, t in dms_in(modem, n, alice_secret)], "'wx' works by DM too")

    n = len(modem.sent)
    alice.send_dm("heartbeatof", ts + 3, direct=True)   # a typo
    await asyncio.sleep(0.5)
    helps = [t for p, a, t in dms_in(modem, n, alice_secret) if t.startswith("Commands:")]
    last_tx = db.db.execute("SELECT command FROM messages WHERE direction='tx' AND channel='dm:Alice' "
                            "AND command != 'ack' ORDER BY id DESC LIMIT 1").fetchone()["command"]
    check(helps and helps[0].endswith("These commands also work by DM to me.") and last_tx == "!help",
          f"unknown DM text gets the help reply, logged as !help (logged {last_tx!r})")

    n = len(modem.sent)
    rows = db.db.execute("SELECT COUNT(*) FROM messages WHERE direction='rx'").fetchone()[0]
    stranger = raw_pub(Ed25519PrivateKey.generate())
    RemoteNode(modem, stranger, hashlib.sha256(stranger).digest(), b"").send_dm("!ping", ts)
    await asyncio.sleep(0.5)
    check(len(modem.sent) == n and db.db.execute("SELECT COUNT(*) FROM messages WHERE direction='rx'").fetchone()[0] == rows,
          "DM from a node whose advert was never heard is ignored")

    # --- telemetry: a companion app's "path discovery" (flooded telemetry request)
    await asyncio.sleep(0.2)
    n = len(modem.sent)
    alice.route_to_bot = None
    alice.send_req(0x12345678, path=b"\x99")
    await asyncio.sleep(0.5)
    paths = [r for r in alice.responses if r[1] == m.ROUTE_FLOOD and r[2] is not None]
    check(paths and paths[-1][2] == b"\x99" and alice.route_to_bot == b"\x99",
          "path discovery answered with a flooded PATH carrying the route the request took")
    data = paths[-1][0] if paths else b""
    lpp = decode_lpp(data[4:])
    check(data[:4] == struct.pack("<I", 0x12345678), "response echoes the request's tag (how the app matches it)")
    check(lpp == {(1, 116): 420}, f"path discovery (base telemetry only): just 4.20 V on channel 1 ({lpp})")
    check(db.db.execute("SELECT 1 FROM messages WHERE direction='rx' AND channel='dm:Alice' "
                        "AND command='telemetry'").fetchone() is not None
          and db.db.execute("SELECT 1 FROM messages WHERE direction='tx' AND channel='dm:Alice' "
                            "AND command='telemetry'").fetchone() is not None,
          "telemetry request and answer logged")

    before = len(alice.responses)
    alice.send_req(0x2222, inv_mask=0x00, direct=True)   # the app's full telemetry request
    await asyncio.sleep(0.5)
    direct_resp = [r for r in alice.responses[before:] if r[2] is None]
    check(direct_resp and direct_resp[0][1] == m.ROUTE_DIRECT and direct_resp[0][0][:4] == struct.pack("<I", 0x2222),
          "telemetry request that arrived direct is answered with a direct RESPONSE")
    lpp = decode_lpp(direct_resp[0][0][4:]) if direct_resp else {}
    check(lpp == {(1, 116): 420, (1, 136): (49.2827, -123.1207, 70.5)},
          f"full telemetry: voltage and --lat/--lon/--alt GPS, all on channel 1 ({lpp})")

    before = len(alice.responses)
    alice.send_req(0x3333, inv_mask=0xFF, path=b"\x99")   # asks for no base telemetry
    await asyncio.sleep(0.5)
    check(len(alice.responses) == before, "request that excludes base telemetry gets no answer")

    alice.send_dm("heartbeaton", ts + 2, direct=True)
    await asyncio.sleep(0.5)
    sub = db.get_sub("Alice")
    check(sub is not None and bytes.fromhex(sub["pubkey"]) == alice_pub and sub["path"] == "99",   # learned from the path discovery above
          "!heartbeaton by DM subscribes her with her proven key and known route")
    db.remove_sub("Alice")

    # --- an existing database (made before positions were kept) gets the new columns
    with tempfile.TemporaryDirectory() as tmp:
        old = os.path.join(tmp, "old.db")
        con = sqlite3.connect(old)
        con.execute("CREATE TABLE nodes (pubkey TEXT PRIMARY KEY, name TEXT, adv_type INTEGER, "
                    "first_seen REAL, last_seen REAL)")
        con.execute("INSERT INTO nodes VALUES ('aa', 'Old', 2, 1, 1)")
        con.commit()
        con.close()
        olddb = m.BotDB(old)
        cols = {r["name"] for r in olddb.db.execute("PRAGMA table_info(nodes)")}
        check({"lat", "lon"} <= cols and olddb.repeater_location(b"\xaa") is None,
              "existing database upgraded with position columns, old rows kept")
        olddb.db.close()

    # --- everything was logged
    rx, senders, tx = db.summary()
    check(rx > 0 and tx > 0, f"message log populated (rx={rx}, senders={senders}, tx={tx})")

    run.cancel()


if __name__ == "__main__":
    asyncio.run(main())
    print("\nALL TESTS PASSED")
