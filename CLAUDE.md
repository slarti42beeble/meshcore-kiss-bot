# meshcore-kiss-bot — project context

Single-file Python bot (`meshcore_kiss_bot.py`) for a **MeshCore** LoRa node flashed with the
**KISS Modem** firmware. It sits on a pre-agreed **hashtag channel** (e.g. `#bot`), answers `!`
commands, logs everything to SQLite, and can send opt-in **direct** heartbeat messages to
individual users. This file is the hand-off from the claude.ai conversation where it was built.
The owner is new to GitHub and git, so explain git steps plainly.

## Run / test

```
pip install -r requirements.txt
python3 meshcore_kiss_bot.py --serial /dev/ttyACM0 --channel "#bot" --name MeshBot \
    --freq 910.525 --bw 62.5 --sf 7 --cr 5 --power 22 --db meshbot_messages.db --log-file meshbot.log
python3 test_simulated_modem.py      # end-to-end test against a fake modem, no radio needed
```

Radio options (`--freq --bw --sf --cr --power`) are all required and must match the target mesh.
Add `-v` for debug logging with raw packet hex. Dependencies: `pyserial`, `cryptography`, `tzdata`
(Windows has no system time zone database). Times shown to users and the `messages.iso` column use
`--timezone` (default `America/Los_Angeles`, owner's choice); `messages.ts` stays unix time. Rows
logged before this change have UTC `iso` values ending in `Z`.

## Status — read this first

- **Never run against real hardware.** The author's own tests are the simulated-modem test, which
  only proves the code is self-consistent, not that real firmware agrees with it.
- The packet layouts below were written from the MeshCore docs and recollection. If something
  fails on a real radio, suspect the layouts first (run with `-v` and compare raw hex).
- Heartbeats (direct messages) are the riskiest part; channel commands are the simplest.

## Architecture (all in `meshcore_kiss_bot.py`)

- **KISS layer**: `kiss_encode`, `KissDecoder`. SetHardware (0x06) sub-commands for radio config,
  identity, signing and key exchange (spec: https://docs.meshcore.io/kiss_modem_protocol/).
- **Startup**: `run_once()` opens serial, calls `configure_radio()` (SetRadio, SetTxPower,
  GetRadio, then verifies), reads the modem's Ed25519 public key (GetIdentity), then starts tasks.
  Radio settings are NOT persisted by the firmware, so they are re-sent on every (re)connect.
  `run()` reconnects with backoff.
- **Tasks**: `serial_reader` (owns the port; RX), `tx_worker` (single TX queue), `heartbeat`,
  `advert_task`. Before `serial_reader` starts, `send_hw_command` reads the port directly; after,
  `hw_request` has the reader hand responses back through a future (`hw_waiter`).
- **TX rule**: the modem accepts ONE pending packet at a time (a second gets Error/TxBusy), so
  everything goes through `tx_queue` and waits for the TxDone event (20 s timeout).
- **RX meta**: RxMeta (SNR x4, RSSI) arrives AFTER the Data frame it describes, so the reader
  holds each packet until its RxMeta (or the next frame / a read timeout) arrives.
- **Dedupe**: the same packet arrives via many repeaters; `seen_before()` hashes the payload.
  Our own transmissions are pre-registered so repeater echoes don't loop back.
- **State**: SQLite (WAL) via `BotDB`: `messages` (full log), `nodes` (name -> pubkey from adverts),
  `hb_subs` (heartbeat subscriptions). Subscriptions survive restarts.

## Protocol facts the code depends on

- **Hashtag channel**: key = first 16 bytes of SHA256(`"#name"`, lowercased); channel hash =
  first byte of SHA256(key). Group text payload = `chan_hash(1) | MAC(2) | AES-128-ECB(ts(4) |
  flags(1) | "Sender: text")`, zero padded. MAC = HMAC-SHA256 over ciphertext, key = secret
  zero-padded to 32 bytes, truncated to 2 bytes.
- **Packet header**: bits 0-1 route (0 transport-flood, 1 flood, 2 direct, 3 transport-direct),
  bits 2-5 payload type (2 TXT_MSG, 4 ADVERT, 5 GRP_TXT). Transport routes carry 4 extra bytes.
  Path-length byte: low 6 bits = hop count, top 2 bits = (hash size - 1) on newer firmware.
- **Direct text**: `dest hash(1) | src hash(1) | MAC(2) | AES(ts | flags | text)`, shared secret
  from X25519 with the recipient's pubkey (the modem computes it: KeyExchange 0x07; the modem's
  private key is never readable). AES key = first 16 bytes of the secret, HMAC key = all 32.
- **ACKs**: expected ACK = first 4 bytes of SHA256(`ts | flags | text | sender pubkey`); flags low
  2 bits = attempt number. A direct message is answered with an ACK packet (type 3, payload = ack;
  extra copies may come as MULTIPART type 10: `(remaining<<4 | 3) | ack`). A flooded one is
  answered with a PATH packet (type 8): `dest hash | src hash | MAC(2) | AES(plb | path |
  extra_type | extra)` where path = route the flood took to reach them (use as-is for direct)
  and extra = the ACK (extra_type 3).
- **Advert**: `pubkey(32) | ts(4) | Ed25519 signature(64) | appdata`, signature over
  `pubkey | ts | appdata`. App flags: low nibble = node type (1 = chat), 0x10 lat/lon, 0x20/0x40
  feature words, 0x80 name present.
- Max KISS data payload is 255 bytes; text replies are capped at 150 bytes (`MAX_TEXT_BYTES`).

## Behaviour decisions made with the owner (don't silently change)

- Heartbeats are **off by default**, per user, **direct (not flooded)**.
  `!heartbeaton` / `!heartbeatoff` / `!heartbeat` (status). Max **24 h** per request
  (`--heartbeat-hours`); re-sending `!heartbeaton` restarts the 24 h, it does not stack. On expiry
  the bot sends one final direct message, then removes the subscription.
- Heartbeats follow the **reverse of the path the user's latest channel message took**; the path
  is refreshed every time they speak in the channel.
- **ACK + flood fallback** (like companion clients): every DM is tracked until ACKed. No ACK on a
  direct route -> route forgotten (`hb_subs.plb = -1`), message resent once by flood (same ts,
  attempt+1). The flood's PATH reply supplies a new route. While no route is known heartbeats
  are flooded; an unACKed flood is not retried. ACK wait mirrors companion firmware timeouts
  (airtime-based), overridable with `--ack-timeout`. Tx rows get status acked / no_ack / acked_late.
- The bot learns user public keys only from **signed adverts it overhears**; if none is known for
  the sender's name it asks them to send an advert. It also broadcasts its own signed advert at
  startup, every `--advert-interval` hours, and when someone enables heartbeats (users generally
  need the bot as a contact to see its DMs).
- Airtime protection: per-sender cooldown, global replies/min, `--max-heartbeat-subs` (default 5),
  jitter delay before replies, `MAX_QUEUED_TX` cap, advert minimum gap.
- Message logging is a core requirement: every rx and tx row is stored, including heartbeats
  (`channel='dm:<name>'`) and adverts (`channel='advert'`).

## Known limitations / ideas

- Channel sender names are **not authenticated**: anyone can enable heartbeats under another
  user's name. If two nodes advertise the same name the bot refuses.
- A user who stays out of range gets a **flooded** heartbeat every interval (mesh-wide airtime)
  until they return or their 24 h runs out; no backoff yet.
- Reciprocal path: before the first direct message on a route (and again whenever that route
  changes or a DM goes unACKed), the bot sends the user a direct PATH packet giving the route
  to itself (the stored from-them-to-us path), so their ACKs come back direct instead of
  flooding. Tracked in memory (`route_shared`), so it is re-sent once after a restart. It
  assumes links work both ways; on a one-way route their direct ACKs will be lost.
- Adverts with unusual app-data layouts may fail parsing; failed signatures are ignored by design.
- The owner's older script `meshcore_bridge.py` (not in this repo) pairs RxMeta SNR/RSSI with the
  *previous* packet; the correct pairing is implemented here in `serial_reader`.
- Planned by the owner: more commands/features later. Add commands as entries in `self.commands`
  (handler receives a ctx dict and returns reply text).

## Git / publishing notes

- `.gitignore` excludes `*.db` and `*.log`: the database holds other people's messages and node
  keys. Never commit them.
- Repo: https://github.com/slarti42beeble/meshcore-kiss-bot (default branch `main`). The licence
  is `LICENSE.md` (MIT, filled in).
- Commits use the GitHub noreply email (set in this repo's local git config) so the owner's real
  address isn't published.
