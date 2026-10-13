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

- **Running on real hardware since 2026-10.** The owner runs it on Windows with a KISS-modem node
  on a live mesh that uses region transport codes (TRANSPORT_FLOOD from companion apps) and
  3-byte path hashes. Confirmed working there (2026-10-10, from `-v` logs and the live database):
  - radio config, identity and signed adverts (repeaters re-flood them);
  - hashtag channel commands and replies;
  - direct heartbeats to subscribers, ACKed by their nodes (`status='acked'`);
  - DMs to the bot: received, decrypted, ACKed (the sender's app marks them delivered), and the
    bot's replies ACKed by the sender; reciprocal PATH packets sent;
  - companion app "path discovery" (2026-10-11): the flooded telemetry request is answered and
    the app shows the route to the bot;
  - full telemetry requests (2026-10-11): the app shows Voltage 4.200 V / 100 % and the
    `--lat/--lon/--alt` GPS position, with no channel headings, like a real companion node;
  - `!wx` (2026-10-12): live Open-Meteo fetch and reply on the radio;
  - new `!ping` format (2026-10-12), seen at 0 hops (the owner is next to the bot). Multi-hop
    paths, 3-byte IDs in the reply, distance and shortening are so far only simulated;
  - `!8ball` (2026-10-12). The `(1/2)`/`(2/2)` reply split hasn't triggered on air yet (help
    still fits in one message with the name `MeshBot`).
- **Not yet seen on air:** the no-ACK path (flood fallback, route learning from PATH replies,
  flood backoff). There has been no `no_ack` row yet, so these are proven only by the
  simulated-modem test, which shows the code is self-consistent, not that firmware agrees.
- Packet layouts were written from the MeshCore docs and recollection. If something fails on a
  real radio, suspect the layouts first (run with `-v` and compare raw hex).
- The owner runs a *copy* of the script from another folder. If a real-radio bug looks like
  missing code, first check that copy matches `main`.

## Architecture (all in `meshcore_kiss_bot.py`)

- **KISS layer**: `kiss_encode`, `KissDecoder`. SetHardware (0x06) sub-commands for radio config,
  identity, signing and key exchange (spec: https://docs.meshcore.io/kiss_modem_protocol/).
- **Startup**: `run_once()` opens serial, calls `configure_radio()` (SetRadio, SetTxPower,
  GetRadio, then verifies), reads the modem's Ed25519 public key (GetIdentity), then starts tasks.
  Radio settings are NOT persisted by the firmware, so they are re-sent on every (re)connect.
  `run()` reconnects with backoff.
- **Tasks**: `serial_reader` (owns the port; RX), `tx_worker` (single TX queue), `heartbeat`,
  `advert_task`, `ack_monitor`, `dm_worker` (incoming DMs; decrypting needs a modem key exchange,
  so `handle_rx` queues them). Before `serial_reader` starts, `send_hw_command` reads the port directly; after,
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
- **Incoming DM** (TXT_MSG to us): sender candidates = heard chat nodes whose pubkey starts with
  the src hash; the MAC picks the real one. flags >> 2 = text type (only 0, plain, is handled).
  ACK = SHA256(`ts | flags | text | sender pubkey`)[:4]. Flooded DM -> flooded PATH reply
  (route = the DM's path, extra = ACK). Direct DM -> ACK packet, direct if we know a route.
- **Telemetry REQ** (type 0, checked against meshcore-dev/MeshCore companion firmware):
  `dest | src | MAC | AES(tag(4) | 0x03 | inverse perm mask | 3 reserved | 4 random)`. App
  "path discovery" floods one with mask `~0x01` (base only). Answer: tag echoed + CayenneLPP
  (big-endian, all on channel 1 so apps don't show channel headings: voltage type 116 = 0.01 V,
  fixed 4.20 V; GPS type 136 = 3+3+3 bytes signed, lat/lon x10000, alt x100, only when the
  request's mask allows location (0x02) and `--lat/--lon` are set). Flooded REQ -> flooded PATH (route = the REQ's path, extra_type 1 RESPONSE,
  extra = answer); direct REQ -> RESPONSE packet (type 1). The app matches the echoed tag and,
  per the firmware source, currently discards the telemetry itself.
- **Advert**: `pubkey(32) | ts(4) | Ed25519 signature(64) | appdata`, signature over
  `pubkey | ts | appdata`. App flags: low nibble = node type (1 = chat, 2 = repeater), 0x10 lat/lon
  (int32 LE millionths of a degree each, right after the flags; 0,0 = unset; stored in `nodes`), 0x20/0x40
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
- **Commands by DM**: same command table and rate limits as the channel (`run_command`); `!` is
  optional; unknown text gets the `!help` reply. Replies go via `send_direct` (ACK-tracked,
  flood fallback). Retries of a DM (same ts/text, attempt+1) are re-ACKed but answered once.
  `!heartbeaton` by DM uses the sender's proven key. Routes for non-subscribers live in
  memory (`Bot.routes`); subscribers' routes stay in `hb_subs`.
- **Telemetry** (owner's choice: look like a companion's: voltage + optional fixed GPS, no
  uptime/percentage/extra channels; position via `--lat/--lon/--alt`, never committed): answered for any heard node (no per-sender cooldown, global limit applies), no
  jitter so the app's round-trip timer isn't exceeded. Requests that mask out base telemetry
  get no answer, as in the firmware.
- **`!ping`** (owner's format): `pong @name | <hashes> (N hops) | SNR: x dB | RSSI: y dBm |
  <km> (n segs) | <ms> | Rx'd: HH:MM:SS`. Hashes shown as on air (1-3 bytes each; first byte
  only if space is short). km = sum of legs between consecutive path repeaters with a known
  advertised position (repeater = adv_type 2, matched by hash prefix, only if unique); omitted
  if no leg is known. ms = receive time - sender timestamp (omitted if negative or > 1 h).
  Shortening order to fit: 1-byte hashes, drop Rx'd, ms, RSSI. In DMs the route shown is the
  one we hold for them (a direct packet's path is used up on the way).
- **`!8ball`**: random one of the classic 20 answers (`EIGHT_BALL`): `🎱 @name <answer>`.
- **Long replies**: a handler may return a list of messages; `split_reply` splits text that
  won't fit `reply_limit()` (150 bytes minus `"<bot name>: "`) at spaces into `(1/2) ...`,
  `(2/2) ...` (owner's request, for `!help`). With the name `MeshBot`, help still fits in one.
- **`!wx`** (owner's request): fixed to East Sooke, BC (`WX_LAT/WX_LON` = the community, not the
  owner's node). Source: Open-Meteo `gem_seamless` (free, no key; owner was told scraping The
  Weather Network is fragile/against ToS and ECCC has no Sooke city page). Format follows the
  owner's example, metric: `<place>: <Day>: <sky> T°C 💨<dir><km/h>[G<gust>] RH%RH 💧dew° 
  📊hPa | Tonight: <sky> L:low°C 💨wind` (tonight = 18:00 or now -> 06:00: most common code,
  min temp, mean wind). Fits `MAX_TEXT_BYTES` incl. the bot-name prefix; drops dew, hPa, RH
  if needed. Cached 10 min. Slow commands may return a coroutine; `send_later` sends the
  reply when it finishes. Tests stub `Bot.fetch_wx` (CI has no internet).
- Message logging is a core requirement: every rx and tx row is stored, including heartbeats
  (`channel='dm:<name>'`) and adverts (`channel='advert'`).

## Known limitations / ideas

- Channel sender names are **not authenticated**: anyone can enable heartbeats under another
  user's name (DMs are authenticated, so `!heartbeaton` by DM is the safe way). If two nodes advertise the same name the bot refuses.
- **Flood backoff**: while a user has no known route and floods go unACKed, flooded heartbeats
  wait 2x, 4x, 8x... the interval (`flood_delay`), capped at `--flood-backoff-max` minutes
  (default 30). Reset by any ACK from them, a channel message, `!heartbeaton` or `!heartbeatoff`.
  Kept in memory (`flood_backoff`), so a restart starts the backoff over. The expiry notice is
  not held back.
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

## Git workflow (owner's standing instruction — no need to ask at each step)

For every change the owner asks for:
1. `git pull origin main`, then create a short-named branch.
2. Make the change, run `python test_simulated_modem.py`, update README/CLAUDE.md if behaviour changed.
3. Commit, push the branch, open a PR with `gh pr create` (plain-English description).
4. Enable GitHub auto-merge on the PR (merge method `merge`). GitHub merges it once the
   `tests` check (`.github/workflows/tests.yml`) passes. Don't merge by hand around a red check;
   fix the failure on the branch instead. If GitHub refuses auto-merge because the PR is
   already in "clean status" (the check passed first), merge it directly:
   `gh pr merge <n> --merge --delete-branch`.
5. Once merged: `git checkout main`, `git pull`, delete the local branch, and tell the owner
   what changed and the PR link.
Still ask first if the owner says to hold a change, or for anything destructive (force-push,
deleting `main` history, changing repo settings).

## Git / publishing notes

- `.gitignore` excludes `*.db` and `*.log`: the database holds other people's messages and node
  keys. Never commit them.
- Repo: https://github.com/slarti42beeble/meshcore-kiss-bot (default branch `main`). The licence
  is `LICENSE.md` (MIT, filled in).
- Commits use the GitHub noreply email (set in this repo's local git config) so the owner's real
  address isn't published.
