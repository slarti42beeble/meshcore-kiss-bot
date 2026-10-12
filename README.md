# meshcore-kiss-bot

A command bot for a [MeshCore](https://meshcore.io) radio running the **KISS Modem** firmware.
It listens on a hashtag channel (for example `#bot`), answers `!` commands, keeps a searchable
log of everything it hears, and can send opt-in, per-user "heartbeat" direct messages.

Because hashtag channel keys are derived from the channel name, people do **not** need to be
contacts to use the channel commands.

## Features

- Configures the modem's radio settings (frequency, bandwidth, SF, CR, TX power) from the command
  line on every connect, since the KISS modem firmware does not remember them across reboots.
- `!wx`: current East Sooke, BC weather plus tonight's outlook in one message (metric), e.g.
  `East Sooke, BC: Mon: ☀️Clear 13°C 💨SW6 55%RH 💧4° 📊1018hPa | Tonight: ☁️Overcast L:6°C 💨W4`.
  Wind is km/h. Data from [Open-Meteo](https://open-meteo.com) (Environment Canada's GEM
  models, CC BY 4.0); needs internet access, and one fetch is reused for 10 minutes.
- Command bot on a hashtag channel: `!ping` (with hop count, SNR, RSSI), `!time`, `!uptime`,
  `!stats`, `!echo <text>`, `!help`.
- The same commands also work by **direct message** to the bot (the `!` is optional there),
  once the bot has heard the sender's advert. Replies come back as direct messages; the bot
  ACKs incoming DMs like any MeshCore node, so the sender's app shows them as delivered.
- Answers **telemetry requests** like a companion node, so a companion app's **path discovery**
  works on the bot. It reports a full battery (4.20 V, shown as 100 %) and, if you give
  `--lat`/`--lon` (and optionally `--alt` in metres), a fixed GPS position. The position is a
  command-line option so it never ends up in the code or on GitHub.
- Opt-in direct heartbeats per user: `!heartbeaton`, `!heartbeatoff`, `!heartbeat` (status).
  Limited to 24 hours per request, renewable. Subscriptions survive restarts.
- Everything heard and sent is logged to SQLite (timestamp, sender, text, hops, repeater path,
  SNR/RSSI, command matched), plus an optional rotating text log.
- Per-sender cooldown and a global reply cap to protect airtime.
- Automatic reconnect to the modem, re-applying radio settings each time.
- Times (`!time`, heartbeats, the log's `iso` column) are in Pacific time by default; change with
  `--timezone` (any IANA name, e.g. `America/Denver`). Windows needs the `tzdata` package
  (included in `requirements.txt`).

## Requirements

- A MeshCore node flashed with the **KISS Radio Modem** firmware (see the MeshCore flasher)
- Python 3.9+
- `pip install -r requirements.txt`

## Usage

```
python3 meshcore_kiss_bot.py --serial /dev/ttyACM0 --channel "#bot" --name MeshBot \
    --freq 910.525 --bw 62.5 --sf 7 --cr 5 --power 22 \
    --db meshbot_messages.db --log-file meshbot.log
```

The radio settings must match the mesh you want to talk to (use "get radio" on an existing
node to check). On Windows the serial port looks like `COM3`.
Run `python3 meshcore_kiss_bot.py --help` for all options.

## Heartbeats: how they work

Heartbeats are **not** posted to the channel. Each one is a direct, end-to-end encrypted
message sent along the reverse of the repeater path the user's last channel message took.

- The bot needs the user's public key. It learns keys by listening for signed adverts on the
  air; if it hasn't heard one for the sender's name it asks them to send an advert.
- The user's node generally needs the bot as a **contact** to display its direct messages, so
  the bot sends its own advert at startup, periodically, and when someone enables heartbeats.
- Every direct message waits for the recipient's ACK. If none arrives (out of range, or a
  repeater on the path has gone away), the bot does what the MeshCore companion apps do: it
  forgets that route and resends the message once by **flood**. The recipient answers a flood
  with the route it took, which becomes the new direct route. Until a route is learned again,
  heartbeats are flooded, backing off while nobody answers: the next flood waits 2x, then 4x,
  8x... the heartbeat interval, up to `--flood-backoff-max` minutes (default 30). Hearing from
  them again (an ACK, a channel message or `!heartbeaton`) resets it. The bot also sends each user's node the route back to the bot
  (a reciprocal path), so their ACKs come back direct instead of being flooded. The ACK wait is estimated from airtime; override it with
  `--ack-timeout` if you see many `acked_late` rows in the log.
- The sender name in a channel message is not authenticated, so someone could enable heartbeats
  under another user's name. Slots are capped (`--max-heartbeat-subs`) to limit the impact.

## Querying the log

```
sqlite3 -header -column meshbot_messages.db \
  "select iso, direction, channel, sender, hops, snr, text from messages order by id desc limit 20"
```

## Notes

- **Regulations:** you are responsible for complying with local rules on frequency, power and
  duty cycle. Heartbeats and adverts are airtime; tune the intervals accordingly.
- **Privacy:** hashtag channels are encrypted on air, but anyone who knows the channel name can
  derive the key and read the channel. The database contains other people's messages, so keep
  it private (it is excluded by `.gitignore`).
- **Status:** written against the [MeshCore KISS modem protocol](https://docs.meshcore.io/kiss_modem_protocol/)
  and packet format docs. Packet layouts follow the published documentation; report anything
  that differs on your firmware version by opening an issue.

## License

MIT, see `LICENSE.md`.
