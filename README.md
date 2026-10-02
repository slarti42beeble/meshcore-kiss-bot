# meshcore-kiss-bot

A command bot for a [MeshCore](https://meshcore.io) radio running the **KISS Modem** firmware.
It listens on a hashtag channel (for example `#bot`), answers `!` commands, keeps a searchable
log of everything it hears, and can send opt-in, per-user "heartbeat" direct messages.

Because hashtag channel keys are derived from the channel name, people do **not** need to be
contacts to use the channel commands.

## Features

- Configures the modem's radio settings (frequency, bandwidth, SF, CR, TX power) from the command
  line on every connect, since the KISS modem firmware does not remember them across reboots.
- Command bot on a hashtag channel: `!ping` (with hop count, SNR, RSSI), `!time`, `!uptime`,
  `!stats`, `!echo <text>`, `!help`.
- Opt-in direct heartbeats per user: `!heartbeaton`, `!heartbeatoff`, `!heartbeat` (status).
  Limited to 24 hours per request, renewable. Subscriptions survive restarts.
- Everything heard and sent is logged to SQLite (timestamp, sender, text, hops, repeater path,
  SNR/RSSI, command matched), plus an optional rotating text log.
- Per-sender cooldown and a global reply cap to protect airtime.
- Automatic reconnect to the modem, re-applying radio settings each time.

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
- Delivery is best-effort. The bot does not process ACKs or retry.
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

MIT, see `LICENSE`.
