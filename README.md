# LXC VPS Discord Bot

This bot creates Ubuntu LXC containers on the Linux VPS where the bot is running.

Commands:
- `.create <vps-name> <ram-gb> <cpu-vcore> <disk-gb> <valid-days> @owner`
- `.all-vps`
- `.delete <vps-name>`
- `.help`

The VPS uses the main host's public IPv4 and a unique SSH port per container.

## 1. Host requirements

Run on the Linux host/VPS that has LXD:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip iptables iptables-persistent openssh-client
```

Make sure LXD works:

```bash
lxc list
```

Enable IPv4 forwarding:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-lxc-vps.conf
sudo sysctl --system
```

If UFW or another firewall is active, make sure the selected SSH port range and LXD forwarding are allowed. Do not blindly disable a firewall on a production server.

## 2. Install the bot

Copy the project to the host, then:

```bash
cd lxc-vps-discord-bot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
nano .env
```

Set:
- `DISCORD_TOKEN`: your bot token
- `ADMIN_IDS`: two Discord user IDs separated by a comma, for example `123456789012345678,987654321098765432`. Both users can use admin commands.
- `PUBLIC_IP`: the main VPS public IPv4
- other values as needed

## 3. Discord bot settings

In the Discord Developer Portal:
- Create the bot.
- Enable the Message Content Intent.
- Enable Server Members Intent.
- Invite it with bot + applications.commands scopes.
- Give it permission to send messages, embed links, read message history, and DM users.
- The bot's Linux process must run as root (or otherwise have permission to run LXD and iptables).

## 4. Start

```bash
source venv/bin/activate
sudo -E venv/bin/python main.py
```

For production, use the systemd example below.

## 5. Test

```text
.create test1 2 2 20 7 @YourUser
```

Then the bot should create the LXC container, assign a port, configure NAT, and DM the owner.

SSH:

```text
ssh root@YOUR_PUBLIC_IP -p YOUR_ASSIGNED_PORT
```

## 6. systemd

Create `/etc/systemd/system/lxc-vps-bot.service`:

```ini
[Unit]
Description=LXC VPS Discord Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/lxc-vps-discord-bot
ExecStart=/opt/lxc-vps-discord-bot/venv/bin/python /opt/lxc-vps-discord-bot/main.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lxc-vps-bot
sudo systemctl status lxc-vps-bot
```

Logs:

```bash
sudo journalctl -u lxc-vps-bot -f
```

## Important

- Back up `vps.db` and your firewall rules.
- The bot stores root passwords in `vps.db`; protect that file.
- This implementation exposes SSH through the main VPS IP on unique ports.
- The public IP is shared; each VPS has its own private LXD address.
- Existing containers are not modified by `.create` or `.delete` unless they have the same name supplied to `.create`.
- `.delete` is permanent for that LXC container. Use it carefully.
