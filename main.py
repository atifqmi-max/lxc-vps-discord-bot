import asyncio
import ipaddress
import os
import secrets
import sqlite3
import string
import subprocess
from datetime import datetime, timedelta, timezone

import discord
from discord.ext import commands, tasks
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN", "")
ADMIN_IDS = {
    int(x.strip()) for x in os.getenv("ADMIN_IDS", "").split(",")
    if x.strip().isdigit()
}
PUBLIC_IP = os.getenv("PUBLIC_IP", "").strip()
LXC_IMAGE = os.getenv("LXC_IMAGE", "images:ubuntu/24.04").strip()
PORT_START = int(os.getenv("PORT_START", "2200"))
PORT_END = int(os.getenv("PORT_END", "2999"))
DB_PATH = os.getenv("DB_PATH", "vps.db")
EXPIRY_CHECK_SECONDS = int(os.getenv("EXPIRY_CHECK_SECONDS", "60"))

if not TOKEN:
    raise SystemExit("DISCORD_TOKEN is missing in .env")
try:
    ipaddress.ip_address(PUBLIC_IP)
except ValueError:
    raise SystemExit("PUBLIC_IP is missing or invalid in .env")
if PORT_START < 1 or PORT_END > 65535 or PORT_START > PORT_END:
    raise SystemExit("Invalid PORT_START/PORT_END")

intents = discord.Intents.default()
intents.message_content = True
intents.members = True
bot = commands.Bot(command_prefix=".", intents=intents, help_command=None)

DB = sqlite3.connect(DB_PATH, check_same_thread=False)
DB.row_factory = sqlite3.Row
DB.execute("""
CREATE TABLE IF NOT EXISTS vps (
    name TEXT PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    owner_tag TEXT NOT NULL,
    ram_gb INTEGER NOT NULL,
    cpu_vcores INTEGER NOT NULL,
    disk_gb INTEGER NOT NULL,
    valid_days INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    ssh_port INTEGER NOT NULL UNIQUE,
    container_ip TEXT NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT NOT NULL
)
""")
DB.commit()

def run_cmd(args, check=True):
    """Run a system command without a shell."""
    return subprocess.run(
        args,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

def lxc(*args, check=True):
    return run_cmd(["lxc", *args], check=check)

def iptables(*args):
    return run_cmd(["iptables", *args])

def container_exists(name):
    p = lxc("info", name, check=False)
    return p.returncode == 0

def get_container_ip(name):
    p = lxc("list", name, "--format", "csv", "-c", "4", check=False)
    if p.returncode != 0:
        return None
    # CSV output may contain more than one address; select IPv4.
    for part in p.stdout.replace("\n", ",").split(","):
        part = part.strip()
        try:
            ip = ipaddress.ip_address(part)
            if ip.version == 4:
                return part
        except ValueError:
            pass
    return None

def random_password(length=18):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(chars) for _ in range(length))

def valid_name(name):
    if not 1 <= len(name) <= 32:
        return False
    return all(c.isalnum() or c in "-_" for c in name)

def used_ports():
    rows = DB.execute("SELECT ssh_port FROM vps").fetchall()
    return {row["ssh_port"] for row in rows}

def allocate_port():
    used = used_ports()
    for port in range(PORT_START, PORT_END + 1):
        if port not in used:
            # Check whether something is already listening on the host.
            p = subprocess.run(
                ["ss", "-ltnH", f"sport = :{port}"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            if not p.stdout.strip():
                return port
    raise RuntimeError("No free SSH ports remain in configured range.")

def add_port_forward(port, container_ip):
    # Main VPS public IP:port -> container private IP:22
    iptables(
        "-t", "nat", "-A", "PREROUTING",
        "-p", "tcp", "-d", PUBLIC_IP, "--dport", str(port),
        "-j", "DNAT", "--to-destination", f"{container_ip}:22"
    )
    iptables(
        "-A", "FORWARD",
        "-p", "tcp", "-d", container_ip, "--dport", "22",
        "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED",
        "-j", "ACCEPT"
    )
    iptables(
        "-A", "FORWARD",
        "-p", "tcp", "-s", container_ip, "--sport", "22",
        "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
        "-j", "ACCEPT"
    )

def remove_port_forward(port, container_ip):
    # Delete exact rules; ignore failure so deletion can continue.
    for args in [
        ["-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-d", PUBLIC_IP,
         "--dport", str(port), "-j", "DNAT", "--to-destination", f"{container_ip}:22"],
        ["-D", "FORWARD", "-p", "tcp", "-d", container_ip, "--dport", "22",
         "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["-D", "FORWARD", "-p", "tcp", "-s", container_ip, "--sport", "22",
         "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ]:
        iptables(*args, check=False)

def save_iptables():
    # If iptables-persistent is installed, save current rules.
    p = subprocess.run(
        ["sh", "-c", "command -v netfilter-persistent >/dev/null 2>&1"],
        check=False,
    )
    if p.returncode == 0:
        subprocess.run(["netfilter-persistent", "save"], check=False)

async def create_vps(name, ram, cpu, disk, days, owner):
    if not valid_name(name):
        raise ValueError("VPS name must be 1-32 chars and contain only letters, numbers, - or _.")

    if DB.execute("SELECT 1 FROM vps WHERE name=?", (name,)).fetchone():
        raise ValueError("A VPS with that name already exists.")

    if container_exists(name):
        raise ValueError("An LXC container with that name already exists.")

    port = allocate_port()
    password = random_password()

    # Create LXC container.
    lxc("launch", LXC_IMAGE, name)

    try:
        # Apply resource limits.
        lxc("config", "set", name, "limits.memory", f"{ram}GiB")
        lxc("config", "set", name, "limits.cpu", str(cpu))
        lxc("config", "device", "override", name, "root", f"size={disk}GiB")

        # Give root a random password and install SSH server.
        # Commands run inside the container; arguments are not shell-interpolated
        # except for the password command passed through bash -c.
        script = (
            "export DEBIAN_FRONTEND=noninteractive; "
            "apt-get update -y >/dev/null 2>&1 && "
            "apt-get install -y openssh-server sudo curl wget neofetch >/dev/null 2>&1; "
            "mkdir -p /run/sshd; "
            "echo 'root:" + password.replace("'", "'\"'\"'") + "' | chpasswd; "
            "sed -i 's/^#\\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config; "
            "sed -i 's/^#\\?PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config; "
            "systemctl enable --now ssh >/dev/null 2>&1 || service ssh restart >/dev/null 2>&1 || true"
        )
        lxc("exec", name, "--", "bash", "-lc", script)

        # Wait for an IPv4 address.
        ip = None
        for _ in range(30):
            ip = get_container_ip(name)
            if ip:
                break
            await asyncio.sleep(1)
        if not ip:
            raise RuntimeError("Container was created but no IPv4 address appeared.")

        add_port_forward(port, ip)
        save_iptables()

        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=days)

        DB.execute(
            """INSERT INTO vps
            (name, owner_id, owner_tag, ram_gb, cpu_vcores, disk_gb, valid_days,
             expires_at, ssh_port, container_ip, password, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                name, owner.id, str(owner), ram, cpu, disk, days,
                expires.isoformat(), port, ip, password, now.isoformat()
            ),
        )
        DB.commit()
        return {
            "name": name, "ram": ram, "cpu": cpu, "disk": disk, "days": days,
            "expires": expires, "port": port, "ip": ip, "password": password,
            "owner": owner,
        }
    except Exception:
        # Best-effort cleanup if creation fails.
        ip = get_container_ip(name)
        if ip:
            remove_port_forward(port, ip)
        lxc("delete", name, "--force", check=False)
        save_iptables()
        raise

async def delete_vps(name):
    row = DB.execute("SELECT * FROM vps WHERE name=?", (name,)).fetchone()
    if not row:
        raise ValueError("VPS not found in the bot database.")

    remove_port_forward(row["ssh_port"], row["container_ip"])
    lxc("delete", name, "--force", check=False)
    DB.execute("DELETE FROM vps WHERE name=?", (name,))
    DB.commit()
    save_iptables()
    return row

async def send_vps_dm(data):
    owner = bot.get_user(data["owner"].id) or data["owner"]
    embed = discord.Embed(title="🖥️ Your VPS is Ready", color=discord.Color.green())
    embed.add_field(name="VPS Name", value=f"`{data['name']}`", inline=False)
    embed.add_field(name="IP", value=f"`{PUBLIC_IP}`", inline=True)
    embed.add_field(name="SSH Port", value=f"`{data['port']}`", inline=True)
    embed.add_field(name="RAM", value=f"`{data['ram']} GB`", inline=True)
    embed.add_field(name="CPU", value=f"`{data['cpu']} vCore`", inline=True)
    embed.add_field(name="Disk", value=f"`{data['disk']} GB`", inline=True)
    embed.add_field(name="Valid Until", value=f"`{discord.utils.format_dt(data['expires'], 'F')}`", inline=False)
    embed.add_field(name="SSH Command", value=f"`ssh root@{PUBLIC_IP} -p {data['port']}`", inline=False)
    embed.add_field(name="Root Password", value=f"||`{data['password']}`||", inline=False)
    embed.set_footer(text="Keep your VPS password private.")
    await owner.send(embed=embed)

def is_admin(ctx):
    return ctx.author.id in ADMIN_IDS or (
        isinstance(ctx.author, discord.Member) and ctx.author.guild_permissions.administrator
    )

@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} ({bot.user.id})")
    if not expiry_loop.is_running():
        expiry_loop.start()

@bot.command(name="create")
async def create_command(ctx, name: str, ram: int, cpu: int, disk: int, days: int, owner: discord.Member):
    if not is_admin(ctx):
        return await ctx.reply("❌ You do not have permission to create VPSs.")
    if ram < 1 or ram > 512 or cpu < 1 or cpu > 128 or disk < 1 or disk > 4096 or days < 1 or days > 3650:
        return await ctx.reply("❌ Invalid resource values.")

    msg = await ctx.reply("⏳ Creating the VPS... Please wait.")
    try:
        data = await create_vps(name, ram, cpu, disk, days, owner)
        try:
            await send_vps_dm(data)
            dm_status = "✅ VPS details sent to the owner by DM."
        except discord.Forbidden:
            dm_status = "⚠️ VPS created, but I could not DM the owner (DMs may be disabled)."

        await msg.edit(content=(
            f"✅ **VPS created:** `{name}`\n"
            f"👤 Owner: {owner.mention}\n"
            f"🌐 IP: `{PUBLIC_IP}`\n"
            f"🔌 SSH Port: `{data['port']}`\n"
            f"🧠 RAM: `{ram}GB` | ⚡ CPU: `{cpu}` vCore | 💾 Disk: `{disk}GB`\n"
            f"📅 Valid for: `{days}` days\n{dm_status}"
        ))
    except Exception as e:
        await msg.edit(content=f"❌ VPS creation failed: `{str(e)[:1500]}`")

@bot.command(name="all-vps")
async def all_vps(ctx):
    if not is_admin(ctx):
        return await ctx.reply("❌ Admin only.")
    rows = DB.execute("SELECT * FROM vps ORDER BY created_at").fetchall()
    if not rows:
        return await ctx.reply("📭 No VPSs found.")

    lines = []
    for r in rows:
        owner = bot.get_user(r["owner_id"])
        owner_text = owner.mention if owner else f"<@{r['owner_id']}>"
        expires = datetime.fromisoformat(r["expires_at"])
        lines.append(
            f"**{r['name']}** — {owner_text}\n"
            f"`{PUBLIC_IP}:{r['ssh_port']}` | {r['ram_gb']}GB RAM | "
            f"{r['cpu_vcores']} vCPU | {r['disk_gb']}GB | "
            f"expires {discord.utils.format_dt(expires, 'R')}"
        )

    # Discord message limit protection.
    chunks, current = [], ""
    for line in lines:
        if len(current) + len(line) + 2 > 3900:
            chunks.append(current)
            current = ""
        current += line + "\n\n"
    if current:
        chunks.append(current)

    for i, chunk in enumerate(chunks):
        embed = discord.Embed(
            title="🖥️ All VPS" + (f" ({i+1}/{len(chunks)})" if len(chunks) > 1 else ""),
            description=chunk,
            color=discord.Color.blurple(),
        )
        await ctx.send(embed=embed)

@bot.command(name="delete")
async def delete_command(ctx, name: str):
    if not is_admin(ctx):
        return await ctx.reply("❌ Admin only.")
    try:
        row = await delete_vps(name)
        owner = bot.get_user(row["owner_id"])
        if owner:
            try:
                await owner.send(
                    f"🗑️ Your VPS **`{name}`** has been deleted by an administrator."
                )
            except discord.Forbidden:
                pass
        await ctx.reply(f"✅ VPS `{name}` deleted.")
    except Exception as e:
        await ctx.reply(f"❌ Delete failed: `{str(e)[:1500]}`")

@bot.command(name="help")
async def help_command(ctx):
    embed = discord.Embed(title="🤖 VPS Bot Commands", color=discord.Color.blurple())
    embed.add_field(
        name=".create",
        value="`.create <name> <ramGB> <cpuVcore> <diskGB> <validDays> @owner`\n"
              "Example: `.create test1 4 2 30 30 @User`",
        inline=False,
    )
    embed.add_field(
        name=".all-vps",
        value="Admin command — shows all VPSs, owners, resources, ports and expiry.",
        inline=False,
    )
    embed.add_field(
        name=".delete",
        value="`.delete <vps-name>`\nAdmin command — deletes the VPS and notifies its owner.",
        inline=False,
    )
    embed.add_field(
        name=".help",
        value="Shows this help menu.",
        inline=False,
    )
    await ctx.reply(embed=embed)

@tasks.loop(seconds=EXPIRY_CHECK_SECONDS)
async def expiry_loop():
    await bot.wait_until_ready()
    now = datetime.now(timezone.utc)
    rows = DB.execute("SELECT * FROM vps WHERE expires_at <= ?", (now.isoformat(),)).fetchall()
    for row in rows:
        try:
            deleted = await delete_vps(row["name"])
            owner = bot.get_user(deleted["owner_id"])
            if owner:
                try:
                    await owner.send(
                        f"⏰ Your VPS **`{deleted['name']}`** expired and has been automatically deleted."
                    )
                except discord.Forbidden:
                    pass
        except Exception as e:
            print(f"Expiry deletion failed for {row['name']}: {e}")

@expiry_loop.before_loop
async def before_expiry_loop():
    await bot.wait_until_ready()

bot.run(TOKEN)
