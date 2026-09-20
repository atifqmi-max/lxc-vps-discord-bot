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

# =========================================================
# CONFIG
# =========================================================

TOKEN = os.getenv("DISCORD_TOKEN", "").strip()

ADMIN_IDS = {
    int(x.strip())
    for x in os.getenv("ADMIN_IDS", "").split(",")
    if x.strip().isdigit()
}

PUBLIC_IP = os.getenv("PUBLIC_IP", "").strip()

# We will try these images automatically.
LXC_IMAGES = [
    os.getenv("LXC_IMAGE", "ubuntu:24.04").strip(),
    "images:ubuntu/24.04",
]

PORT_START = int(os.getenv("PORT_START", "2200"))
PORT_END = int(os.getenv("PORT_END", "2999"))

DB_PATH = os.getenv("DB_PATH", "vps.db")

EXPIRY_CHECK_SECONDS = int(
    os.getenv("EXPIRY_CHECK_SECONDS", "60")
)

# =========================================================
# BASIC CHECKS
# =========================================================

if not TOKEN:
    raise SystemExit("ERROR: DISCORD_TOKEN is missing in .env")

try:
    ipaddress.ip_address(PUBLIC_IP)
except ValueError:
    raise SystemExit("ERROR: PUBLIC_IP is missing or invalid in .env")

if PORT_START < 1 or PORT_END > 65535 or PORT_START > PORT_END:
    raise SystemExit("ERROR: Invalid PORT_START / PORT_END")

# =========================================================
# DISCORD
# =========================================================

intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(
    command_prefix=".",
    intents=intents,
    help_command=None
)

# =========================================================
# DATABASE
# =========================================================

DB = sqlite3.connect(
    DB_PATH,
    check_same_thread=False
)

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

# =========================================================
# COMMAND RUNNER
# =========================================================

def run_cmd(args, check=True):
    """
    Runs a command and returns stdout/stderr.
    Actual errors are included so Discord can show what failed.
    """

    result = subprocess.run(
        args,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    if check and result.returncode != 0:
        error = result.stderr.strip()

        if not error:
            error = result.stdout.strip()

        raise RuntimeError(
            f"Command failed ({result.returncode}): "
            f"{' '.join(args)}\n{error}"
        )

    return result


def lxc(*args, check=True):
    return run_cmd(
        ["lxc", *args],
        check=check
    )


def iptables(*args, check=True):
    return run_cmd(
        ["iptables", *args],
        check=check
    )

# =========================================================
# HELPERS
# =========================================================

def container_exists(name):
    result = lxc(
        "info",
        name,
        check=False
    )

    return result.returncode == 0


def get_container_ip(name):
    result = lxc(
        "list",
        name,
        "--format",
        "csv",
        "-c",
        "4",
        check=False
    )

    if result.returncode != 0:
        return None

    text = result.stdout.replace("\n", ",")

    for part in text.split(","):

        part = part.strip()

        try:
            ip = ipaddress.ip_address(part)

            if ip.version == 4:
                return part

        except ValueError:
            continue

    return None


def random_password(length=20):

    chars = (
        string.ascii_letters
        + string.digits
        + "!@#$%^&*"
    )

    return "".join(
        secrets.choice(chars)
        for _ in range(length)
    )


def valid_name(name):

    if not 1 <= len(name) <= 32:
        return False

    return all(
        c.isalnum() or c in "-_"
        for c in name
    )


def used_ports():

    rows = DB.execute(
        "SELECT ssh_port FROM vps"
    ).fetchall()

    return {
        row["ssh_port"]
        for row in rows
    }


def allocate_port():

    used = used_ports()

    for port in range(
        PORT_START,
        PORT_END + 1
    ):

        if port in used:
            continue

        result = subprocess.run(
            [
                "ss",
                "-ltnH",
                f"sport = :{port}"
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )

        if not result.stdout.strip():
            return port

    raise RuntimeError(
        "No free SSH ports available."
    )


# =========================================================
# IPTABLES
# =========================================================

def add_port_forward(
    port,
    container_ip
):

    # Public IP:PORT
    #       ↓
    # Container IP:22

    iptables(
        "-t",
        "nat",
        "-A",
        "PREROUTING",
        "-p",
        "tcp",
        "-d",
        PUBLIC_IP,
        "--dport",
        str(port),
        "-j",
        "DNAT",
        "--to-destination",
        f"{container_ip}:22"
    )

    iptables(
        "-A",
        "FORWARD",
        "-p",
        "tcp",
        "-d",
        container_ip,
        "--dport",
        "22",
        "-m",
        "conntrack",
        "--ctstate",
        "NEW,ESTABLISHED,RELATED",
        "-j",
        "ACCEPT"
    )

    iptables(
        "-A",
        "FORWARD",
        "-p",
        "tcp",
        "-s",
        container_ip,
        "--sport",
        "22",
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT"
    )


def remove_port_forward(
    port,
    container_ip
):

    rules = [

        [
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-p",
            "tcp",
            "-d",
            PUBLIC_IP,
            "--dport",
            str(port),
            "-j",
            "DNAT",
            "--to-destination",
            f"{container_ip}:22"
        ],

        [
            "-D",
            "FORWARD",
            "-p",
            "tcp",
            "-d",
            container_ip,
            "--dport",
            "22",
            "-m",
            "conntrack",
            "--ctstate",
            "NEW,ESTABLISHED,RELATED",
            "-j",
            "ACCEPT"
        ],

        [
            "-D",
            "FORWARD",
            "-p",
            "tcp",
            "-s",
            container_ip,
            "--sport",
            "22",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT"
        ]
    ]

    for rule in rules:

        iptables(
            *rule,
            check=False
        )


def save_iptables():

    result = subprocess.run(
        [
            "sh",
            "-c",
            "command -v netfilter-persistent"
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if result.returncode == 0:

        subprocess.run(
            [
                "netfilter-persistent",
                "save"
            ],
            check=False
        )


# =========================================================
# CREATE VPS
# =========================================================

async def create_vps(
    name,
    ram,
    cpu,
    disk,
    days,
    owner
):

    if not valid_name(name):

        raise ValueError(
            "VPS name can only contain "
            "letters, numbers, - and _"
        )

    if DB.execute(
        "SELECT 1 FROM vps WHERE name=?",
        (name,)
    ).fetchone():

        raise ValueError(
            "This VPS already exists in database."
        )

    if container_exists(name):

        raise ValueError(
            f"LXC container '{name}' already exists. "
            f"Choose another VPS name or delete the old container."
        )

    port = allocate_port()

    password = random_password()

    # -----------------------------------------------------
    # FIND WORKING UBUNTU IMAGE
    # -----------------------------------------------------

    launch_error = None

    for image in LXC_IMAGES:

        try:

            print(
                f"[VPS] Trying LXC image: {image}"
            )

            lxc(
                "launch",
                image,
                name
            )

            print(
                f"[VPS] Container created using {image}"
            )

            break

        except Exception as error:

            launch_error = str(error)

            print(
                f"[VPS] Image failed: {image}"
            )

            print(
                launch_error
            )

            # If partially created, remove it
            if container_exists(name):

                lxc(
                    "delete",
                    name,
                    "--force",
                    check=False
                )

    else:

        raise RuntimeError(
            "LXC container could not be created.\n\n"
            "Tried images:\n"
            + "\n".join(LXC_IMAGES)
            + "\n\nLast LXC error:\n"
            + str(launch_error)
        )

    try:

        # -------------------------------------------------
        # RAM
        # -------------------------------------------------

        lxc(
            "config",
            "set",
            name,
            "limits.memory",
            f"{ram}GiB"
        )

        # -------------------------------------------------
        # CPU
        # -------------------------------------------------

        lxc(
            "config",
            "set",
            name,
            "limits.cpu",
            str(cpu)
        )

        # -------------------------------------------------
        # DISK
        # -------------------------------------------------

        lxc(
            "config",
            "device",
            "override",
            name,
            "root",
            f"size={disk}GiB"
        )

        # -------------------------------------------------
        # INSTALL SSH
        # -------------------------------------------------

        password_safe = (
            password
            .replace("\\", "\\\\")
            .replace("'", "'\"'\"'")
        )

        setup_script = f"""
export DEBIAN_FRONTEND=noninteractive

apt-get update -y

apt-get install -y \
openssh-server \
sudo \
curl \
wget \
neofetch

mkdir -p /run/sshd

echo 'root:{password_safe}' | chpasswd

sed -i \
's/^#\\?PasswordAuthentication .*/PasswordAuthentication yes/' \
/etc/ssh/sshd_config

sed -i \
's/^#\\?PermitRootLogin .*/PermitRootLogin yes/' \
/etc/ssh/sshd_config

systemctl enable ssh || true

systemctl restart ssh || \
service ssh restart || true
"""

        lxc(
            "exec",
            name,
            "--",
            "bash",
            "-lc",
            setup_script
        )

        # -------------------------------------------------
        # WAIT FOR IP
        # -------------------------------------------------

        container_ip = None

        for _ in range(30):

            container_ip = get_container_ip(
                name
            )

            if container_ip:
                break

            await asyncio.sleep(1)

        if not container_ip:

            raise RuntimeError(
                "Container was created but no IPv4 "
                "address was detected."
            )

        # -------------------------------------------------
        # PORT FORWARD
        # -------------------------------------------------

        add_port_forward(
            port,
            container_ip
        )

        save_iptables()

        # -------------------------------------------------
        # EXPIRY
        # -------------------------------------------------

        now = datetime.now(
            timezone.utc
        )

        expires = (
            now
            + timedelta(days=days)
        )

        # -------------------------------------------------
        # DATABASE
        # -------------------------------------------------

        DB.execute(
            """
            INSERT INTO vps
            (
                name,
                owner_id,
                owner_tag,
                ram_gb,
                cpu_vcores,
                disk_gb,
                valid_days,
                expires_at,
                ssh_port,
                container_ip,
                password,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                owner.id,
                str(owner),
                ram,
                cpu,
                disk,
                days,
                expires.isoformat(),
                port,
                container_ip,
                password,
                now.isoformat()
            )
        )

        DB.commit()

        return {
            "name": name,
            "ram": ram,
            "cpu": cpu,
            "disk": disk,
            "days": days,
            "expires": expires,
            "port": port,
            "ip": container_ip,
            "password": password,
            "owner": owner
        }

    except Exception:

        container_ip = get_container_ip(
            name
        )

        if container_ip:

            remove_port_forward(
                port,
                container_ip
            )

        lxc(
            "delete",
            name,
            "--force",
            check=False
        )

        save_iptables()

        raise


# =========================================================
# DELETE VPS
# =========================================================

async def delete_vps(name):

    row = DB.execute(
        "SELECT * FROM vps WHERE name=?",
        (name,)
    ).fetchone()

    if not row:

        raise ValueError(
            "VPS not found in database."
        )

    remove_port_forward(
        row["ssh_port"],
        row["container_ip"]
    )

    lxc(
        "delete",
        name,
        "--force",
        check=False
    )

    DB.execute(
        "DELETE FROM vps WHERE name=?",
        (name,)
    )

    DB.commit()

    save_iptables()

    return row


# =========================================================
# VPS DM
# =========================================================

async def send_vps_dm(data):

    owner = (
        bot.get_user(data["owner"].id)
        or data["owner"]
    )

    embed = discord.Embed(
        title="🖥️ Your VPS Is Ready!",
        color=discord.Color.green()
    )

    embed.add_field(
        name="📦 VPS Name",
        value=f"`{data['name']}`",
        inline=False
    )

    embed.add_field(
        name="🌐 IP",
        value=f"`{PUBLIC_IP}`",
        inline=True
    )

    embed.add_field(
        name="🔌 SSH Port",
        value=f"`{data['port']}`",
        inline=True
    )

    embed.add_field(
        name="🧠 RAM",
        value=f"`{data['ram']} GB`",
        inline=True
    )

    embed.add_field(
        name="⚡ CPU",
        value=f"`{data['cpu']} vCore`",
        inline=True
    )

    embed.add_field(
        name="💾 Disk",
        value=f"`{data['disk']} GB`",
        inline=True
    )

    embed.add_field(
        name="📅 Valid Days",
        value=f"`{data['days']} Days`",
        inline=True
    )

    embed.add_field(
        name="⏰ Expiry",
        value=discord.utils.format_dt(
            data["expires"],
            "F"
        ),
        inline=False
    )

    embed.add_field(
        name="🔑 SSH Command",
        value=(
            f"`ssh root@{PUBLIC_IP} "
            f"-p {data['port']}`"
        ),
        inline=False
    )

    embed.add_field(
        name="🔐 Root Password",
        value=(
            f"||`{data['password']}`||"
        ),
        inline=False
    )

    embed.set_footer(
        text="Keep your VPS password private."
    )

    await owner.send(
        embed=embed
    )


# =========================================================
# ADMIN CHECK
# =========================================================

def is_admin(ctx):

    # Admin ID from .env
    if ctx.author.id in ADMIN_IDS:
        return True

    # Discord server Administrator permission
    if isinstance(
        ctx.author,
        discord.Member
    ):

        if ctx.author.guild_permissions.administrator:
            return True

    return False


# =========================================================
# BOT READY
# =========================================================

@bot.event
async def on_ready():

    print(
        f"Bot online: {bot.user}"
    )

    print(
        f"Admins: {ADMIN_IDS}"
    )

    if not expiry_loop.is_running():

        expiry_loop.start()


# =========================================================
# CREATE COMMAND
# =========================================================

@bot.command(
    name="create"
)
async def create_command(
    ctx,
    name: str,
    ram: int,
    cpu: int,
    disk: int,
    days: int,
    owner: discord.Member
):

    if not is_admin(ctx):

        return await ctx.reply(
            "❌ You don't have permission "
            "to create VPS."
        )

    if (
        ram < 1
        or ram > 512
        or cpu < 1
        or cpu > 128
        or disk < 1
        or disk > 4096
        or days < 1
        or days > 3650
    ):

        return await ctx.reply(
            "❌ Invalid VPS resource values."
        )

    message = await ctx.reply(
        "⏳ Creating VPS...\n"
        "Please wait."
    )

    try:

        data = await create_vps(
            name,
            ram,
            cpu,
            disk,
            days,
            owner
        )

        try:

            await send_vps_dm(
                data
            )

            dm_status = (
                "✅ VPS details sent to owner DM."
            )

        except discord.Forbidden:

            dm_status = (
                "⚠️ VPS created but owner's "
                "DM is closed."
            )

        await message.edit(
            content=(
                f"✅ **VPS Created Successfully!**\n\n"
                f"📦 Name: `{name}`\n"
                f"👤 Owner: {owner.mention}\n"
                f"🌐 IP: `{PUBLIC_IP}`\n"
                f"🔌 Port: `{data['port']}`\n"
                f"🧠 RAM: `{ram}GB`\n"
                f"⚡ CPU: `{cpu} vCore`\n"
                f"💾 Disk: `{disk}GB`\n"
                f"📅 Valid: `{days} days`\n\n"
                f"{dm_status}"
            )
        )

    except Exception as error:

        error_text = str(error)

        # Discord message max safety
        if len(error_text) > 1800:
            error_text = error_text[-1800:]

        await message.edit(
            content=(
                "❌ **VPS Creation Failed**\n\n"
                f"```text\n"
                f"{error_text}\n"
                f"```"
            )
        )


# =========================================================
# ALL VPS
# =========================================================

@bot.command(
    name="all-vps"
)
async def all_vps(ctx):

    if not is_admin(ctx):

        return await ctx.reply(
            "❌ Admin only."
        )

    rows = DB.execute(
        "SELECT * FROM vps ORDER BY created_at"
    ).fetchall()

    if not rows:

        return await ctx.reply(
            "📭 No VPS found."
        )

    lines = []

    for row in rows:

        owner = bot.get_user(
            row["owner_id"]
        )

        if owner:

            owner_text = owner.mention

        else:

            owner_text = (
                f"<@{row['owner_id']}>"
            )

        expires = datetime.fromisoformat(
            row["expires_at"]
        )

        lines.append(
            f"**{row['name']}**\n"
            f"👤 Owner: {owner_text}\n"
            f"🌐 `{PUBLIC_IP}:{row['ssh_port']}`\n"
            f"🧠 `{row['ram_gb']}GB RAM` | "
            f"⚡ `{row['cpu_vcores']} vCPU` | "
            f"💾 `{row['disk_gb']}GB`\n"
            f"⏰ Expires: "
            f"{discord.utils.format_dt(expires, 'R')}"
        )

    chunks = []
    current = ""

    for line in lines:

        if len(current) + len(line) + 2 > 3800:

            chunks.append(current)

            current = ""

        current += line + "\n\n"

    if current:

        chunks.append(current)

    for index, chunk in enumerate(chunks):

        embed = discord.Embed(
            title=(
                "🖥️ All VPS"
                + (
                    f" ({index + 1}/{len(chunks)})"
                    if len(chunks) > 1
                    else ""
                )
            ),
            description=chunk,
            color=discord.Color.blurple()
        )

        await ctx.send(
            embed=embed
        )


# =========================================================
# DELETE COMMAND
# =========================================================

@bot.command(
    name="delete"
)
async def delete_command(
    ctx,
    name: str
):

    if not is_admin(ctx):

        return await ctx.reply(
            "❌ Admin only."
        )

    try:

        row = await delete_vps(
            name
        )

        owner = bot.get_user(
            row["owner_id"]
        )

        if owner:

            try:

                await owner.send(
                    f"🗑️ Your VPS "
                    f"**`{name}`** has been "
                    f"deleted by an administrator."
                )

            except discord.Forbidden:

                pass

        await ctx.reply(
            f"✅ VPS `{name}` deleted."
        )

    except Exception as error:

        await ctx.reply(
            f"❌ Delete failed:\n"
            f"```text\n"
            f"{str(error)[:1500]}\n"
            f"```"
        )


# =========================================================
# HELP
# =========================================================

@bot.command(
    name="help"
)
async def help_command(ctx):

    embed = discord.Embed(
        title="🤖 VPS Bot Commands",
        color=discord.Color.blurple()
    )

    embed.add_field(
        name="🖥️ .create",
        value=(
            "`.create <name> <ram> <cpu> "
            "<disk> <days> @owner`\n\n"
            "Example:\n"
            "`.create test 4 2 30 30 @User`"
        ),
        inline=False
    )

    embed.add_field(
        name="📋 .all-vps",
        value=(
            "Admin command.\n"
            "Shows VPS list, owner, IP, "
            "port, RAM, CPU, disk and expiry."
        ),
        inline=False
    )

    embed.add_field(
        name="🗑️ .delete",
        value=(
            "`.delete <vps-name>`\n"
            "Deletes selected VPS."
        ),
        inline=False
    )

    embed.add_field(
        name="❓ .help",
        value=(
            "Shows all bot commands."
        ),
        inline=False
    )

    await ctx.reply(
        embed=embed
    )


# =========================================================
# AUTO EXPIRY
# =========================================================

@tasks.loop(
    seconds=EXPIRY_CHECK_SECONDS
)
async def expiry_loop():

    await bot.wait_until_ready()

    now = datetime.now(
        timezone.utc
    )

    rows = DB.execute(
        """
        SELECT *
        FROM vps
        WHERE expires_at <= ?
        """,
        (
            now.isoformat(),
        )
    ).fetchall()

    for row in rows:

        try:

            deleted = await delete_vps(
                row["name"]
            )

            owner = bot.get_user(
                deleted["owner_id"]
            )

            if owner:

                try:

                    await owner.send(
                        f"⏰ Your VPS "
                        f"**`{deleted['name']}`** "
                        f"has expired and was "
                        f"automatically deleted."
                    )

                except discord.Forbidden:

                    pass

        except Exception as error:

            print(
                f"Expiry deletion failed "
                f"for {row['name']}: {error}"
            )


@expiry_loop.before_loop
async def before_expiry_loop():

    await bot.wait_until_ready()


# =========================================================
# START BOT
# =========================================================

bot.run(TOKEN)
