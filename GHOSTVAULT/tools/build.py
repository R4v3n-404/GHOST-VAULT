#!/usr/bin/env python3
"""GHOSTVAULT builder.

Generates 11 stages and 10 encrypted vaults, so the key for stage N
is the only way to open stage N. Passwords are random on every build
and are never written to disk in plaintext.

Usage:
    python3 tools/build.py            # refuse if stages already exist
    python3 tools/build.py --force    # wipe everything and regenerate
"""
from __future__ import annotations

import base64
import hashlib
import io
import os
import random
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEVELS = ROOT / "levels"
HINTS = ROOT / "hints"
SYS = ROOT / ".system"
WORK = ROOT / "work"
STATE = ROOT / ".state"
META = ROOT / "meta.tsv"

ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
STAGE_TITLES = {
    0: ("First Contact", "ls · cat · pwd"),
    1: ("The Nameless File", "dashes · ./"),
    2: ("Spaces in the Name", "quoting · escaping · tab"),
    3: ("What ls Hides", "hidden files · ls -a"),
    4: ("Trust the Contents", "file · find + xargs"),
    5: ("The Needle by Size", "find -size · ! -executable"),
    6: ("Composing Predicates", "find -group · -newer · ranges"),
    7: ("Reading Between Lines", "grep · pipelines · -E"),
    8: ("The Singular Line", "sort · uniq -u · uniq -c"),
    9: ("Ghosts in the Binary", "strings · grep"),
    10: ("The Encoded Message", "base64 -d"),
}

HINTS_TEXT = {
    0: [
        "List everything in your home directory. The file is not hidden.",
        "`ls` first, then read the file named `readme` with `cat`.",
        "`cat readme`",
    ],
    1: [
        "The filename is a single dash. A bare dash means standard input to many commands.",
        "Give the shell a path so the dash is not read as an option. Prefix it with `./`.",
        "`cat ./-`",
    ],
    2: [
        "The shell splits arguments on spaces, so the filename must be protected.",
        "Quote the whole name, or escape each space with a backslash. Tab completion helps too.",
        '`cat "field report.txt"`   (or `cat field\\ report.txt`)',
    ],
    3: [
        "`ls` hides names that begin with a dot.",
        "Use `ls -a` on the `vault` directory, then read the dotfile that is not a directory.",
        "`cd vault && ls -a`   then   `cat .hidden`",
    ],
    4: [
        "Extensions are labels, not proof. Inspect what is actually inside each file.",
        "`file` reports the type from the bytes. Combine it with a glob or `find`.",
        "`file drop/*`   then `cat` the one marked `ASCII text`",
    ],
    5: [
        "You need files filtered by exact size in bytes, not by name.",
        "`find` has `-size` (use the `c` suffix for bytes) and `-executable` with `!` to negate.",
        "`find haystack -type f -size 1337c ! -executable`",
    ],
    6: [
        "Several filters combine here: type, size range, group, modification time, and a name pattern.",
        "`find` supports `-size +2047c -size -3073c`, `-group`, `-newer`, and `-name '*.log'`.",
        "`find depot -type f -size +2047c -size -3073c -group \"$(id -gn)\" -newer depot/.stamp -name '*.log'`",
    ],
    7: [
        "You are looking for one line that satisfies three conditions at once.",
        "Use `grep` on the log files, then pipe into another `grep` for the status. Do not use `-i` blindly.",
        "`grep 'POST /admin ' logs/*.log | grep ' 200 '`",
    ],
    8: [
        "Duplicates hide a single line. Counting lines is easier after sorting.",
        "`sort` makes identical lines adjacent; `uniq -u` prints only lines that appear once.",
        "`sort signals.txt | uniq -u`   (or `sort signals.txt | uniq -c | sort -n`)",
    ],
    9: [
        "The file contains binary noise, but readable strings are embedded in it.",
        "`strings` extracts printable sequences. Filter them with `grep`.",
        "`strings artifact.bin | grep '=='`",
    ],
    10: [
        "The file is text, but the text is an encoding of the real message.",
        "`base64` decodes with `-d` (or `--decode`). Without `-d` it encodes.",
        "`base64 -d transmission.b64`",
    ],
}


def randkey() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(20))


def write(path: Path, data: str | bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)
    os.chmod(path, mode)


def pad_to(data: bytes, size: int, filler: bytes = b"#") -> bytes:
    if len(data) > size:
        raise ValueError("payload larger than requested size")
    return data + filler * (size - len(data))


def make_tar(src: Path) -> bytes:
    buf = io.BytesIO()

    def add(tf: tarfile.TarFile, path: Path, arcname: str, fileobj=None) -> None:
        info = tf.gettarinfo(str(path), arcname=arcname)
        # Keep local account names out of the archive. The numeric uid/gid
        # still carries the metadata the stage-06 group puzzle needs.
        info.uname = "player"
        info.gname = "player"
        if fileobj is not None:
            tf.addfile(info, fileobj)
        else:
            tf.addfile(info)

    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
        for base, dirs, files in os.walk(src):
            dirs.sort()
            files.sort()
            rel_dir = os.path.relpath(base, src)
            if rel_dir != ".":
                add(tf, Path(base), rel_dir)
            for name in files:
                full = Path(base) / name
                arc = os.path.relpath(full, src)
                with open(full, "rb") as fh:
                    add(tf, full, arc, fh)
    return buf.getvalue()


def openssl_enc(data: bytes, key: str) -> bytes:
    proc = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt",
         "-pass", f"pass:{key}"],
        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode(errors="replace"))
    return proc.stdout


def openssl_dec(data: bytes, key: str) -> bytes:
    proc = subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
         "-pass", f"pass:{key}"],
        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise ValueError("bad key")
    return proc.stdout


# --------------------------------------------------------------------------
# stage content
# --------------------------------------------------------------------------
def plain(text: str) -> str:
    """Turn the lightweight markdown used in stage copy into terminal text."""
    text = text.replace("**", "").replace("`", "")
    text = "\n".join(
        line[2:] if line.startswith("# ") else line
        for line in text.splitlines()
    )
    return text.strip()


def mission(n: int, body: str) -> str:
    title = STAGE_TITLES[n][0].upper()
    bar = "=" * len(f"STAGE {n:02d} — {title}")
    if n < 10:
        nxt = f"  exit\n  ./play.sh login {n + 1}"
    else:
        nxt = "  exit\n  ./play.sh finish <MASTER KEY>"
    return (
        f"STAGE {n:02d} — {title}\n"
        f"{bar}\n\n"
        f"{plain(body)}\n\n"
        f"WHEN YOU HAVE THE KEY\n"
        f"{nxt}\n\n"
        f"Type mission to read this again, hint for a nudge, exit to leave.\n"
    )


def build_level(n: int, d: Path, keys: dict[int, str]) -> None:
    if n == 0:
        write(d / "MISSION.txt", mission(0, textwrap.dedent("""\
            The archive was split into eleven vaults. This is the entry point.
            One file in your home directory contains the key to Stage 01.

            **Skill:** `ls`, `cat`, `pwd`
            """)))
        write(d / "readme", textwrap.dedent(f"""\
            GHOSTVAULT — FIELD MANUAL
            =========================
            Eleven vaults. One key each.

            LEVEL 1 KEY: {keys[1]}

            Leave this vault and run: ./play.sh login 1
            """))
        write(d / "welcome.txt", textwrap.dedent("""\
            You are inside the first vault. Everything needed is in front of you.
            Start by looking around, then read what you find.
            """))
        write(d / "notes" / "scratch.txt", "Nothing useful here. Keep looking.\n")
        write(d / "inbox" / "message.txt", "Courier delay. The manual still arrived.\n")

    elif n == 1:
        write(d / "MISSION.txt", mission(1, textwrap.dedent("""\
            A courier left a file whose entire name is a single dash.
            Read it without letting the shell treat the name as an option.

            **Skill:** filenames beginning with `-`, path prefix `./`
            """)))
        write(d / "-", f"LEVEL 2 KEY: {keys[2]}\n")
        write(d / "-old", "Decoy. The dash alone is the door.\n")
        write(d / "brief.txt", "The nameless file is the only one that matters.\n")
        write(d / "logs" / "note.txt", "Nothing here.\n")

    elif n == 2:
        write(d / "MISSION.txt", mission(2, textwrap.dedent("""\
            The key is in a file whose name contains spaces.
            Quoting is the lockpick.

            **Skill:** spaces, quotes, escaping, tab completion
            """)))
        write(d / "field report.txt", f"LEVEL 3 KEY: {keys[3]}\n")
        write(d / "backup copy.txt", "Wrong report. The field copy is the real one.\n")
        write(d / "don't panic.txt", "Decoy. Apostrophes need care too.\n")
        write(d / "archive" / "old report.txt", "Archived. Not the key.\n")

    elif n == 3:
        write(d / "MISSION.txt", mission(3, textwrap.dedent("""\
            The key is in a hidden file inside `vault/`.
            A plain `ls` will lie to you by omission.

            **Skill:** hidden files, `ls -a`
            """)))
        write(d / "vault" / ".hidden", f"LEVEL 4 KEY: {keys[4]}\n")
        write(d / "vault" / ".cache", "Decoy. Not every dotfile is the key.\n")
        write(d / "vault" / ".trash" / "old.txt", "Deleted long ago.\n")
        write(d / "vault" / "manifest.txt", "Three artifacts archived. One is hidden.\n")

    elif n == 4:
        write(d / "MISSION.txt", mission(4, textwrap.dedent("""\
            Fifteen files sit in `drop/`. Extensions are unreliable.
            One file is plain ASCII text and contains a line beginning `LEVEL 5 KEY:`.

            **Skill:** `file`, `find ... | xargs file`, `grep -l`
            """)))
        drop = d / "drop"
        write(drop / "notes.md", f"# recovery notes\n\nLEVEL 5 KEY: {keys[5]}\n")
        write(drop / "readme.txt", "No key in this file. Try another.\n")
        write(drop / "photo.png", "ASCII decoy: a picture that is actually text.\n")
        write(drop / "image.jpg", "Another text file wearing an image name.\n")
        binary_files = [
            ("report.txt", 240), ("data.csv", 180), ("archive.zip", 300),
            ("payload.bin", 200), ("summary.docx", 260), ("capture.pcap", 220),
            ("backup.tar", 340), ("frame.raw", 160), ("voice.wav", 280),
            ("package.deb", 210), ("table.xlsx", 190),
        ]
        for name, size in binary_files:
            write(drop / name, os.urandom(size))
        write(drop / "README.txt", "Do not trust the extension. Ask `file`.\n")

    elif n == 5:
        write(d / "MISSION.txt", mission(5, textwrap.dedent("""\
            One file is exactly **1337 bytes** and is **not executable**.
            Everything else is noise.

            **Skill:** `find -size`, byte suffix `c`, `! -executable`
            """)))
        hay = d / "haystack"
        line = f"LEVEL 6 KEY: {keys[6]}\n".encode()
        for sub in ("alpha", "beta", "deep/level_01", "deep/level_07", "deep/level_13"):
            (hay / sub).mkdir(parents=True, exist_ok=True)
        write(hay / "deep" / "level_07" / "cache.dat", pad_to(line, 1337))
        decoy = b"Decoy file. Wrong size or mode.\n"
        write(hay / "alpha" / "near-miss.dat", pad_to(decoy, 1336))
        write(hay / "beta" / "near-miss.dat", pad_to(decoy, 1338))
        write(hay / "alpha" / "wrong-mode.dat", pad_to(decoy, 1337), 0o755)
        for i in range(110):
            sub = random.choice(["alpha", "beta", "deep/level_01",
                                 "deep/level_07", "deep/level_13"])
            size = random.choice([1336, 1338, 1200, 1500, 900, 2048, 4096])
            write(hay / sub / f"noise-{i:03d}.bin", os.urandom(size))

    elif n == 6:
        write(d / "MISSION.txt", mission(6, textwrap.dedent("""\
            Find one regular file in `depot/` that is:

            - **newer** than `depot/.stamp`
            - **between 2048 and 3072 bytes** (exclusive)
            - group is **your primary group** (find it with `id -gn`)
            - name ending in **`.log`**

            **Skill:** composing `find` predicates: `-size`, `-group`, `-newer`, `-name`
            """)))
        depot = d / "depot"
        for sub in ("alpha/2026", "beta/2025", "old", "shared", "big", "small", "misc"):
            (depot / sub).mkdir(parents=True, exist_ok=True)

        stamp = depot / ".stamp"
        write(stamp, "reference timestamp\n")
        old = time.mktime(time.strptime("2023-01-01", "%Y-%m-%d"))
        recent = time.time() - 3600
        os.utime(stamp, (old, old))

        primary_gid = os.getgid()
        # Use a supplementary group for the group decoy. Skip the primary
        # group so the target and the decoy can never share a group.
        other_gid = primary_gid
        for gid in os.getgroups():
            if gid != primary_gid:
                other_gid = gid
                break

        def make(path: Path, size: int, mtime: float, gid: int, mode: int = 0o644):
            payload = pad_to(f"decoys and noise — {path.name}\n".encode(), size)
            write(path, payload, mode)
            os.chown(path, -1, gid)
            os.utime(path, (mtime, mtime))

        line = f"LEVEL 7 KEY: {keys[7]}\n".encode()
        target = depot / "alpha" / "2026" / "audit-7.log"
        write(target, pad_to(line, 2500))
        os.chown(target, -1, primary_gid)
        os.utime(target, (recent, recent))

        make(depot / "old" / "legacy.log", 2500, old - 999, primary_gid)
        if other_gid == primary_gid:
            # No supplementary group is available. Make this decoy fail the
            # size predicate so only the target matches every condition.
            make(depot / "shared" / "team.log", 4000, recent, primary_gid)
        else:
            make(depot / "shared" / "team.log", 2500, recent, other_gid)
        make(depot / "alpha" / "report.txt", 2500, recent, primary_gid)
        make(depot / "big" / "oversize.log", 7000, recent, primary_gid)
        make(depot / "small" / "tiny.log", 1000, recent, primary_gid)
        make(depot / "misc" / "wrong-mode.txt", 2500, recent, primary_gid, 0o755)

        for i in range(80):
            sub = random.choice(["alpha/2026", "beta/2025", "old", "shared",
                                 "big", "small", "misc"])
            name = random.choice([f"note-{i}.txt", f"trace-{i}.log",
                                  f"data-{i}.bin", f"draft-{i}.md"])
            if name.endswith(".log"):
                name = f"trace-{i}.txt"
            size = random.choice([1200, 1800, 2048, 2500, 2600, 3072, 4096, 900])
            gid = random.choice([primary_gid, other_gid])
            mt = random.choice([old + i, recent - i])
            make(depot / sub / name, size, mt, gid)

    elif n == 7:
        write(d / "MISSION.txt", mission(7, textwrap.dedent("""\
            `logs/` holds two days of web traffic.
            Exactly one line is an **uppercase `POST`** to exactly **`/admin`**
            that returned **status `200`**.

            The `X-Token:` header on that line is the key.
            Do not use `-i` blindly: there are lowercase and near-miss decoys.

            **Skill:** `grep`, piping, `-E`, `-n`, `-v`, `-c`
            """)))
        logs = d / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        uas = ['"Mozilla/5.0"', '"curl/8.5"', '"python-requests/2.31"',
               '"Wget/1.21"', '"GhostProbe/0.4"']
        paths = ["/", "/index.html", "/login", "/logout", "/assets/app.css",
                 "/assets/app.js", "/api/status", "/api/v1/users", "/docs",
                 "/favicon.ico", "/search?q=archive", "/health"]
        rng = random.Random(0xC0FFEE)

        def rnd_line(day: int, idx: int) -> str:
            minute_total = idx * 8
            ts = f"2026-11-{day:02d}T{(minute_total // 60) % 24:02d}:{minute_total % 60:02d}:{rng.randint(0, 59):02d}Z"
            ip = f"10.0.{rng.randint(1, 9)}.{rng.randint(2, 250)}"
            method = rng.choice(["GET", "GET", "GET", "HEAD", "POST"])
            path = rng.choice(paths)
            status = rng.choice([200, 200, 200, 204, 304, 403, 404, 500])
            size = rng.randint(90, 9000)
            return f'{ts} {ip} {method} {path} {status} {size} {rng.choice(uas)}'

        day1 = [rnd_line(1, i) for i in range(170)]
        day2 = [rnd_line(2, i) for i in range(170)]

        day1.insert(41, '2026-11-01T09:12:44Z 10.0.7.14 POST /admin 403 128 "curl/8.5" X-Token: DECOY-403')
        day1.insert(92, '2026-11-01T15:40:02Z 10.0.3.88 GET /admin 200 512 "Mozilla/5.0" X-Token: DECOY-GET')
        day2.insert(37, '2026-11-02T04:05:19Z 10.0.9.21 POST /admin/export 200 2048 "python-requests/2.31" X-Token: DECOY-EXPORT')
        day2.insert(88, '2026-11-02T11:22:51Z 10.0.2.7 post /admin 200 64 "curl/8.5" X-Token: DECOY-LOWER')
        day2.insert(121, '2026-11-02T19:48:03Z 10.0.5.60 POST /administrator 200 64 "Wget/1.21" X-Token: DECOY-LONGER')
        day2.insert(144, f'2026-11-02T22:17:36Z 10.0.4.19 POST /admin 200 64 "curl/8.5" X-Token: {keys[8]}')

        write(logs / "2026-11-01.log", "\n".join(day1) + "\n")
        write(logs / "2026-11-02.log", "\n".join(day2) + "\n")
        write(logs / "README", "Rotated daily. Search both files.\n")

    elif n == 8:
        write(d / "MISSION.txt", mission(8, textwrap.dedent("""\
            `signals.txt` is full of repeating noise.
            Exactly one line appears **only once**. That line is the key.

            **Skill:** `sort`, `uniq -u`, `uniq -c`
            """)))
        pool = [
            "carrier lock acquired", "relay 7 nominal", "handshake ok",
            "noise burst on 144.2", "checksum pass", "buffer flushed",
            "packet 8841 dropped", "clock drift 3ms", "channel A quiet",
            "channel B noisy", "retry scheduled", "frame 0110 accepted",
            "frame 0111 accepted", "sync pulse", "watchdog reset",
            "queue depth 12", "queue depth 13", "link stable",
            "temperature 41c", "temperature 42c", "antenna parked",
            "sweep complete", "beacon received", "beacon lost",
            "archive checksum ok", "mirror lag 2s", "mirror lag 3s",
            "route via node 4", "route via node 5", "signal archived",
        ]
        rng = random.Random(0xBEEF)
        lines: list[str] = []
        for phrase in pool:
            for _ in range(rng.randint(2, 6)):
                lines.append(phrase)
        unique = f"LEVEL 9 KEY: {keys[9]}"
        lines.insert(rng.randint(0, len(lines)), unique)
        rng.shuffle(lines)
        write(d / "signals.txt", "\n".join(lines) + "\n")

    elif n == 9:
        write(d / "MISSION.txt", mission(9, textwrap.dedent("""\
            `artifact.bin` is a binary dump. Somewhere inside it is a
            printable string that begins with `==` and holds the key.

            Other strings also begin with `==`. Only one is real.

            **Skill:** `strings`, `grep`
            """)))
        rng = random.Random(0x5EED)
        decoys = [
            "== DECOY-ALPHA-7741", "== archived record 0091",
            "== signal lost", "== checksum mismatch", "== do not use",
            "== LEVEL 10 KEY: DECOY-DO-NOT-USE",
        ]
        real = f"== LEVEL 10 KEY: {keys[10]}"
        strings_pool = [
            "GHOSTVAULT artifact", "recovered fragment", "binary carrier",
            "noise floor -91db", "header 0x4f5a", "trailer 0x1a2b",
            "operator note: verify", "integrity unknown",
        ] + decoys
        rng.shuffle(strings_pool)
        blob = bytearray(os.urandom(rng.randint(40, 90)))
        for i, s in enumerate(strings_pool):
            blob += os.urandom(rng.randint(6, 30))
            blob += b"\x00" + (s + "\n").encode()
            if i == len(strings_pool) // 2:
                blob += os.urandom(rng.randint(20, 60))
                blob += b"\x00" + (real + "\n").encode()
        blob += os.urandom(rng.randint(40, 90))
        write(d / "artifact.bin", bytes(blob))
        write(d / "README", "Do not cat this. It is not text.\n")

    elif n == 10:
        write(d / "MISSION.txt", mission(10, textwrap.dedent("""\
            `transmission.b64` is base64-encoded text.
            Decode it. The master key is inside.

            **Skill:** `base64 -d`
            """)))
        msg = textwrap.dedent(f"""\
            GHOSTVAULT // INTERCEPT 011
            STATUS: ARCHIVE RECOVERED
            MASTER KEY: {keys[11]}

            All eleven stages cleared. You rebuilt the archive.
            Verify with: ./play.sh finish <MASTER KEY>
            """)
        write(d / "transmission.b64", base64.encodebytes(msg.encode()))


# --------------------------------------------------------------------------
def main() -> int:
    force = "--force" in sys.argv[1:]
    if LEVELS.exists() and any(LEVELS.iterdir()) and not force:
        print("Stages already exist. Use --force to regenerate (wipes progress).")
        return 1

    if force:
        for path in (LEVELS, WORK, STATE, SYS, HINTS):
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()
        if META.exists():
            META.unlink()

    LEVELS.mkdir(parents=True, exist_ok=True)
    HINTS.mkdir(parents=True, exist_ok=True)
    SYS.mkdir(parents=True, exist_ok=True)

    keys = {}
    while len(keys) < 11:
        k = randkey()
        if k not in keys.values():
            keys[len(keys) + 1] = k

    tmp = Path(tempfile.mkdtemp(prefix="ghostvault-"))
    try:
        for n in range(11):
            d = tmp / f"{n:02d}"
            d.mkdir(parents=True, exist_ok=True)
            build_level(n, d, keys)
            if n == 0:
                shutil.copytree(d, LEVELS / "00")

        # archive + encrypt stages 1..10, verifying each round trip
        for n in range(1, 11):
            payload = make_tar(tmp / f"{n:02d}")
            sealed = openssl_enc(payload, keys[n])
            if openssl_dec(sealed, keys[n]) != payload:
                raise RuntimeError(f"self-test failed for stage {n}")
            try:
                openssl_dec(sealed, "definitely-the-wrong-key")
                raise RuntimeError(f"wrong key opened stage {n}")
            except ValueError:
                pass
            (LEVELS / f"{n:02d}.tar.gz.enc").write_bytes(sealed)
            os.chmod(LEVELS / f"{n:02d}.tar.gz.enc", 0o644)

        # final key check: only a salted hash is stored
        (SYS / "final.hash").write_text(
            hashlib.sha256(keys[11].encode()).hexdigest() + "\n"
        )

        # metadata + hints (no keys here)
        with open(META, "w", encoding="utf-8") as fh:
            for n in range(11):
                title, skill = STAGE_TITLES[n]
                fh.write(f"{n}|{title}|{skill}\n")

        for n in range(11):
            lines = [f"H{i + 1}\t{text}" for i, text in enumerate(HINTS_TEXT[n])]
            (HINTS / f"{n:02d}.txt").write_text("\n".join(lines) + "\n")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("GHOSTVAULT built.")
    print(f"  stages        : 0-10  (11 total)")
    print(f"  encrypted     : stages 1-10  (10 vaults)")
    print(f"  keys generated: 11  (held only in memory during build)")
    print( "  keys on disk  : stage 0 only; the rest are encrypted")
    print( "  next          : ./play.sh")
    return 0


if __name__ == "__main__":
    sys.exit(main())
