# GHOST-VAULT

A local capture-the-flag game in **11 stages**, built to train the same shell
skills as OverTheWire Bandit levels 0–10 — but with fresh puzzles, decoys, and
a key-chain that forces you to actually think instead of memorising commands.

- **No root required.**
- **No network, no SSH server, no Docker.**
- **Every stage after 0 is an encrypted vault.** The key for stage *N* is hidden
  inside stage *N−1*; only the free starting stage is stored in plaintext.

---

## Requirements

Linux (or WSL) with `bash`, Python 3, OpenSSL, GNU `tar`, and the usual Unix
tools (`find`, `grep`, `sort`, `strings`, `base64`).

---

## Quick start

```bash
cd GHOST-VAULT          # or the folder you cloned into
./play.sh setup        # first run only: generate the vaults and keys
./play.sh              # show progress
./play.sh login 0      # enter stage 0 (free)
```

`levels/`, `.system/`, `.state/`, and `work/` are generated locally and are
ignored by git. Each clone builds its own random key chain. Stage 6 uses your
primary group, so build and play as the same user.

Inside a stage:

```bash
mission     # read the objective
hint        # progressive nudge (hint 2, hint 3)
ls -a       # look around
exit        # leave the vault
```

When you find a key, leave the vault and log in to the next stage:

```bash
./play.sh login 1
# bandit1@ghostvault's password: <paste the key>
```

Wrong keys are rejected exactly like an SSH login.

The final stage contains a **master key**:

```bash
./play.sh finish <MASTER KEY>
```

---

## Commands

| Command | What it does |
|---|---|
| `./play.sh` or `./play.sh status` | Show progress for all 11 stages |
| `./play.sh setup` | Build the vaults for the first time |
| `./play.sh login <0-10>` | Decrypt and enter a stage (prompts for the key) |
| `./play.sh hint <stage> [1-3\|all]` | Progressive hints, no passwords |
| `./play.sh finish <key>` | Verify the master key |
| `./play.sh reset` | Wipe progress and vault folders |
| `./play.sh rebuild` | Regenerate everything with **new random keys** |
| `./play.sh help` | Usage |

Inside a vault: `mission`, `hint`, `status`, `exit`.

---

## The 11 stages

| Stage | Name | Skill trained |
|---|---|---|
| 00 | First Contact | `ls`, `cat`, `pwd` |
| 01 | The Nameless File | filenames starting with `-`, `./` |
| 02 | Spaces in the Name | quoting, escaping, tab completion |
| 03 | What ls Hides | hidden files, `ls -a` |
| 04 | Trust the Contents | `file`, `find … \| xargs file`, `grep -l` |
| 05 | The Needle by Size | `find -size`, `! -executable` |
| 06 | Composing Predicates | `find -group`, `-newer`, size ranges, `-name` |
| 07 | Reading Between Lines | `grep`, pipelines, `-E`, `-n`, `-v` |
| 08 | The Singular Line | `sort`, `uniq -u`, `uniq -c` |
| 09 | Ghosts in the Binary | `strings`, `grep` |
| 10 | The Encoded Message | `base64 -d` |

---

## How the vault chain works

These files are created by `./play.sh setup` (or `python3 tools/build.py`):

```
levels/00/                 plaintext starting stage
levels/01.tar.gz.enc       AES-256, password = key found in stage 00
levels/02.tar.gz.enc       AES-256, password = key found in stage 01
...
levels/10.tar.gz.enc       AES-256, password = key found in stage 09
```

`play.sh login N` decrypts the vault into `work/N`, launches a shell whose
`HOME` is that folder, and cleans up the previous vault. There is no plaintext
copy of any unsolved stage anywhere on disk.

If a login is rejected, the key is wrong — same feeling as `Permission denied`.

---

## Rules

1. Try it yourself before asking for a hint.
2. Use `hint` one level at a time. Hint 3 is almost the command; save it for last.
3. Don't read `tools/build.py` if you want the full challenge — it reveals
   *where* each key is hidden (though never the key values, which are random).
4. `./play.sh rebuild` gives you a fresh set of keys, so the game is replayable.

---

## Is this a real security boundary?

No. It is a **learning game**, not a sandbox. `work/` contains only the stage
you are currently in, and unsolved stages are encrypted, but the shell itself
is a normal shell with your normal permissions. Don't put real secrets in it.

---

## Files

```
play.sh              launcher / login / hints / progress
lib/rc.sh            prompt and helper functions for the stage shell
meta.tsv             stage titles and skills
hints/               three progressive hints per stage
tools/build.py       generator; creates the encrypted vaults
.gitignore           ignores generated vaults and local progress
```

Generated locally (not committed):

```
levels/              stage 0 + encrypted vaults
.system/final.hash   master-key hash
.state/              progress markers
work/                the vault you are currently inside
```
