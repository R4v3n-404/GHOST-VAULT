# How to play GHOST-VAULT

## 0. Build the game (first time only)

The encrypted vaults are generated locally; they are not stored in the repo.

```bash
cd GHOST-VAULT          # or the folder you cloned into
./play.sh setup
```

Build and play as the same user: stage 6 uses your primary group.

## 1. Open the game folder

```bash
cd GHOST-VAULT
./play.sh
```

You will see the 11 stage names and your progress. Stage 0 is always open.

## 2. Enter stage 0

```bash
./play.sh login 0
```

Your prompt changes to:

```
bandit0@ghostvault:~$
```

You are now inside the stage's home directory (`work/0`). Everything you need
is in front of you.

## 3. Use the in-vault helpers

```bash
mission      # the objective for this stage
hint         # hint 1
hint 2       # hint 2
hint 3       # near-solution
status       # progress, even from inside the vault
```

`ls`, `cat`, `find`, `grep`, `sort`, `uniq`, `strings`, `base64`, `file` — all
your normal tools work.

## 4. Find the key and leave

A stage's target file contains a line like:

```
LEVEL 4 KEY: <20 random characters>
```

That is the password for the **next** stage. Once you have it:

```bash
exit
```

You are back outside the vault. Then:

```bash
./play.sh login 4
bandit4@ghostvault's password:        # paste the key; input is hidden
```

If the key is wrong you get:

```
Permission denied, please try again.
```

## 5. Finish the game

Stage 10 contains a **master key** instead of a stage key. Verify it with:

```bash
./play.sh finish <MASTER KEY>
```

That marks the run complete and prints the full skill list.

---

## Example first run

```text
$ ./play.sh
   +----------------------------------------------+
   |   G H O S T V A U L T   .   local ctf        |
   |   11 stages . no root . pure shell           |
   +----------------------------------------------+

PROGRESS
  .  00  First Contact            ls · cat · pwd
  .  01  The Nameless File        dashes · ./
  ...
Start here : ./play.sh login 0

$ ./play.sh login 0

Access granted.  Stage 0 — First Contact
Vault mounted at /path/to/GHOST-VAULT/work/0

Stage 0: First Contact
Commands: mission | hint [1-3] | status | exit

bandit0@ghostvault:~$ ls
inbox  MISSION.txt  notes  readme  welcome.txt
bandit0@ghostvault:~$ cat readme
...
LEVEL 1 KEY: ................................
...
bandit0@ghostvault:~$ exit

Connection to ghostvault closed.
If you recovered the key: ./play.sh login 1

$ ./play.sh login 1
bandit1@ghostvault's password:
...
```

---

## Rules of thumb

- **Read the mission first.** It tells you which properties to filter on.
- **Build pipelines in pieces.** Run the left half, look at the output, then add
  the next pipe.
- **`man <command>` / `<command> --help`** before guessing a flag.
- **Don't trust filenames or extensions.** Inspect contents with `file`.
- **`Tab` completes, `Ctrl+C` aborts, `Ctrl+D` exits.**
- **One vault at a time.** `login` deletes the previous vault folder, so you
  must have the key again to go back.

---

## Troubleshooting

**"Game is not built."**
```bash
./play.sh setup
```

**"You are inside a vault. Type 'exit' first."**
You ran `./play.sh login ...` from inside a stage shell. `exit` first.

**"Missing vault for stage N."**
The `levels/` folder is incomplete. Rebuild:
```bash
./play.sh rebuild
```

**I forgot a key.**
You can re-enter the previous stage if you still have its key. If you have lost
the chain completely, `./play.sh rebuild` starts a fresh run with new keys.

**I want new puzzles without losing the design.**
```bash
./play.sh rebuild     # new random keys, same stages
```
