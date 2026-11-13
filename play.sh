#!/usr/bin/env bash
# GHOSTVAULT launcher — local CTF, no root, no network.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
LEVELS="$ROOT/levels"
STATE="$ROOT/.state"
WORK="$ROOT/work"
META="$ROOT/meta.tsv"
mkdir -p "$STATE" "$WORK"

if [[ -t 1 ]]; then
  R=$'\e[0m'; B=$'\e[1m'; DIM=$'\e[2m'
  GRN=$'\e[1;32m'; BLU=$'\e[1;34m'; RED=$'\e[1;31m'
  YEL=$'\e[1;33m'; CYA=$'\e[1;36m'
else
  R=""; B=""; DIM=""; GRN=""; BLU=""; RED=""; YEL=""; CYA=""
fi

banner() {
  printf '%s\n' "${CYA}${B}"
  printf '%s\n' '   +----------------------------------------------+'
  printf '%s\n' '   |   G H O S T V A U L T   .   local ctf        |'
  printf '%s\n' '   |   11 stages . no root . pure shell           |'
  printf '%s\n' '   +----------------------------------------------+'
  printf '%s\n\n' "${R}"
}

title_of() { awk -F'|' -v n="$1" '$1==n{print $2}' "$META" 2>/dev/null; }
skill_of() { awk -F'|' -v n="$1" '$1==n{print $3}' "$META" 2>/dev/null; }

ensure_game() {
  if [[ ! -f "$META" || ! -d "$LEVELS/00" ]]; then
    echo "${RED}Game is not built.${R} Run: ${B}./play.sh setup${R}   (or ${B}python3 tools/build.py${R})"
    exit 1
  fi
}

status() {
  banner
  ensure_game
  echo "${B}PROGRESS${R}"
  local n current="" next=""
  for n in $(seq 0 10); do
    local mark="." col="$DIM"
    if [[ -f "$STATE/cleared/$n" ]]; then
      mark="x"; col="$GRN"
    elif [[ -f "$STATE/entered/$n" ]]; then
      mark=">"; col="$YEL"; current="$n"
    fi
    printf '  %s%s%s  %s%02d%s  %-24s %s%s%s\n' \
      "$col" "$mark" "$R" "$col" "$n" "$R" "$(title_of "$n")" "$DIM" "$(skill_of "$n")" "$R"
    if [[ -z "$next" && ! -f "$STATE/cleared/$n" && ! -f "$STATE/entered/$n" ]]; then next="$n"; fi
  done
  echo
  if [[ -f "$STATE/finished" ]]; then
    echo "${GRN}${B}VAULT COMPLETE — all 11 keys recovered.${R}"
  elif [[ -n "$current" ]]; then
    if (( current < 10 )); then
      echo "Current    : stage $current — find its key, then ${B}./play.sh login $((current+1))${R}"
    else
      echo "Current    : stage 10 — find the master key, then ${B}./play.sh finish <key>${R}"
    fi
  elif [[ "$next" == "0" ]]; then
    echo "Start here : ${B}./play.sh login 0${R}"
  elif [[ -n "$next" ]]; then
    echo "Next stage : ${B}./play.sh login $next${R}   ${DIM}(key from stage $((next-1)))${R}"
  else
    echo "Run        : ${B}./play.sh finish <MASTER KEY>${R}"
  fi
  echo "Hints      : ./play.sh hint <stage> [1-3|all]"
}

usage() {
  banner
  cat <<EOF
${B}USAGE${R}
  ./play.sh                    show progress
  ./play.sh setup              build the game for the first time
  ./play.sh login <stage>      enter stage 0-10 (prompts for the key)
  ./play.sh status             show progress
  ./play.sh hint <stage> [n]   hint 1-3, or "all"
  ./play.sh finish <key>       verify the master key
  ./play.sh reset              wipe progress and vaults
  ./play.sh rebuild            regenerate all stages (wipes progress)
  ./play.sh help               this text

${B}HOW IT WORKS${R}
  Stage 0 is open. Every later stage is an AES-encrypted archive whose
  password is the key hidden in the previous stage. Nothing is written
  to disk in plaintext. Solve a stage, leave it, log in to the next.
EOF
}

guard_cwd() {
  case "$PWD" in
    "$WORK"/*) echo "${YEL}You are inside a vault. Type 'exit' first.${R}"; return 1 ;;
  esac
  return 0
}

launch_shell() {
  local n="$1"
  CTF_ROOT="$ROOT" CTF_LEVEL="$n" CTF_STAGE_TITLE="$(title_of "$n")" \
    HOME="$WORK/$n" bash --noprofile --rcfile "$ROOT/lib/rc.sh" -i
  echo
  echo "${DIM}Connection to ghostvault closed.${R}"
  if (( n < 10 )); then
    echo "${DIM}If you recovered the key: ./play.sh login $((n+1))${R}"
  else
    echo "${DIM}If you have the master key: ./play.sh finish <key>${R}"
  fi
}

cmd_setup() {
  if [[ -f "$META" && -d "$LEVELS/00" ]]; then
    echo "Game already built. Use ./play.sh rebuild to regenerate it."
    return 0
  fi
  python3 "$ROOT/tools/build.py"
}

cmd_login() {
  ensure_game
  local n="${1:-}"
  shift || true
  if [[ ! "$n" =~ ^[0-9]+$ ]] || (( n < 0 || n > 10 )); then
    echo "Usage: ./play.sh login <stage 0-10>"
    return 1
  fi
  guard_cwd || return 1

  if (( n == 0 )); then
    [[ -d "$LEVELS/00" ]] || { echo "${RED}Stage 0 is missing. Run rebuild.${R}"; return 1; }
    find "$WORK" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null
    mkdir -p "$WORK/0"
    cp -a "$LEVELS/00"/. "$WORK/0"/
  else
    local enc="$LEVELS/$(printf '%02d' "$n").tar.gz.enc"
    [[ -f "$enc" ]] || { echo "${RED}Missing vault for stage $n. Run rebuild.${R}"; return 1; }
    local key="${1:-}"
    if [[ -z "$key" ]]; then
      printf "%s@ghostvault's password: " "bandit$n"
      IFS= read -rs key
      echo
    fi
    [[ -n "$key" ]] || { echo "No key entered."; return 1; }

    local tmp
    tmp="$(mktemp -d)"
    if ! printf '%s\n' "$key" | openssl enc -d -aes-256-cbc -pbkdf2 -in "$enc" \
         -out "$tmp/vault.tar.gz" -pass stdin 2>/dev/null; then
      rm -rf "$tmp"
      echo "${RED}Permission denied, please try again.${R}"
      return 1
    fi
    find "$WORK" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null
    mkdir -p "$WORK/$n"
    if ! tar xzf "$tmp/vault.tar.gz" -C "$WORK/$n" \
         --same-owner --same-permissions --numeric-owner 2>/dev/null || \
       [[ ! -f "$WORK/$n/MISSION.txt" ]]; then
      find "$WORK" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null
      echo "${RED}Permission denied, please try again.${R}"
      return 1
    fi
    rm -rf "$tmp"
  fi

  mkdir -p "$STATE/cleared"
  if (( n > 0 )); then touch "$STATE/cleared/$((n-1))"; fi
  touch "$STATE/entered/$n" 2>/dev/null || { mkdir -p "$STATE/entered"; touch "$STATE/entered/$n"; }

  echo
  echo "${GRN}${B}Access granted.${R}  Stage $n — $(title_of "$n")"
  echo "${DIM}Vault mounted at $WORK/$n${R}"
  echo

  if [[ "${CTF_NO_SHELL:-0}" == "1" ]]; then
    echo "(shell suppressed: CTF_NO_SHELL=1)"
    return 0
  fi
  launch_shell "$n"
}

cmd_hint() {
  ensure_game
  local n="${1:-}" want="${2:-1}"
  if [[ ! "$n" =~ ^[0-9]+$ ]] || (( n < 0 || n > 10 )); then
    echo "Usage: ./play.sh hint <stage 0-10> [1-3|all]"
    return 1
  fi
  local f="$ROOT/hints/$(printf '%02d' "$n").txt"
  [[ -f "$f" ]] || { echo "No hints for stage $n."; return 1; }
  echo "${B}STAGE $n — $(title_of "$n")${R}"
  if [[ "$want" == "all" ]]; then
    awk -F'\t' '{printf "  %sHint %s:%s %s\n", "\033[1;33m", substr($1,2), "\033[0m", $2}' "$f" | sed 's/`//g'
  elif [[ "$want" =~ ^[123]$ ]]; then
    local line
    line="$(awk -F'\t' -v k="H$want" '$1==k{print $2}' "$f" | sed 's/`//g')"
    echo "  ${YEL}Hint $want/3:${R} $line"
  else
    echo "Hint number must be 1, 2, 3, or all."
    return 1
  fi
}

cmd_finish() {
  ensure_game
  local key="${1:-}"
  if [[ -z "$key" ]]; then
    printf "Master key: "
    IFS= read -r key
  fi
  [[ -n "$key" ]] || { echo "No key entered."; return 1; }
  local got want
  got="$(printf '%s' "$key" | sha256sum | awk '{print $1}')"
  want="$(cat "$ROOT/.system/final.hash" 2>/dev/null || true)"
  if [[ -n "$want" && "$got" == "$want" ]]; then
    mkdir -p "$STATE/cleared"
    touch "$STATE/cleared/10" "$STATE/finished"
    banner
    echo "${GRN}${B}MASTER KEY ACCEPTED.${R}"
    echo
    echo "All eleven vaults are open. You rebuilt the archive."
    echo
    echo "Skills cleared:"
    for n in 0 1 2 3 4 5 6 7 8 9 10; do
      printf "  %02d  %-24s %s\n" "$n" "$(title_of "$n")" "$(skill_of "$n")"
    done
    echo
    echo "${DIM}Run ./play.sh status any time. ./play.sh rebuild starts fresh.${R}"
  else
    echo "${RED}That is not the master key.${R}"
    return 1
  fi
}

cmd_reset() {
  guard_cwd || return 1
  local ans
  read -r -p "Wipe all progress and vault folders? [y/N] " ans
  [[ "$ans" == [yY]* ]] || { echo "Cancelled."; return 0; }
  find "$STATE" -mindepth 1 -exec rm -rf {} + 2>/dev/null
  find "$WORK" -mindepth 1 -exec rm -rf {} + 2>/dev/null
  echo "Progress wiped."
}

cmd_rebuild() {
  guard_cwd || return 1
  local ans
  read -r -p "Regenerate all stages and wipe progress? [y/N] " ans
  [[ "$ans" == [yY]* ]] || { echo "Cancelled."; return 0; }
  python3 "$ROOT/tools/build.py" --force
}

case "${1:-}" in
  ""|status)      status ;;
  setup)          cmd_setup ;;
  start)          cmd_login 0 ;;
  login)          shift; cmd_login "$@" ;;
  hint)           shift; cmd_hint "$@" ;;
  finish)         shift; cmd_finish "$@" ;;
  reset)          cmd_reset ;;
  rebuild)        cmd_rebuild ;;
  help|-h|--help) usage ;;
  *)              usage; exit 1 ;;
esac
