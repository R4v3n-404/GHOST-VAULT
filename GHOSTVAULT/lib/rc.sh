# Interactive shell for a GHOSTVAULT stage.
# Started by play.sh with CTF_ROOT, CTF_LEVEL, CTF_STAGE_TITLE and HOME set.

if [[ -n "${CTF_LEVEL:-}" ]]; then
  PS1='\[\e[1;32m\]bandit'"${CTF_LEVEL}"'@ghostvault\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
fi
export PS1

cd "${HOME:-.}" 2>/dev/null || true
shopt -s checkwinsize 2>/dev/null || true

alias ls='ls --color=auto'
alias ll='ls -al'
alias la='ls -a'

mission() { cat "$HOME/MISSION.txt" 2>/dev/null || echo "No MISSION.txt here."; }
hint()    { "$CTF_ROOT/play.sh" hint "$CTF_LEVEL" "${1:-1}"; }
status()  { "$CTF_ROOT/play.sh" status; }

echo
echo "Stage ${CTF_LEVEL}: ${CTF_STAGE_TITLE:-}"
echo "Commands: mission | hint [1-3] | status | exit"
echo
