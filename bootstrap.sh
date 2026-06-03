#!/usr/bin/env bash
# bootstrap.sh — interactive server setup
# Usage: ./bootstrap.sh        (interactive)
#        ./bootstrap.sh --yes  (non-interactive, run all sections)
set -uo pipefail

# ── Colors & helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
info()  { echo -e "${GRN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YEL}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERR]${NC}   $*"; }

NONINTERACTIVE=false
[[ "${1:-}" == "--yes" || "${1:-}" == "-y" ]] && NONINTERACTIVE=true

# SSH port the box will end up on (used by both UFW and sshd hardening below)
SSH_PORT=2002

# Prompt helper: returns 0 (run) or 1 (skip)
# Usage: section_prompt "Section name" ["warning text"]
section_prompt() {
  local section="$1" warning="${2:-}"
  [[ -n "$warning" ]] && warn "$warning"
  if $NONINTERACTIVE; then return 0; fi
  echo -ne "${YEL}[?]${NC} Run section [${section}]? [Y/n] "
  read -r ans
  [[ "${ans,,}" == "n" ]] && { info "Skipping: ${section}"; return 1; }
  return 0
}

# Confirm helper: stricter — requires explicit 'y'
confirm() {
  local msg="$1"
  if $NONINTERACTIVE; then return 0; fi
  echo -ne "${YEL}[?]${NC} ${msg} [y/N] "
  read -r ans
  [[ "${ans,,}" == "y" ]]
}

# sshd directive: set if present (commented or not), append if missing entirely
set_sshd() {
  local key="$1" val="$2" file="$3"
  if grep -qP "^#?\s*${key}\s" "$file"; then
    sed -i -E "s|^#?\s*${key}\s.*|${key} ${val}|" "$file"
  else
    echo "${key} ${val}" >> "$file"
  fi
}

# ── Pre-flight ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then error "Must run as root."; exit 1; fi
info "Running as root on $(hostname) — $(date)"
echo

# ── 0) System update & packages ───────────────────────────────────────────────
if section_prompt "System update + install ufw/sudo/curl"; then
  apt update && apt upgrade -y
  apt install -y ufw sudo curl
  info "Packages done."
fi
echo

# ── 1) UFW ────────────────────────────────────────────────────────────────────
UFW_WARN=""
if command -v csf &>/dev/null; then
  UFW_WARN="CSF firewall detected — UFW + CSF will conflict. Strongly consider skipping."
elif [[ -f /usr/local/directadmin/directadmin ]]; then
  UFW_WARN="DirectAdmin detected — DA manages its own firewall (CSF/iptables). Skip unless you've removed DA's firewall."
fi

if section_prompt "UFW setup" "$UFW_WARN"; then
  warn "This will RESET all existing UFW rules."
  if confirm "Proceed with UFW reset and reconfigure?"; then
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    if $NONINTERACTIVE; then
      # Non-interactive: open SSH to the world (assumption — tightening manually right after).
      # Both 22 and ${SSH_PORT} so we're reachable before AND after the sshd port change below.
      warn "Non-interactive — opening SSH to the world on 22 and ${SSH_PORT}."
      ufw allow 22/tcp
      ufw allow "${SSH_PORT}/tcp"
      info "SSH open on 22 + ${SSH_PORT}. Lock this down manually."
    else
      # Interactive: whitelist ONLY the IP we're currently connected from, SSH only.
      # SSH_CONNECTION = "<client_ip> <client_port> <server_ip> <server_port>"
      read -r CLIENT_IP _ _ CUR_PORT <<< "${SSH_CONNECTION:-}"
      # Fallback to SSH_CLIENT ("<client_ip> <client_port> <server_port>") if needed
      if [[ -z "$CLIENT_IP" && -n "${SSH_CLIENT:-}" ]]; then
        read -r CLIENT_IP _ _ <<< "$SSH_CLIENT"
        CUR_PORT=""
      fi

      if [[ -n "$CLIENT_IP" ]]; then
        ufw allow from "$CLIENT_IP" to any port "$SSH_PORT" proto tcp
        info "Allowed SSH from current IP: ${CLIENT_IP} → ${SSH_PORT}/tcp"
        # Also allow the port we're actually connected on, if it differs from
        # ${SSH_PORT}. Covers the window before sshd moves to ${SSH_PORT}, and the
        # case where you skip the sshd-hardening section entirely (no lockout).
        if [[ -n "$CUR_PORT" && "$CUR_PORT" != "$SSH_PORT" ]]; then
          ufw allow from "$CLIENT_IP" to any port "$CUR_PORT" proto tcp
          info "Also allowed current session port: ${CLIENT_IP} → ${CUR_PORT}/tcp"
        fi
      else
        warn "Couldn't detect connecting IP (console session, or sudo stripped \$SSH_CONNECTION)."
        warn "Falling back to open SSH on 22 + ${SSH_PORT} to avoid lockout — tighten manually."
        ufw allow 22/tcp
        ufw allow "${SSH_PORT}/tcp"
      fi
    fi

    ufw --force enable
    info "UFW configured."
  else
    info "UFW reset cancelled — skipping rule application."
  fi
fi
echo

# ── 2) Group & user ───────────────────────────────────────────────────────────
if section_prompt "Create group 'ssudo' and user 'Dank' (UID 1337)"; then
  if getent group ssudo &>/dev/null; then
    info "Group 'ssudo' already exists."
  else
    groupadd ssudo && info "Group 'ssudo' created."
  fi

  if id Dank &>/dev/null; then
    warn "User 'Dank' already exists — ensuring group membership."
    usermod -aG ssudo Dank
  else
    useradd -m -s /bin/bash -G ssudo -u 1337 Dank && info "User 'Dank' created (UID 1337)."
  fi
fi
echo

# ── 3) Passwordless sudo ──────────────────────────────────────────────────────
if section_prompt "Passwordless sudo for %ssudo"; then
  SUDOERS_FILE=/etc/sudoers.d/ssudo
  SUDOERS_CONTENT="%ssudo ALL=(ALL) NOPASSWD:ALL"

  if [[ -f "$SUDOERS_FILE" ]] && grep -qxF "$SUDOERS_CONTENT" "$SUDOERS_FILE"; then
    info "Sudoers rule already present — no change."
  else
    echo "$SUDOERS_CONTENT" > "$SUDOERS_FILE"
    chmod 0440 "$SUDOERS_FILE"
    if visudo -cf "$SUDOERS_FILE" &>/dev/null; then
      info "Sudoers rule written and validated."
    else
      error "Sudoers validation failed — removing bad file."
      rm -f "$SUDOERS_FILE"
      exit 1
    fi
  fi
fi
echo

# ── 4) Authorized keys ────────────────────────────────────────────────────────
if section_prompt "Install authorized_keys for Dank"; then
  AUTH_KEYS=/home/Dank/.ssh/authorized_keys
  mkdir -p /home/Dank/.ssh
  touch "$AUTH_KEYS"

  # Key label → pubkey (associative arrays require bash 4+)
  declare -A KEYS=(
    ["Dank@PC"]="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTO/nV3nTWSW3YbwdjAn+5/nJPm00nYQpfD2optMCxy"
    ["Dank@Termius"]="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILXm5cgqL3FiJCsp2fyeN1k9qfwADvalqwB5I/j4M5ap"
    ["Dank@daremote"]="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFbfozDhADu8xmOWLBv9bkEjfn8+JY7oLlltY/DCobsm"
  )

  for label in "${!KEYS[@]}"; do
    pubkey="${KEYS[$label]}"
    if grep -qF "$pubkey" "$AUTH_KEYS"; then
      info "Key already present: $label"
    else
      echo "$pubkey $label" >> "$AUTH_KEYS"
      info "Added key: $label"
    fi
  done

  chmod 600 "$AUTH_KEYS"
  chmod 700 /home/Dank/.ssh
  chown -R Dank:Dank /home/Dank/.ssh
fi
echo

# ── 5) Harden sshd_config ─────────────────────────────────────────────────────
if section_prompt "Harden sshd_config (port ${SSH_PORT}, key-only auth, match blocks)"; then
  SSH_CFG=/etc/ssh/sshd_config

  if [[ ! -f "${SSH_CFG}.orig" ]]; then
    cp "$SSH_CFG" "${SSH_CFG}.orig"
    info "Backup saved to ${SSH_CFG}.orig"
  else
    info "Backup already exists at ${SSH_CFG}.orig"
  fi

  set_sshd Port                          "$SSH_PORT"   "$SSH_CFG"
  set_sshd PermitRootLogin               prohibit-password "$SSH_CFG"
  set_sshd PasswordAuthentication        no            "$SSH_CFG"
  set_sshd ChallengeResponseAuthentication no          "$SSH_CFG"
  set_sshd UsePAM                        yes           "$SSH_CFG"
  set_sshd X11Forwarding                 no            "$SSH_CFG"

  # Match blocks — idempotent check on first block's signature
  if grep -q "Match Address 10.0.0.0/8" "$SSH_CFG"; then
    info "Match blocks already present — skipping."
  else
    cat >> "$SSH_CFG" << 'SSHEOF'

# Whitelisted IPs: allow root + password auth
Match Address 10.0.0.0/8
        PermitRootLogin yes
        PasswordAuthentication yes

SSHEOF
    info "Match blocks appended."
  fi

  # Validate before we do anything destructive
  if sshd -t -f "$SSH_CFG"; then
    info "sshd config validated OK."
  else
    error "sshd config validation FAILED — restoring backup."
    cp "${SSH_CFG}.orig" "$SSH_CFG"
    exit 1
  fi
fi
echo

# ── 6) Restart sshd ───────────────────────────────────────────────────────────
warn "=== SSH restart will take effect immediately ==="
warn "If you're connected remotely, test port ${SSH_PORT} in a NEW terminal before confirming."
if section_prompt "Restart sshd" ""; then
  if ! confirm "Confirmed — restart sshd now?"; then
    warn "Skipping restart. Run manually: systemctl restart sshd"
  else
    if systemctl is-system-running &>/dev/null; then
      systemctl restart sshd && info "sshd restarted via systemctl."
    else
      service ssh restart && info "sshd restarted via service."
    fi
  fi
fi
echo

info "Bootstrap complete."