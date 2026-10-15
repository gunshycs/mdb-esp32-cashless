#!/usr/bin/env bash
#
# rpc.sh — send a signed RPC command to a VMflow mdb-slave device over MQTT.
#
# Envelope: "<cmd>:<args>:<ts>:<hmac>"  hmac = HMAC-SHA256(passkey, "<cmd>:<args>:<ts>")
# Topic:    <sub>.<domain>/rpc          Reply: domain.<domain>/<sub>/rpc/<cmd>
# Commands with no parameter use "-" as <args>.
#
# Every command publishes to domain.<domain>/<sub>/rpc/* on completion.
# <domain> is DOMAIN (default vmflow.xyz) and must match CONFIG_VMFLOW_TOPIC_DOMAIN.
# -w subscribes to rpc/# and captures the first reply regardless of subtopic.
#
# Usage:
#   SUB=51 PASSKEY=af6c51a556fd71b345 ./rpc.sh info
#   ./rpc.sh -s 51 -k af6c51a556fd71b345 dex
#   ./rpc.sh -s 51 -k <key> -a 100 credit     # -a: command parameter (<args>)
#   ./rpc.sh -s 51 -k <key> -w info           # -w: also wait for the reply
#   ./rpc.sh -H 192.168.1.50 -d mybrand.io -s 51 -k <key> info   # own broker/domain
#   ./rpc.sh -s 51 -k <key> -a v1.3.6 ota    # OTA to pinned tag
#
# Commands: dex info oos buzzer echo restart credit ota
#
# Broker auth/TLS: pass through extra mosquitto flags after `--`, e.g.
#   ./rpc.sh -s 51 -k <key> info -- -u user -P pass
#   ./rpc.sh -s 51 -k <key> info -- -p 8883 --cafile ca.pem

set -euo pipefail

SUB="${SUB:-}"
PASSKEY="${PASSKEY:-}"
HOST="${HOST:-}"
DOMAIN="${DOMAIN:-vmflow.xyz}"
ARGS="-"
WAIT=0

usage() { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; s/^#//'; exit "${1:-0}"; }

while getopts ":s:k:H:d:a:wh" opt; do
  case "$opt" in
    s) SUB="$OPTARG" ;;
    k) PASSKEY="$OPTARG" ;;
    H) HOST="$OPTARG" ;;
    d) DOMAIN="$OPTARG" ;;
    a) ARGS="$OPTARG" ;;
    w) WAIT=1 ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done
shift $((OPTIND - 1))

CMD="${1:-}"
[ -n "$CMD" ] || { echo "error: missing command" >&2; usage 1; }
shift || true

# Anything after the command (or after `--`) is passed straight to mosquitto.
EXTRA=("$@")

[ -n "$SUB" ]     || { echo "error: set SUB or pass -s <subdomain>" >&2; exit 1; }
[ -n "$PASSKEY" ] || { echo "error: set PASSKEY or pass -k <passkey>" >&2; exit 1; }
[ -n "$ARGS" ]    || { echo "error: -a <args> must be non-empty (use '-' for none)" >&2; exit 1; }
HOST="${HOST:-mqtt.$DOMAIN}"    # broker host; <sub>.<domain> is the device topic, not a host

TS="$(date +%s)"                 # UTC epoch — fresh (device enforces a 10s window)
MSG="$CMD:$ARGS:$TS"
SIG="$(printf '%s' "$MSG" | openssl dgst -sha256 -hmac "$PASSKEY" -hex | awk '{print $NF}')"
PAYLOAD="$MSG:$SIG"

REPLY_TOPIC="domain.$DOMAIN/$SUB/rpc/#"

if [ "$WAIT" -eq 1 ]; then
  # Subscribe to the reply first so we don't miss it, then publish.
  mosquitto_sub -h "$HOST" -t "$REPLY_TOPIC" -C 1 -W 15 "${EXTRA[@]}" &
  SUB_PID=$!
  sleep 0.3
fi

echo "-> $HOST  $SUB.$DOMAIN/rpc  '$PAYLOAD'" >&2
mosquitto_pub -h "$HOST" -t "$SUB.$DOMAIN/rpc" -m "$PAYLOAD" -q 1 "${EXTRA[@]}"

if [ "$WAIT" -eq 1 ]; then
  echo "<- waiting on $REPLY_TOPIC (15s)" >&2
  wait "$SUB_PID"
fi
