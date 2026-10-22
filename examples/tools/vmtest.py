#!/usr/bin/env python3
"""
vmtest.py: interactive terminal for testing a device on a real vending machine.

Type commands at the prompt; everything the device publishes is printed as it
arrives (signatures checked). Credit sessions are followed end to end and the
backend decision (CAPTURE / CANCEL) is printed, same rules as session_bench.py.

  credit 5.50     put $5.50 on the machine, then pick a product on the keypad
  info            device snapshot (machine state, heap, uptime, last sale)
  echo            liveness + round-trip time
  dex             trigger a DEX/DDCMP telemetry pull from the VMC
  oos             send MDB "command out of sequence" (unstick the VMC)
  restart         reboot the device
  watch           toggle printing of noisy topics (paxcounter)
  help / quit

A card reader can't pick a slot: MDB only lets it offer credit, and the VMC
vends whatever the customer selects. To test one product, credit its price.

Settings come from flags or env (SUB, PASSKEY, HOST, DOMAIN), falling back to
the dev identity and broker in mdb-slave-esp32s3/sdkconfig when run from the repo.

  python3 examples/tools/vmtest.py
  python3 examples/tools/vmtest.py -s 1 -k <passkey> -H 172.20.10.10

Needs: sudo apt install python3-paho-mqtt
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import sys
import threading
import time
from decimal import Decimal, InvalidOperation

try:
    import readline
except ImportError:   # Windows
    readline = None

import paho.mqtt.client as mqtt

SESSION_MARGIN_S = 15   # backend gives up this long after the device's own session timeout
REPLY_TIMEOUT_S = 5
MACHINE_STATES = ["INACTIVE", "DISABLED", "ENABLED", "IDLE (session open)", "VEND"]
RESET_REASONS = {1: "power-on", 2: "reset pin", 3: "software", 4: "panic", 5: "int watchdog",
                 6: "task watchdog", 7: "watchdog", 9: "brownout", 11: "USB", 14: "power glitch"}   # esp_reset_reason_t


def sign(key, body):
    return hmac.new(key.encode(), body.encode(), hashlib.sha256).hexdigest()


def verify(key, payload):
    """'<fields>:<ts>:<hmac>' -> (fields, ts), or None if the signature is wrong."""
    body, _, sig = payload.rpartition(":")
    if not body or not hmac.compare_digest(sign(key, body), sig):
        return None
    fields, _, ts = body.rpartition(":")
    return fields, int(ts) if ts.isdigit() else 0


def dollars(cents):
    return f"${int(cents) / 100:.2f}"


def sdkconfig_defaults():
    """Dev identity + broker host from the local (git-ignored) sdkconfig, if there is one."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "mdb-slave-esp32s3", "sdkconfig")
    found = {}
    try:
        text = open(path).read()
    except OSError:
        return found
    for key, name in (("sub", "VMFLOW_DEV_SUBDOMAIN"), ("key", "VMFLOW_DEV_PASSKEY"),
                      ("domain", "VMFLOW_TOPIC_DOMAIN"), ("host", "VMFLOW_MQTT_BROKER_URI")):
        m = re.search(rf'^CONFIG_{name}="([^"]*)"', text, re.M)
        if m and m.group(1):
            found[key] = m.group(1)
    if "host" in found:   # mqtt://172.20.10.10[:1883]
        found["host"] = re.sub(r"^\w+://", "", found["host"]).split(":")[0].split("/")[0]
    return found


class Session:
    def __init__(self, sid, cents):
        self.sid, self.cents = sid, cents
        self.vended = None
        self.replied = False
        self.timer = None


class Terminal:
    def __init__(self, args):
        self.args = args
        self.base = f"domain.{args.domain}/{args.sub}"
        self.rpc_topic = f"{args.sub}.{args.domain}/rpc"
        self.sessions = {}
        self.lock = threading.Lock()
        self.watch = False
        self.echo_sent = {}
        self.connected = threading.Event()
        self.quitting = False

    # ---- output ---------------------------------------------------------

    def say(self, text):
        """Print above the prompt without mangling what the user is typing."""
        stamp = time.strftime("%H:%M:%S")
        with self.lock:
            line = readline.get_line_buffer() if readline else ""
            sys.stdout.write(f"\r\033[K{stamp}  {text}\n> {line}")
            sys.stdout.flush()

    # ---- MQTT -----------------------------------------------------------

    def on_connect(self, client, *_):
        client.subscribe(f"{self.base}/#", qos=1)
        self.connected.set()

    def on_disconnect(self, *_):
        if not self.quitting:
                self.say("!! lost connection to the broker (paho will retry)")

    def send(self, cmd, arg="-", ts=None):
        body = f"{cmd}:{arg}:{ts or int(time.time())}"
        self.client.publish(self.rpc_topic, f"{body}:{sign(self.args.key, body)}", qos=1)

    def on_message(self, client, userdata, msg):
        topic = msg.topic[len(self.base) + 1:]
        payload = msg.payload.decode(errors="replace")
        try:
            self.handle(topic, payload)
        except Exception as e:   # never let a bad message kill the MQTT thread
            self.say(f"!! could not parse {topic}: {payload!r} ({e})")

    def handle(self, topic, payload):
        if topic == "status":
            state, _, reason = payload.partition(",")
            why = RESET_REASONS.get(int(reason), f"reason {reason}") if reason.isdigit() else ""
            self.say(f"device {state}" + (f" (last reset: {why})" if why else ""))
        elif topic == "rpc/info":
            self.show_info(json.loads(payload))
        elif topic == "rpc/echo":
            sent = self.echo_sent.pop(payload, None)
            rtt = f"{(time.monotonic() - sent) * 1000:.0f} ms round trip" if sent else "reply"
            self.say(f"echo: device alive, {rtt}")
        elif topic == "rpc/confirm":
            self.say(f"device confirmed: {payload}")
        elif topic == "paxcounter":
            if self.watch:
                self.say(f"paxcounter {payload}")
        elif topic in ("rpc/credit", "session", "sale", "vend_fail"):
            checked = verify(self.args.key, payload)
            if checked is None:
                self.say(f"!! {topic} with BAD SIGNATURE ignored: {payload}")
                return
            fields, ts = checked
            if abs(time.time() - ts) > 30:
                self.say(f"!! {topic} is {int(time.time() - ts)}s old (device clock or replay?)")
            {"rpc/credit": self.on_credit, "session": self.on_session,
             "sale": self.on_sale, "vend_fail": self.on_vend_fail}[topic](fields)
        else:
            self.say(f"{topic}: {payload}")

    def on_credit(self, fields):
        verdict, sid, *rest = fields.split(",")
        s = self.sessions.get(sid)
        if s:
            s.replied = True
        if verdict == "accepted":
            self.say(f"credit {sid} accepted, waiting for the machine to open the session")
        else:
            reason = rest[0] if rest else "?"
            hint = {"not_ready": "machine not enabled (LED green?) or session already open",
                    "busy": "another credit is still queued",
                    "duplicate": "session id reused",
                    "bad_amount": "amount not representable in MDB units"}.get(reason, "")
            self.say(f"credit {sid} REJECTED: {reason}" + (f" ({hint})" if hint else ""))
            self.finish(sid, "CANCEL authorization", f"device rejected: {reason}")

    def on_session(self, fields):
        sid, event, *rest = fields.split(",")
        s = self.sessions.get(sid)
        if event == "begin":
            self.say(f"session {sid}: machine shows {dollars(rest[0])}, pick a product now")
        elif event == "vend_ok":
            if s:
                s.vended = int(rest[0])
            self.say(f"session {sid}: VEND OK, item {rest[1]} for {dollars(rest[0])}")
        elif event == "vend_fail":
            self.say(f"session {sid}: VEND FAILED, item {rest[1]} ({dollars(rest[0])}), nothing dropped")
        elif event == "end":
            reason = rest[0] if rest else "?"
            self.say(f"session {sid}: ended ({reason})")
            if s and s.vended is not None:
                left = s.cents - s.vended
                self.finish(sid, f"CAPTURE {dollars(s.vended)}",
                            f"{dollars(left)} of the hold released" if left > 0 else "full amount")
            else:
                self.finish(sid, "CANCEL authorization", f"nothing vended ({reason})")
        else:
            self.say(f"session {sid}: {event} {','.join(rest)}")

    def on_sale(self, fields):
        price, _, item = fields.partition(":")
        self.say(f"cash sale reported by VMC: item {item} for {dollars(price)}")

    def on_vend_fail(self, fields):
        price, _, item = fields.partition(",")
        self.say(f"vend failure reported: item {item} (MDB price units {price})")

    def finish(self, sid, action, why):
        s = self.sessions.pop(sid, None)
        if s is None:
            return
        if s.timer:
            s.timer.cancel()
        self.say(f"==> BACKEND: {action}  ({why})")

    def show_info(self, d):
        state = d.get("machine_state")
        name = MACHINE_STATES[state] if isinstance(state, int) and 0 <= state < len(MACHINE_STATES) else state
        last = d.get("last_vend_success_time") or 0
        lines = [
            f"firmware {d.get('version')}, up {d.get('uptime_s', 0) // 60} min, ip {d.get('ip_wifi') or d.get('ip_ppp') or '-'}",
            f"machine state: {name}",
            f"heap free {d.get('free_heap')} (lowest {d.get('min_free_heap')})",
            f"last sale: " + (f"item {d.get('last_sale_item')} raw price {d.get('last_sale_price')} at "
                              f"{time.strftime('%H:%M:%S', time.localtime(last))}" if last else "none since boot"),
        ]
        self.say("info:\n    " + "\n    ".join(lines))

    # ---- commands -------------------------------------------------------

    def cmd_credit(self, argv):
        if not argv:
            self.say("usage: credit <dollars>   e.g. credit 5.50")
            return
        try:
            cents = int(Decimal(argv[0].lstrip("$")) * 100)
        except InvalidOperation:
            self.say(f"not an amount: {argv[0]}")
            return
        if cents <= 0 or cents >= 65535:
            self.say("amount must be between $0.01 and $655.34")
            return
        sid = secrets.token_hex(4)
        s = self.sessions[sid] = Session(sid, cents)
        s.timer = threading.Timer(self.args.session_timeout + SESSION_MARGIN_S, self.finish,
                                  [sid, "CANCEL authorization", "backend timer expired, no end event"])
        s.timer.daemon = True
        s.timer.start()
        check = threading.Timer(REPLY_TIMEOUT_S, self.check_reply, [sid])
        check.daemon = True
        check.start()
        self.send("credit", f"{cents},{sid}")
        self.say(f"-> credit {dollars(cents)}, session {sid}")

    def check_reply(self, sid):
        s = self.sessions.get(sid)
        if s and not s.replied:
            self.finish(sid, "CANCEL authorization", f"no answer in {REPLY_TIMEOUT_S}s, device offline?")

    def cmd_echo(self, argv):
        ts = int(time.time())
        self.echo_sent[str(ts)] = time.monotonic()
        self.send("echo", ts=ts)

    def simple(name, note):
        def run(self, argv):
            self.send(name)
            self.say(f"-> {name}" + (f" ({note})" if note else ""))
        return run

    cmd_info = simple("info", "")
    cmd_dex = simple("dex", "needs a DEX cable on GPIO8/9; the mdb-slave board has no DEX port, so expect no reply")
    cmd_oos = simple("oos", "sent on the next VMC poll")
    cmd_restart = simple("restart", "device reboots, expect offline then online")
    del simple

    def cmd_watch(self, argv):
        self.watch = not self.watch
        self.say(f"watching noisy topics: {'on' if self.watch else 'off'}")

    def cmd_help(self, argv):
        print(__doc__.split("\n\n")[2])

    def run(self):
        try:
            self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)   # paho-mqtt 2.x
        except AttributeError:
            self.client = mqtt.Client()                                   # paho-mqtt 1.x
        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect
        self.client.on_message = self.on_message
        try:
            self.client.connect(self.args.host, self.args.port, keepalive=30)
        except OSError as e:
            sys.exit(f"cannot reach broker {self.args.host}:{self.args.port}: {e} (laptop on the hotspot?)")
        self.client.loop_start()
        if not self.connected.wait(5):
            sys.exit(f"no MQTT connection to {self.args.host}")

        print(f"vmtest: device {self.args.sub} via {self.args.host}. Type 'help' for commands, 'quit' to exit.")
        self.send("info")
        while True:
            try:
                line = input("> ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            argv = shlex.split(line)
            if not argv:
                continue
            if argv[0] in ("quit", "exit", "q"):
                break
            fn = getattr(self, "cmd_" + argv[0].lower(), None)
            if fn:
                fn(argv[1:])
            else:
                self.say(f"unknown command '{argv[0]}', type 'help'")
        if self.sessions:
            print(f"note: {len(self.sessions)} session(s) still open, nothing captured or cancelled by this tool")
        self.quitting = True
        self.client.disconnect()
        self.client.loop_stop()


def main():
    dev = sdkconfig_defaults()
    env = os.environ.get
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("-s", "--sub", default=env("SUB", dev.get("sub")), help="device subdomain/ID (env SUB)")
    p.add_argument("-k", "--key", default=env("PASSKEY", dev.get("key")), help="device passkey (env PASSKEY)")
    p.add_argument("-H", "--host", default=env("HOST", dev.get("host", "localhost")), help="broker host (env HOST)")
    p.add_argument("-p", "--port", type=int, default=1883)
    p.add_argument("-d", "--domain", default=env("DOMAIN", dev.get("domain", "vmflow.xyz")), help="topic domain (env DOMAIN)")
    p.add_argument("--session-timeout", type=int, default=60, help="device's CONFIG_VMFLOW_SESSION_TIMEOUT_S")
    args = p.parse_args()
    if not args.sub or not args.key:
        p.error("set SUB and PASSKEY (or pass -s and -k)")
    Terminal(args).run()


if __name__ == "__main__":
    sys.exit(main())
