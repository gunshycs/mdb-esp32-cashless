#!/usr/bin/env python3
"""
session_bench.py: act as the payment backend for one tap-to-pay session.

Sends a signed "credit:<cents>,<sid>" to a device, verifies every reply and
session event it publishes, and prints what a real backend would do with the
customer's card authorization: CAPTURE the vended price or CANCEL.

  credit reply   domain.<domain>/<sub>/rpc/credit  accepted,<sid> | rejected,<sid>,<reason>
  session events domain.<domain>/<sub>/session     <sid>,begin,<cents>
                                                   <sid>,vend_ok,<cents>,<item>
                                                   <sid>,vend_fail,<cents>,<item>
                                                   <sid>,end,<completed|timeout|aborted|expired>
  (every message ends with ":<ts>:<hmac>", HMAC-SHA256(passkey, everything before the last ':'))

Usage (SUB / PASSKEY / HOST env vars work too, same as rpc.sh):
  python3 session_bench.py -s 1 -k <passkey> -a 150     # $1.50 session
  python3 session_bench.py --watch                       # only print verified events

Needs: sudo apt install python3-paho-mqtt
"""

import argparse
import hashlib
import hmac
import os
import secrets
import sys
import threading
import time

import paho.mqtt.client as mqtt

REPLY_TIMEOUT_S = 5     # no accept/reject by then -> device offline
SESSION_MARGIN_S = 15   # wait this much past the device's session timeout


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


class Bench:
    def __init__(self, args):
        self.args = args
        self.sid = secrets.token_hex(4)
        self.base = f"domain.{args.domain}/{args.sub}"
        self.t0 = time.monotonic()
        self.done = threading.Event()
        self.replied = threading.Event()
        self.vended_cents = None

    def log(self, text):
        print(f"[{time.monotonic() - self.t0:6.2f}s] {text}", flush=True)

    def decide(self, action, why):
        self.log(f"==> BACKEND: {action}  ({why})")
        self.done.set()

    def on_connect(self, client, *_):
        client.subscribe(f"{self.base}/rpc/credit", qos=1)
        client.subscribe(f"{self.base}/session", qos=1)
        client.subscribe(f"{self.base}/status", qos=1)
        self.log(f"connected to {self.args.host}, watching {self.base}/...")
        if not self.args.watch:
            threading.Timer(0.3, self.send_credit, [client]).start()

    def send_credit(self, client):
        body = f"credit:{self.args.amount},{self.sid}:{int(time.time())}"
        client.publish(f"{self.args.sub}.{self.args.domain}/rpc", f"{body}:{sign(self.args.key, body)}", qos=1)
        self.log(f"-> credit {dollars(self.args.amount)} session {self.sid} (customer's card authorized for this)")

    def on_message(self, client, userdata, msg):
        payload = msg.payload.decode(errors="replace")
        topic = msg.topic[len(self.base) + 1:]

        if topic == "status":   # retained, unsigned
            self.log(f"<- status {payload}")
            return

        checked = verify(self.args.key, payload)
        if checked is None:
            self.log(f"<- {topic} {payload}   !! BAD SIGNATURE, ignored")
            return
        fields, ts = checked
        age = int(time.time()) - ts
        stale = f"   (!! {age}s old)" if abs(age) > 30 else ""
        self.log(f"<- {topic} {fields}   (signature OK){stale}")

        parts = fields.split(",")
        if self.args.watch or len(parts) < 2 or parts[1 if topic == "rpc/credit" else 0] != self.sid:
            return

        if topic == "rpc/credit":
            self.replied.set()
            if parts[0] == "rejected":
                self.decide("CANCEL authorization", f"device rejected: {parts[2] if len(parts) > 2 else '?'}")
            return

        event = parts[1]
        if event == "vend_ok":
            self.vended_cents = int(parts[2])
            self.log(f"   product {parts[3]} dropped for {dollars(parts[2])}")
        elif event == "vend_fail":
            self.log(f"   vend failed for product {parts[3]}")
        elif event == "end":
            if self.vended_cents is not None:
                rest = self.args.amount - self.vended_cents
                self.decide(f"CAPTURE {dollars(self.vended_cents)}",
                            f"session {parts[2]}" + (f", {dollars(rest)} of the hold released" if rest > 0 else ""))
            else:
                self.decide("CANCEL authorization", f"session ended '{parts[2]}' with nothing vended")

    def run(self):
        try:
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)   # paho-mqtt 2.x
        except AttributeError:
            client = mqtt.Client()                                   # paho-mqtt 1.x
        client.on_connect = self.on_connect
        client.on_message = self.on_message
        client.connect(self.args.host, self.args.port)
        client.loop_start()

        try:
            if self.args.watch:
                self.done.wait()
            elif not self.replied.wait(REPLY_TIMEOUT_S + 0.3) and not self.done.is_set():
                self.decide("CANCEL authorization", f"no answer from device in {REPLY_TIMEOUT_S}s (offline?)")
            elif not self.done.wait(self.args.session_timeout + SESSION_MARGIN_S):
                self.decide("CANCEL authorization", "backend timer expired, no end event from device")
        except KeyboardInterrupt:
            pass
        client.loop_stop()
        client.disconnect()


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("-s", "--sub", default=os.environ.get("SUB"), help="device subdomain/ID (env SUB)")
    p.add_argument("-k", "--key", default=os.environ.get("PASSKEY"), help="device passkey (env PASSKEY)")
    p.add_argument("-H", "--host", default=os.environ.get("HOST", "localhost"), help="broker host (env HOST)")
    p.add_argument("-p", "--port", type=int, default=1883)
    p.add_argument("-d", "--domain", default=os.environ.get("DOMAIN", "vmflow.xyz"), help="topic domain (env DOMAIN)")
    p.add_argument("-a", "--amount", type=int, default=150, help="credit in cents (default 150 = $1.50)")
    p.add_argument("--session-timeout", type=int, default=60, help="device's CONFIG_VMFLOW_SESSION_TIMEOUT_S")
    p.add_argument("--watch", action="store_true", help="send nothing, just print verified events")
    args = p.parse_args()

    if not args.sub or not args.key:
        p.error("set SUB and PASSKEY (or pass -s and -k)")
    Bench(args).run()


if __name__ == "__main__":
    sys.exit(main())
