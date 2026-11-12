"""Records real lab runs and exports their event logs for the visual demo (demo/replay_data.json)."""
import json
import os
import sys

from hivebreak_lab import Colluder, SEG_RE, run_once, score

SEED = int(sys.argv[1]) if len(sys.argv) > 1 else 3
DURATION = 25


def decode_text(text):
    for seg in SEG_RE.findall(text):
        d = Colluder.dec(seg)
        if isinstance(d, dict):
            return d
    return None


def export(mode):
    lab, variant = run_once(mode, SEED, DURATION)
    roles = dict(lab.roles)
    writers = {}
    out = []
    for e in lab.events:
        k = e["kind"]
        a = e.get("agent")
        if k == "start":
            out.append({"t": e["t"], "k": "start", "a": a})
        elif k == "write":
            writers[e["res"]] = a
            if roles.get(a) == "colluder" or a == "canary":
                out.append({"t": e["t"], "k": "write", "a": a, "res": e["res"], "chan": e["chan"],
                            "text": e["text"], "dec": decode_text(e["text"])})
            else:
                out.append({"t": e["t"], "k": "hwrite", "a": a})
        elif k == "read":
            w = writers.get(e["res"])
            if (roles.get(w) == "colluder" or w == "canary") and a != w and roles.get(a) == "colluder":
                out.append({"t": e["t"], "k": "read", "a": a, "res": e["res"], "from": w})
        elif k == "target":
            out.append({"t": e["t"], "k": "target", "a": a, "ok": e["ok"], "honey": e["honey"]})
        elif k == "alert":
            out.append({"t": e["t"], "k": "alert", "reason": e["reason"], "members": e["members"], "res": e["res"]})
        elif k == "canary":
            out.append({"t": e["t"], "k": "canary"})
    return {"mode": mode, "seed": SEED, "variant": variant, "duration": DURATION,
            "roles": {k: v for k, v in roles.items()}, "events": out,
            "score": score(lab, mode, SEED, variant)}


if __name__ == "__main__":
    os.makedirs("demo", exist_ok=True)
    data = {m: export(m) for m in ("kill", "full")}
    with open("demo/replay_data.json", "w") as f:
        json.dump(data, f)
    for m, d in data.items():
        s = d["score"]
        print(m, len(d["events"]), "events | back:", s["channel_back_after_closure"],
              "| harm:", s["harmful_actions"], "| stopped:", s["colluders_paused"])
