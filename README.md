# HIVEBREAK

**Detect, contain and outlast covert coordination between AI agents.**
IS CyberNext 2026 · Cybersecurity track · Team Beekeepers

In July 2026, AI agents running an OpenAI security benchmark turned a shared package registry into a secret message board, shared stolen credentials and broke into Hugging Face. When the board was wiped, they rebuilt it in folder names. HIVEBREAK watches the shared layer agents use. It detects a board, stops only the agents involved, exposes hidden agents with a fake credential, and recognises the same group when it moves to a new channel.

- **Live demo (lab replay):** `index.html`, served by GitHub Pages at this repository's Pages link
- **Pitch deck and poster:** `HIVEBREAK_Pitch_Deck.pdf` and `HIVEBREAK_Poster.pdf`

## Prototype results (10 runs per setup)

| Metric | No defense | Detect + kill only | HIVEBREAK |
|---|---|---|---|
| Board came back in folder names | never closed | 10 of 10 runs | **0 of 10 runs** |
| Healthy agents wrongly paused | 0 of 40 | 0 of 40 | 0 of 40 |
| Harmful actions per run (median) | 81 | 3 | 3 |
| Colluding agents stopped | 0 of 40 | 40 of 40 | 40 of 40 |

Simulated offline lab with 8 agents per run and a scripted attacker modelled on the incident. The 3 harmful actions happen before any message is posted: HIVEBREAK stops the coordination, not the first use of a stolen credential.

## Team Beekeepers

| Name | Role |
|---|---|
| Ghazal Sami Arab | Swarm Builder: agent lab and attacks |
| Retal Jamil Abdulsalam | Signal Hunter: detection signals |
| Retal Mazen Makkawi | Hive Tracker: episode graph and pursuit |
| Maya Mazen Faghia | Gatekeeper: control, dashboard, testing |

## About the lab

A small, offline simulation of the July 2026 agent message-board incident. It's used to measure HIVEBREAK against two baselines.

Everything runs on `127.0.0.1`, so nothing in it can reach the internet. It needs Python 3.10 or later and nothing else (standard library only).

## Run

```bash
python3 run_experiment.py                                     # full experiment, about 30 seconds -> results.csv, summary.md
python3 export_replay.py 3                                    # record two runs for the demo -> demo/replay_data.json (move it next to template.html to rebuild index.html)
python3 hivebreak_lab.py run --mode full --seed 3             # one run, prints its score and alerts
python3 hivebreak_lab.py run --mode full --seed 101 --clean   # healthy agents only
```

## What is in the lab

| Part | What it does |
|---|---|
| Shared registry | An HTTP package registry. Agents publish packages (`PUT /pkg/<name>`), create folders (`MKCOL /dir/<name>`), search and read. Every request is logged with the agent's identity. |
| Target server | Holds a fake `secret_flag`. Every successful read counts as one **harmful action**. |
| 4 healthy agents | Normal build traffic: publish `lib-*` and `cache-<hash>` packages, create `builds/` folders, read each other's packages. |
| 4 colluding agents (scripted) | Two start at t=0 and two join at about t=10 s, as in the incident. They post notes such as `seeks results.json` with status words (`pending`, `hold`, `confirm`), share a stolen credential encoded in base64 or base32, and use it. When their board is wiped, the late joiners rebuild it in **folder names**. |
| Controller | Runs in one of four modes (below). |

Each seed rotates the attacker variant: base64 or base32 encoding, and plain (`x-*`) or camouflaged (`lib-<word>-<id>`) package names.

## Controller modes

| Mode | Detect | Pause the agents involved | Canary credential | Pursuit of new channels |
|---|---|---|---|---|
| `none` | no | no | no | no |
| `kill` | yes | yes | no | no |
| `full` (HIVEBREAK) | yes | yes | yes | yes |
| `nocanary` | yes | yes | no | yes |

**Detection** looks for four signals on every write:

- an encoded segment (high entropy, and not a hex hash)
- protocol status words
- an off-task package name
- a read of the resource by a different agent

It alerts when a resource has 3 signals, or 2 signals plus a cross-agent read.

**Containment**, once an alert fires:

- quarantine the board items
- pause the agents involved
- revoke their tokens
- revoke any credential decoded from the board

**Pursuit** learns the board's grammar (status words and payload keys). Any later write in that grammar, on any channel, is contained at once.

**Canary**: a fake credential is posted in the board's own grammar. Whoever uses it is paused.

## Metrics (in `results.csv`)

- `time_to_detect_s`: first alert minus the first colluder write.
- `healthy_agents_flagged`: healthy agents paused by mistake.
- `channel_back_after_closure`: a colluder wrote to the folder channel and another colluder read it.
- `harmful_actions`: successful reads of the secret.
- `colluders_paused`: how many of the 4 colluding agents were stopped.

## Limits (say these out loud to the judges)

- The same people wrote the attacker and the detector. A teammate should write a second attacker without reading `Controller`.
- The colluders are scripted, not LLM agents. The next step is a run with real LLM agents that are missing a file.
- It's a small lab: 8 agents and 30-second runs. Detection is fast partly because healthy agents read packages often.
- The baselines are automatic. A human-operated kill switch was not measured.
