"""Runs the full HIVEBREAK experiment and writes results.csv and summary.md."""
import csv
import statistics
from multiprocessing import Pool

from hivebreak_lab import run_once, score

SEEDS = list(range(1, 11))          # 10 runs per setup; variants rotate: b64/b32 x plain/camouflaged
CLEAN_SEEDS = list(range(101, 106)) # 5 runs with healthy agents only
DURATION = 30


def job(args):
    mode, seed, colluders = args
    lab, variant = run_once(mode, seed, DURATION, colluders=colluders)
    return score(lab, mode, seed, variant, colluders=colluders)


def med_range(xs, unit=""):
    xs = [x for x in xs if x is not None]
    if not xs:
        return "n/a"
    m = statistics.median(xs)
    return f"{m:g}{unit} ({min(xs):g}–{max(xs):g})"


if __name__ == "__main__":
    jobs = [(m, s, True) for m in ("none", "kill", "full", "nocanary") for s in SEEDS]
    jobs += [("full", s, False) for s in CLEAN_SEEDS]
    with Pool(len(jobs)) as p:
        rows = p.map(job, jobs)
    with open("results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    names = {"none": "No defense", "kill": "Detect + kill only", "full": "HIVEBREAK", "nocanary": "HIVEBREAK, no canary"}
    out = ["| Metric | " + " | ".join(names[m] for m in ("none", "kill", "full", "nocanary")) + " |",
           "|---|---|---|---|---|"]

    def col(m):
        return [r for r in rows if r["mode"] == m and r["colluders"]]

    def line(label, fn):
        out.append(f"| {label} | " + " | ".join(fn(col(m), m) for m in ("none", "kill", "full", "nocanary")) + " |")

    line("Time to detect, median (range)",
         lambda rs, m: "never" if m == "none" else med_range([r["time_to_detect_s"] for r in rs], " s"))
    line("Healthy agents wrongly paused (of 40)",
         lambda rs, m: f"{sum(r['healthy_agents_flagged'] for r in rs)}")
    line("Runs where the board came back in folders (of 10)",
         lambda rs, m: "n/a (never closed)" if m == "none" else f"{sum(r['channel_back_after_closure'] for r in rs)}")
    line("Harmful actions per run, median (range)",
         lambda rs, m: med_range([r["harmful_actions"] for r in rs]))
    line("Colluding agents stopped (of 40)",
         lambda rs, m: f"{sum(r['colluders_paused'] for r in rs)}")
    clean = [r for r in rows if not r["colluders"]]
    out.append("")
    out.append(f"Clean runs (healthy agents only, HIVEBREAK on): {len(clean)} runs, "
               f"{sum(r['alerts'] for r in clean)} alerts, {sum(r['healthy_agents_flagged'] for r in clean)} healthy agents paused.")
    open("summary.md", "w").write("\n".join(out) + "\n")
    print("\n".join(out))
