import argparse
from pathlib import Path
from .assessor import load_records, assess
from .reporting import render


def main():
    p=argparse.ArgumentParser(description="Offline defensive AD delegation posture assessor")
    p.add_argument("evidence")
    p.add_argument("--output")
    args=p.parse_args()
    report=render(assess(load_records(args.evidence)))
    if args.output:
        Path(args.output).parent.mkdir(parents=True,exist_ok=True)
        Path(args.output).write_text(report,encoding="utf-8")
    else: print(report,end="")

if __name__ == "__main__": main()
