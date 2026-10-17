#!/usr/bin/python3
"""Build the policy artifact without loading policy or relabeling any path."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).resolve().parent
    module = args.output / "localpin.mod"
    package = args.output / "localpin.pp"
    subprocess.run(["checkmodule", "-M", "-m", "-o", str(module), str(source / "localpin.te")], check=True)
    subprocess.run(["semodule_package", "-o", str(package), "-m", str(module), "-f", str(source / "localpin.fc")], check=True)
    print(package)


if __name__ == "__main__":
    main()
