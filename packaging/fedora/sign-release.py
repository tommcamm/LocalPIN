#!/usr/bin/python3
"""Sign one candidate RPM in an ephemeral keyring; never touch the host keyrings."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def primary_fingerprints(listing, secret=True):
    result = []
    primary = False
    for line in listing.splitlines():
        fields = line.split(":")
        if fields[0] in ("sec", "ssb", "pub", "sub"):
            primary = fields[0] == ("sec" if secret else "pub")
        elif fields[0] == "fpr" and primary:
            result.append(fields[9])
            primary = False
    return result


def has_private_signer(listing):
    for line in listing.splitlines():
        fields = line.split(":")
        # GnuPG's lowercase capability belongs to this key, while uppercase S
        # can describe a public-only subkey. '+' means local private material;
        # '#' is a primary/subkey stub and cannot sign in the release runner.
        if len(fields) > 14 and fields[0] in ("sec", "ssb") and "s" in fields[11] and fields[14] == "+":
            return True
    return False


def validate_signing_material(secret_listing, public_listing, fingerprint):
    public_fingerprints = primary_fingerprints(public_listing, secret=False)
    if public_fingerprints != [fingerprint]:
        # Report only canonical public fingerprints, never imported UID text,
        # secret material, the passphrase or raw GnuPG diagnostics.
        observed = ", ".join(value for value in public_fingerprints if re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64})", value)) or "none"
        raise ValueError(f"RPM_SIGNING_FINGERPRINT is {fingerprint}; uploaded primary fingerprint(s): {observed}. Use the full primary fingerprint from the same RPM_SIGNING_KEY export, not a subkey fingerprint.")
    if primary_fingerprints(secret_listing) != [fingerprint] or not has_private_signer(secret_listing):
        raise ValueError(f"RPM_SIGNING_KEY matches primary fingerprint {fingerprint}, but contains no available private signing key. A public-only or stub-only export cannot sign. Create a signing subkey [S], export it with gpg --armor --export-secret-subkeys {fingerprint}, and replace the release environment's RPM_SIGNING_KEY secret. Keep RPM_SIGNING_PASSPHRASE consistent with that subkey.")


def sign(directory):
    key = os.environ.get("LOCALPIN_SIGNING_KEY", "")
    fingerprint = os.environ.get("LOCALPIN_SIGNING_FINGERPRINT", "").upper()
    passphrase = os.environ.get("LOCALPIN_SIGNING_PASSPHRASE", "")
    if not key or not re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64})", fingerprint):
        raise ValueError("signing requires RPM_SIGNING_KEY and the full RPM_SIGNING_FINGERPRINT; refusing unsigned fallback")
    packages = list(directory.glob("*.rpm"))
    if len(packages) != 1 or packages[0].is_symlink():
        raise ValueError("expected one regular candidate RPM")
    env = {k: v for k, v in os.environ.items() if not k.startswith("LOCALPIN_SIGNING_")}
    env["LC_ALL"] = "C"
    with tempfile.TemporaryDirectory(prefix="localpin-release-sign-") as temporary:
        home = Path(temporary)
        env["GNUPGHOME"] = str(home)
        def run(argv, **kwargs):
            return subprocess.run(argv, env=env, check=True, capture_output=True, **kwargs)
        try:
            run(["gpg", "--batch", "--import"], input=key.encode())
            listing = run(["gpg", "--batch", "--with-colons", "--list-secret-keys", "--fingerprint"], text=True).stdout
            if primary_fingerprints(listing) != [fingerprint] or not has_private_signer(listing):
                public_listing = run(["gpg", "--batch", "--with-colons", "--list-keys", "--fingerprint"], text=True).stdout
                validate_signing_material(listing, public_listing, fingerprint)
            passfile = home / "passphrase"
            passfile.write_text(passphrase + "\n")
            passfile.chmod(0o600)
            run(["rpmsign", "--define", "_openpgp_sign gpg", "--define", f"_gpg_path {home}",
                 "--define", f"_openpgp_sign_id {fingerprint}", "--define",
                 f"_gpg_sign_cmd_extra_args --batch --pinentry-mode loopback --passphrase-file {passfile}",
                 "--addsign", str(packages[0])])
            public = directory / "RPM-GPG-KEY-LocalPIN"
            public.write_bytes(run(["gpg", "--batch", "--armor", "--export", fingerprint]).stdout)
            database = home / "rpmdb"
            run(["rpm", "--dbpath", str(database), "--initdb"])
            run(["rpmkeys", "--dbpath", str(database), "--import", str(public)])
            run(["rpmkeys", "--dbpath", str(database), "--define", "_pkgverify_level signature", "--checksig", str(packages[0])])
            manifest = directory / "RELEASE.json"
            data = json.loads(manifest.read_text())
            data["signing"] = {"signed": True, "fingerprint": fingerprint}
            manifest.write_text(json.dumps(data, indent=2) + "\n")
            notes = directory / "RELEASE-NOTES.md"
            notes.write_text(notes.read_text() + f"\nRPM OpenPGP signing fingerprint: `{fingerprint}`. Verify this fingerprint through the maintainer's trusted channel before importing the supplied public key.\n")
            script = Path(__file__).with_name("release-bundle.py")
            run(["python3", str(script), "--finalize", str(directory)])
            run(["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase-file", str(passfile),
                 "--local-user", fingerprint, "--armor", "--detach-sign", str(directory / "SHA256SUMS")])
        finally:
            subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=env, capture_output=True, check=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    sign(args.directory.resolve())
