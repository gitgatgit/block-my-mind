#!/usr/bin/env python3
"""ADB app freeze helper.

Only third-party apps (pm list packages -3).
Built-in camera, phone, and settings are never touched.

freeze skips whitelist.txt. Apps are grayed out with package suspend.
Disabled or suspended apps stay off after unplug.
Individual thaw is recorded until the next freeze; `keep` adds those to the whitelist.
`keep --now` adds apps that are currently thawed on the phone.
`freeze PACKAGE` grays one app; a named freeze still runs if that app is whitelisted.
`freeze social` / `thaw social` use categories.txt; `categories` lists them.

Work profile, Dual App, and Secure Folder often refuse ADB. Those
users are skipped; freeze success is the profiles the shell can control.

Not a screen-time lock. Settings / Safe Mode can still undo it.
Default launcher, device-admin, and some OEM apps cannot be blocked.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SAVE = HERE / "frozen_packages.txt"
FAILS = HERE / "freeze_failed.txt"
WHITELIST = HERE / "whitelist.txt"
THAWED = HERE / "thawed.txt"
CATEGORIES = HERE / "categories.txt"

DEFAULT_WHITELIST = """\
# substring match, case-insensitive. one pattern per line.
# built-in apps are already left alone.
whatsapp
gmail
com.google.android.gm
outlook
com.microsoft.office.outlook
com.android.email
samsung.android.email
yahoo.mobile.client.android.mail
proton.android.mail
com.fsck.k9
org.kman.AquaMail
com.readdle.spark
fair.email
googlecamera
com.google.android.GoogleCamera
sec.android.app.camera
"""

DEFAULT_CATEGORIES = """\
# [name] then one substring pattern per line, case-insensitive.
# freeze social / thaw social / categories
# edit this file to add apps or whole groups.

[social]
facebook
instagram
twitter
musically
tiktok
discord
linkedin
telegram
securesms
viber
whatsapp
snapchat
barcelona
reddit
twitch
rumble
skool
substack
quora
patreon
orca

[games]
mahjong
juggle
puzzle
.games
xbox
roblox
minecraft
steam
sudoku
solitaire

[shopping]
amazon
ebay
walmart
mercadolibre
shopify
iherb
soriana
aliexpress
shein
temu

[media]
youtube
spotify
soundcloud
audible
kindle
shazam
twitch
netflix
disney
videos

[ai]
chatgpt
openai
anthropic
claude
grok
mistral
perplexity
deepseek
talkpal
praktika
lumo
googleassistant
gpai

[finance]
revolut
paypal
kraken
okex
mercadopago
santander
transferwise
wallet
burodecredito
zapptax
weiss.ratings
invest
binance
coinbase
codi

[travel]
booking
ryanair
skyscanner
uber
didi
indriver
waze
rappi
dhl
postnord
airbnb
cheapflights

[learning]
preply
superprof
tutored
languatalk
birlingo
picoai
kelime
brilliant
edtech
translate
duolingo
memoryos
praktika
talkpal

[news]
lemonde
berlingske
mint
zetland
nordjyske
wikipedia
substack
ereolen
"""


def adb(*args: str) -> str:
    r = subprocess.run(["adb", *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(r.stderr.strip() or f"adb failed: {' '.join(('adb',) + args)}")
    return r.stdout.strip()


def require_device() -> None:
    if not device_ready():
        raise SystemExit("No ADB device. Enable debugging and run: adb devices")


def device_ready() -> bool:
    r = subprocess.run(["adb", "devices"], capture_output=True, text=True)
    if r.returncode != 0:
        return False
    return any(l.strip() and "\tdevice" in l for l in r.stdout.splitlines()[1:])


def ensure_whitelist() -> None:
    if not WHITELIST.exists():
        WHITELIST.write_text(DEFAULT_WHITELIST)


def patterns() -> list[str]:
    ensure_whitelist()
    out = []
    for line in WHITELIST.read_text().splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            out.append(line)
    return out


def kept(pkg: str, pats: list[str]) -> bool:
    name = pkg.lower()
    return any(p in name for p in pats)


_USERS: list[str] | None = None


def users() -> list[str]:
    global _USERS
    if _USERS is None:
        out = adb("shell", "pm", "list", "users")
        found = []
        for line in out.splitlines():
            if "UserInfo{" not in line:
                continue
            try:
                found.append(line.split("UserInfo{", 1)[1].split(":", 1)[0])
            except IndexError:
                continue
        _USERS = found or ["0"]
    return _USERS


def sh(*args: str) -> tuple[int, str]:
    r = subprocess.run(["adb", "shell", *args], capture_output=True, text=True)
    return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()


def denied(text: str) -> bool:
    t = text.lower()
    return (
        "does not have permission to access user" in t
        or "does not belong to calling uid" in t
    )


def third_party() -> list[str]:
    seen: list[str] = []
    for user in users():
        _, out = sh("pm", "list", "packages", "--user", user, "-3")
        if denied(out):
            continue
        for line in out.splitlines():
            if line.startswith("package:"):
                pkg = line.replace("package:", "", 1).strip()
                if pkg and pkg not in seen:
                    seen.append(pkg)
    return sorted(seen)


def user_states(pkg: str) -> dict[str, str]:
    """Map user id -> dumpsys 'User N: ... installed= ... suspended= ... enabled=' line."""
    _, text = sh("dumpsys", "package", pkg)
    found: dict[str, str] = {}
    for raw in text.splitlines():
        line = " ".join(raw.split())
        if "installed=" not in line or "suspended=" not in line or "enabled=" not in line:
            continue
        if "User " not in line or ":" not in line:
            continue
        try:
            uid = line.split("User ", 1)[1].split(":", 1)[0]
        except IndexError:
            continue
        if uid.isdigit():
            found[uid] = line
    return found


def is_blocked(line: str) -> bool:
    return (
        "enabled=2" in line
        or "enabled=3" in line
        or "enabled=4" in line
        or "suspended=true" in line
    )


def _installed(line: str) -> bool:
    return "installed=true" in line


def _suspended(line: str) -> bool:
    return "suspended=true" in line


def _disabled(line: str) -> bool:
    return "enabled=2" in line or "enabled=3" in line or "enabled=4" in line


def block_one(pkg: str) -> str:
    notes = []
    grayed = 0
    failed = 0
    states = user_states(pkg)
    for user in users():
        line = states.get(user, "")
        if line and not _installed(line):
            continue
        if _suspended(line):
            notes.append(f"u{user} gray")
            grayed += 1
            continue
        if _disabled(line):
            sh("pm", "enable", "--user", user, pkg)
        _, msg = sh("cmd", "package", "suspend", "--user", user, pkg)
        if denied(msg):
            notes.append(f"u{user} no-access")
            continue
        line = user_states(pkg).get(user, "")
        if _suspended(line) or "new suspended state: true" in msg.lower():
            notes.append(f"u{user} gray")
            grayed += 1
            continue
        failed += 1
        notes.append(f"u{user} FAILED")
    if not notes:
        return "FAILED not installed"
    prefix = "gray" if failed == 0 and grayed else "FAILED"
    return prefix + " " + ", ".join(notes)


def unblock_one(pkg: str) -> str:
    notes = []
    states = user_states(pkg)
    for user in users():
        line = states.get(user, "")
        if line and not _installed(line):
            continue
        _, msg = sh("cmd", "package", "unsuspend", "--user", user, pkg)
        if denied(msg):
            notes.append(f"u{user} no-access")
            continue
        sh("pm", "enable", "--user", user, pkg)
        line = user_states(pkg).get(user, "")
        if not _suspended(line) or "new suspended state: false" in msg.lower():
            notes.append(f"u{user} on")
        else:
            notes.append(f"u{user} FAILED")
    return "; ".join(notes) or "not installed"


def split_keep(pkgs: list[str]) -> tuple[list[str], list[str]]:
    pats = patterns()
    stay = [p for p in pkgs if kept(p, pats)]
    kill = [p for p in pkgs if p not in stay]
    return kill, stay


def ensure_categories() -> None:
    if not CATEGORIES.exists():
        CATEGORIES.write_text(DEFAULT_CATEGORIES)


def load_categories() -> dict[str, list[str]]:
    ensure_categories()
    cats: dict[str, list[str]] = {}
    current: str | None = None
    for line in CATEGORIES.read_text().splitlines():
        raw = line.split("#", 1)[0].strip()
        if not raw:
            continue
        if raw.startswith("[") and raw.endswith("]"):
            current = raw[1:-1].strip().lower()
            cats.setdefault(current, [])
            continue
        if current:
            cats[current].append(raw.lower())
    return {k: v for k, v in cats.items() if v}


def match_category(catalog: list[str], pats: list[str]) -> list[str]:
    out = []
    for p in catalog:
        name = p.lower()
        if any(pat in name for pat in pats):
            out.append(p)
    return out


def expand_targets(
    needles: list[str],
    catalog: list[str],
    empty: str,
    apply_whitelist: bool,
) -> tuple[list[str], list[str]]:
    cats = load_categories()
    wl = patterns() if apply_whitelist else []
    out: list[str] = []
    stay: list[str] = []
    used_cat = False
    for needle in needles:
        key = needle.lower()
        if key in cats:
            used_cat = True
            hits = match_category(catalog, cats[key])
            if not hits:
                print(f"category {key}: no matching apps")
                continue
            print(f"category {key}: {len(hits)} apps")
            for p in hits:
                if apply_whitelist and kept(p, wl):
                    if p not in stay:
                        stay.append(p)
                    continue
                if p not in out:
                    out.append(p)
            continue
        p = resolve_pkg(needle, catalog, empty)
        if p not in out:
            out.append(p)
    if not out:
        if stay:
            raise SystemExit("Nothing to freeze. Everything matched the whitelist.")
        if used_cat:
            names = ", ".join(sorted(cats))
            raise SystemExit(f"No apps in those categories. Have: {names}")
        raise SystemExit(empty)
    return out, stay


def freeze(use_whitelist: bool, packages: list[str] | None = None) -> None:
    pkgs = third_party()
    if not pkgs:
        raise SystemExit("No third-party apps found.")
    full = not packages
    if packages:
        catalog: list[str] = []
        for p in pkgs + recorded() + load_lines(THAWED):
            if p not in catalog:
                catalog.append(p)
        kill, stay = expand_targets(
            packages,
            catalog,
            "No app matching",
            apply_whitelist=use_whitelist,
        )
    elif use_whitelist:
        kill, stay = split_keep(pkgs)
    else:
        kill, stay = pkgs, []
    if not kill:
        raise SystemExit("Nothing to freeze. Everything matched the whitelist.")
    if full:
        print(f"Freezing {len(kill)} user apps. Kept {len(stay)}.")
    else:
        print(f"Freezing {len(kill)} app{'s' if len(kill) != 1 else ''}.")
    for p in stay:
        print(f"keep  {p}")
    done = []
    failed = []
    for p in kill:
        result = block_one(p)
        print(f"{result}  {p}")
        if result.startswith("FAILED"):
            failed.append(p)
        else:
            done.append(p)
    if full:
        write_lines(SAVE, done)
        write_lines(FAILS, failed)
        write_lines(THAWED, [])
    else:
        add_unique(SAVE, done)
        drop_from(FAILS, done)
        add_unique(FAILS, failed)
        drop_from(SAVE, failed)
        drop_from(THAWED, done)
    print(f"off={len(done)} failed={len(failed)}")
    if failed:
        print("Could not block (often the current launcher or a device admin):")
        for p in failed:
            print(f"  {p}")
    if full:
        print("Unplug. Restore with: python3 adb_screen_helper.py thaw")
        print("One app: python3 adb_screen_helper.py thaw PACKAGE")
        print("Freeze one: python3 adb_screen_helper.py freeze PACKAGE")
        print("Category: python3 adb_screen_helper.py freeze social")
    elif done:
        cats = load_categories()
        cat_args = [n for n in (packages or []) if n.lower() in cats]
        restore = " ".join(cat_args) if cat_args else " ".join(done)
        print("Restore: python3 adb_screen_helper.py thaw " + restore)


def load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text().splitlines() if l.strip()]


def recorded() -> list[str]:
    seen: list[str] = []
    for p in load_lines(SAVE) + load_lines(FAILS):
        if p not in seen:
            seen.append(p)
    return seen


def write_lines(path: Path, pkgs: list[str]) -> None:
    path.write_text("\n".join(pkgs) + ("\n" if pkgs else ""))


def add_unique(path: Path, pkgs: list[str]) -> None:
    have = load_lines(path)
    for p in pkgs:
        if p not in have:
            have.append(p)
    write_lines(path, have)


def drop_from(path: Path, pkgs: list[str]) -> None:
    drop = set(pkgs)
    write_lines(path, [p for p in load_lines(path) if p not in drop])


def drop_recorded(pkgs: list[str]) -> None:
    drop_from(SAVE, pkgs)
    drop_from(FAILS, pkgs)


def resolve_pkg(needle: str, catalog: list[str], empty: str = "No app matching") -> str:
    if needle in catalog:
        return needle
    low = needle.lower()
    hits = [p for p in catalog if low in p.lower()]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        listed = "\n".join(f"  {h}" for h in hits)
        raise SystemExit(f"Ambiguous {needle}:\n{listed}")
    if "." in needle:
        return needle
    raise SystemExit(f"{empty} {needle}")


def thaw(packages: list[str] | None = None) -> None:
    recorded_pkgs = recorded()
    catalog = recorded_pkgs or third_party()
    if packages:
        seen, _ = expand_targets(
            packages,
            catalog,
            "No frozen app matching",
            apply_whitelist=False,
        )
    else:
        seen = catalog
    if not seen:
        raise SystemExit("Nothing to thaw.")
    print(f"Enabling {len(seen)} app{'s' if len(seen) != 1 else ''}.")
    done = []
    for p in seen:
        result = unblock_one(p)
        print(f"{p}: {result}")
        if "FAILED" not in result and result != "not installed":
            done.append(p)
    drop_recorded(done)
    if packages:
        remember_thawed(done)
        if done:
            print("Whitelist picks: python3 adb_screen_helper.py keep")
            print("Currently thawed: python3 adb_screen_helper.py keep --now")


def remember_thawed(pkgs: list[str]) -> None:
    add_unique(THAWED, pkgs)


def parse_selection(text: str, n: int) -> list[int]:
    raw = text.strip().lower()
    if not raw:
        return []
    if raw in ("all", "*"):
        return list(range(1, n + 1))
    picked: set[int] = set()
    for part in raw.replace(" ", "").split(","):
        if not part:
            continue
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                start, end = int(a), int(b)
            else:
                start = end = int(part)
        except ValueError:
            raise SystemExit(f"Bad selection: {text}")
        if start > end:
            start, end = end, start
        for i in range(start, end + 1):
            picked.add(i)
    if not picked:
        raise SystemExit(f"Bad selection: {text}")
    if any(i < 1 or i > n for i in picked):
        raise SystemExit(f"Out of range; list is 1-{n}")
    return sorted(picked)


def currently_thawed() -> list[str]:
    print("Checking which apps are thawed on the phone...")
    out = []
    for p in third_party():
        line = user_states(p).get("0", "")
        if _installed(line) and not _suspended(line):
            out.append(p)
    return out


def print_thawed(pkgs: list[str], title: str) -> None:
    pats = patterns()
    print(title)
    for i, p in enumerate(pkgs, 1):
        extra = "  (already kept)" if kept(p, pats) else ""
        print(f"[{i}] {p}{extra}")


def keep(parts: list[str] | None, now: bool = False) -> None:
    parts = list(parts or [])
    if parts and parts[0].lower() in ("now", "current"):
        now = True
        parts = parts[1:]
    if now:
        pkgs = currently_thawed()
        title = "Currently thawed on the phone:"
        empty = "No thawed third-party apps on the phone."
        pick = "python3 adb_screen_helper.py keep --now 1-5 | 1,3,7 | all"
    else:
        pkgs = load_lines(THAWED)
        title = "Thawed since last freeze:"
        empty = "No individually thawed apps since last freeze."
        pick = "python3 adb_screen_helper.py keep 1-5 | 1,3,7 | all"
    if not pkgs:
        raise SystemExit(empty)
    print_thawed(pkgs, title)
    selection = ",".join(parts) if parts else ""
    if not selection:
        if sys.stdin.isatty():
            try:
                selection = input("Add to whitelist (1-5, 1,3,7, all, Enter to cancel): ")
            except EOFError:
                selection = ""
        else:
            print("Pick with: " + pick)
            return
    indexes = parse_selection(selection, len(pkgs))
    if not indexes:
        print("Cancelled.")
        return
    chosen = [pkgs[i - 1] for i in indexes]
    added = add_whitelist_pkgs(chosen)
    drop_from(THAWED, chosen)
    if added:
        print("Next freeze will keep these.")


def add_whitelist_pkgs(pkgs: list[str]) -> list[str]:
    ensure_whitelist()
    pats = patterns()
    existing = {
        line.split("#", 1)[0].strip().lower()
        for line in WHITELIST.read_text().splitlines()
        if line.split("#", 1)[0].strip()
    }
    added: list[str] = []
    with WHITELIST.open("a") as f:
        for p in pkgs:
            key = p.lower()
            if kept(p, pats) or key in existing:
                print(f"skip  {p} (already kept)")
                continue
            f.write(p + "\n")
            added.append(p)
            pats.append(key)
            existing.add(key)
            print(f"added {p}")
    return added


def show_whitelist() -> None:
    ensure_whitelist()
    print(WHITELIST.read_text(), end="")
    print("---")
    pkgs = third_party()
    kill, stay = split_keep(pkgs)
    print(f"would keep {len(stay)}, freeze {len(kill)}")
    for p in stay:
        print(f"keep  {p}")


def add_pattern(text: str) -> None:
    ensure_whitelist()
    with WHITELIST.open("a") as f:
        f.write(text.strip() + "\n")
    print(f"added {text.strip()}")


def show_categories(name: str | None) -> None:
    cats = load_categories()
    if not cats:
        raise SystemExit("No categories in categories.txt.")
    if name:
        key = name.lower()
        if key not in cats:
            raise SystemExit(f"Unknown category {name}. Have: {', '.join(sorted(cats))}")
        cats = {key: cats[key]}
    catalog: list[str] = []
    label = "installed"
    if device_ready():
        catalog = third_party()
    else:
        catalog = recorded()
        if catalog:
            label = "frozen"
            print("(no device; matching frozen_packages.txt)")
        else:
            print("(no device; showing patterns in categories.txt)")
    for key, pats in sorted(cats.items()):
        if catalog:
            hits = match_category(catalog, pats)
            print(f"{key}  ({len(hits)} {label})")
            for p in hits:
                print(f"  {p}")
            if not hits:
                print("  (none)")
        else:
            print(f"{key}")
            for pat in pats:
                print(f"  {pat}")


def main() -> None:
    p = argparse.ArgumentParser(description="Freeze/thaw third-party Android apps over ADB.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("devices")
    sub.add_parser("user-apps")
    fr = sub.add_parser("freeze")
    fr.add_argument(
        "packages",
        nargs="*",
        help="package, unique substring, or category (social, games, ...); omit to freeze all non-whitelist apps",
    )
    fr.add_argument("--all", action="store_true", help="ignore whitelist")
    th = sub.add_parser("thaw")
    th.add_argument(
        "packages",
        nargs="*",
        help="package, unique substring, or category (social, games, ...); omit to thaw every frozen app",
    )
    kp = sub.add_parser("keep", help="whitelist thawed apps")
    kp.add_argument(
        "selection",
        nargs="*",
        help="1-5, 1,3,7, or all; omit to list and prompt. 'now' lists currently thawed apps",
    )
    kp.add_argument(
        "--now",
        "--current",
        action="store_true",
        help="use apps currently thawed on the phone, not only individual thaws since last freeze",
    )
    catp = sub.add_parser("categories", help="list freeze/thaw categories")
    catp.add_argument("name", nargs="?", help="show one category; omit to list all")
    wl = sub.add_parser("whitelist")
    wl.add_argument("action", nargs="?", default="show", choices=["show", "add"])
    wl.add_argument("pattern", nargs="?")
    d = sub.add_parser("disable")
    d.add_argument("packages", nargs="+")
    e = sub.add_parser("enable")
    e.add_argument("packages", nargs="+")
    args = p.parse_args()

    if args.cmd == "devices":
        print(adb("devices"))
        return
    if args.cmd == "whitelist" and args.action == "add":
        if not args.pattern:
            raise SystemExit("whitelist add needs a substring, e.g. maps")
        add_pattern(args.pattern)
        return
    if args.cmd == "keep":
        parts = list(args.selection or [])
        now = args.now or bool(parts and parts[0].lower() in ("now", "current"))
        if now:
            require_device()
        keep(args.selection, now=args.now)
        return
    if args.cmd == "categories":
        show_categories(args.name)
        return
    require_device()
    if args.cmd == "user-apps":
        print("\n".join(third_party()) or "(none)")
    elif args.cmd == "freeze":
        freeze(use_whitelist=not args.all, packages=args.packages)
    elif args.cmd == "thaw":
        thaw(args.packages)
    elif args.cmd == "whitelist":
        show_whitelist()
    elif args.cmd == "disable":
        for pkg in args.packages:
            print(f"{block_one(pkg)}  {pkg}")
    elif args.cmd == "enable":
        for pkg in args.packages:
            print(f"{pkg}: {unblock_one(pkg)}")


if __name__ == "__main__":
    main()
