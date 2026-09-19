#!/usr/bin/env python3
"""Generate the keys a live Rand bridge needs, on this machine, from a mixed entropy pool.

    deploy/keygen.py deployer  [--network mainnet]     # ETH, BSC, TRON keys, a Solana keypair, RAND_EMITTER
    deploy/keygen.py guardian  [--network mainnet] [--index N]      # ONE guardian key, on that operator's host
    deploy/keygen.py guardian  --count 6 --i-accept-one-host-holds-the-quorum   # a rehearsal, not a launch
    deploy/keygen.py --self-test                       # the known-answer tests only; generates nothing

Python 3.8+ standard library only: nothing to `pip install`, so nothing to be supply-chained.

What it does about entropy
  Every secret is SHA-512 over a pool of *independent* draws, so the result is at least as
  unpredictable as the best one of them and a single weak source cannot weaken it:
    - the kernel CSPRNG through `secrets.token_bytes` (getentropy/getrandom),
    - a second, separate read of /dev/random,
    - `openssl rand` if openssl is installed (its own DRBG, its own seeding),
    - CPU timing jitter (8 192 samples of the nanosecond counter around hashing work),
    - whatever you type when asked (dice rolls, keyboard mashing) — optional, never required,
    - the pid, the clocks and a per-run counter, so two runs or two keys can never share a pool.
  The OS sources are health-checked first (two draws must differ, neither may be constant), a
  secp256k1 secret is redrawn unless it lies in [1, n-1], every key of a run must be distinct, and
  a key whose address appears in a testnet record under deploy/ is refused: an attestation does
  not name its network, so a reused guardian key lets a testnet message mint on mainnet.

What it does about exposure
  Secrets are written to files of mode 0600 in a directory of mode 0700 (default
  ~/.rand-bridge/<network>/) and are NEVER printed, put in argv, or written under the repository.
  Only addresses are shown. Existing files are never overwritten. The address printed for each
  key is derived here (pure-Python secp256k1, Keccak-256, Ed25519) and the derivation code is
  checked against published test vectors on every run, before any key is drawn.

A guardian key belongs on its operator's host and nowhere else: run `guardian` there, and send
only the printed address to whoever assembles GUARDIANS. Six keys made on one laptop are a
1-of-1 bridge however the contracts count them.
"""
import argparse
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import time

DOMAIN = b"rand-bridge-keygen-1"

# ---------------------------------------------------------------- Keccak-256 (not SHA3-256: the padding differs)
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _M if n else x


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & _M & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    p = bytearray(data) + b"\x01"
    p += b"\x00" * (-len(p) % rate)
    p[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(p[off + 8 * i: off + 8 * i + 8], "little")
        a = _keccak_f(a)
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


# ---------------------------------------------------------------- secp256k1 public key, EVM and Tron addresses
_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0]:
        if (p[1] + q[1]) % _P == 0:
            return None
        lam = 3 * p[0] * p[0] * pow(2 * p[1], -1, _P) % _P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    return x, (lam * (p[0] - x) - p[1]) % _P


def _ec_mul(k, p=_G):
    # Not constant time. This runs once, offline, on the machine that owns the key; nothing
    # observes its timing. Do not reuse it for signing.
    r = None
    while k:
        if k & 1:
            r = _ec_add(r, p)
        p = _ec_add(p, p)
        k >>= 1
    return r


def evm_address(secret: bytes) -> str:
    k = int.from_bytes(secret, "big")
    if not 1 <= k < _N:
        raise ValueError("secp256k1 secret out of range")
    x, y = _ec_mul(k)
    raw = keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:].hex()
    chk = keccak256(raw.encode()).hex()
    return "0x" + "".join(c.upper() if int(chk[i], 16) >= 8 else c for i, c in enumerate(raw))


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b: bytes) -> str:
    n, out = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def tron_address(evm_addr: str) -> str:
    body = b"\x41" + bytes.fromhex(evm_addr[2:])
    return b58encode(body + hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4])


# ---------------------------------------------------------------- Ed25519 public key (RFC 8032), for Solana
_Q = 2**255 - 19
_D = -121665 * pow(121666, -1, _Q) % _Q
_BY = 4 * pow(5, -1, _Q) % _Q
_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_B = (_BX, _BY, 1, _BX * _BY % _Q)


def _ed_add(p, q):
    a, b = (p[1] - p[0]) * (q[1] - q[0]) % _Q, (p[1] + p[0]) * (q[1] + q[0]) % _Q
    c, d = 2 * p[3] * q[3] * _D % _Q, 2 * p[2] * q[2] % _Q
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q


def ed25519_public(seed: bytes) -> bytes:
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    k, p, r = int.from_bytes(h, "little"), _B, (0, 1, 1, 0)
    while k:
        if k & 1:
            r = _ed_add(r, p)
        p = _ed_add(p, p)
        k >>= 1
    zi = pow(r[2], -1, _Q)
    x, y = r[0] * zi % _Q, r[1] * zi % _Q
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


# ---------------------------------------------------------------- known-answer tests: run before any key is drawn
def self_test():
    h = bytes.fromhex
    checks = [
        ("keccak256('')", keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        ("keccak256('abc')", keccak256(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
        # Exactly one rate block of input, so the padding lands in a block of its own (cross-checked with `cast keccak`).
        ("keccak256('a' * 136)", keccak256(b"a" * 136).hex(), "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"),
        ("secp256k1 key 1", evm_address((1).to_bytes(32, "big")), "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"),
        ("secp256k1 anvil account 0",
         evm_address(h("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")),
         "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
        ("tron base58check (the USDT TRC-20 contract)", tron_address("0xa614f803b6fd780986a42c78ec9c7f77e6ded13c"),
         "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
        ("ed25519 RFC 8032 test 1",
         ed25519_public(h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")).hex(),
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
        ("ed25519 RFC 8032 test 2",
         ed25519_public(h("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")).hex(),
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
    ]
    bad = [(name, got, want) for name, got, want in checks if got != want]
    for name, got, want in bad:
        print(f"SELF-TEST FAILED: {name}\n  got  {got}\n  want {want}", file=sys.stderr)
    if bad:
        sys.exit("refusing to generate keys with a broken derivation")
    return len(checks)


# ---------------------------------------------------------------- the entropy pool
class Pool:
    def __init__(self, user_entropy: bytes):
        self.user = user_entropy
        self.counter = 0
        self.sources = []
        a, b = secrets.token_bytes(64), secrets.token_bytes(64)
        if a == b or len(set(a)) < 16 or len(set(b)) < 16:
            sys.exit("the OS random source failed its health check (repeated or constant output); do not generate keys here")
        self.openssl = shutil.which("openssl")

    def _jitter(self) -> bytes:
        acc = hashlib.sha256()
        x = b"\x00" * 32
        for _ in range(8192):
            t0 = time.perf_counter_ns()
            x = hashlib.sha256(x).digest()
            acc.update((time.perf_counter_ns() - t0).to_bytes(8, "little"))
        return acc.digest()

    def draw(self, label: bytes) -> bytes:
        self.counter += 1
        parts = [("kernel CSPRNG (secrets)", secrets.token_bytes(64))]
        try:
            with open("/dev/random", "rb", buffering=0) as f:
                parts.append(("/dev/random", f.read(64)))
        except OSError:
            pass
        if self.openssl:
            try:
                out = subprocess.run([self.openssl, "rand", "64"], capture_output=True, timeout=10, check=True).stdout
                if len(out) == 64:
                    parts.append(("openssl rand", out))
            except (OSError, subprocess.SubprocessError):
                pass
        parts.append(("cpu timing jitter", self._jitter()))
        if self.user:
            parts.append(("typed entropy", hashlib.sha512(self.user).digest()))
        self.sources = [name for name, _ in parts]
        pool = hashlib.sha512()
        pool.update(DOMAIN + b"\x00" + label + b"\x00" + self.counter.to_bytes(8, "big"))
        pool.update(os.getpid().to_bytes(8, "big") + time.time_ns().to_bytes(16, "big") + time.monotonic_ns().to_bytes(16, "big"))
        for name, data in parts:
            # Length-prefixed, so no two different pools serialise to the same bytes.
            pool.update(len(name).to_bytes(2, "big") + name.encode() + len(data).to_bytes(4, "big") + data)
        return pool.digest()[:32]

    def secp256k1(self, label: bytes) -> bytes:
        while True:
            s = self.draw(label)
            if 1 <= int.from_bytes(s, "big") < _N:
                return s


# ---------------------------------------------------------------- files
def _secure_dir(path):
    repo = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    if (os.path.realpath(path) + os.sep).startswith(repo + os.sep):
        sys.exit(f"{path} is inside the repository; keys do not belong in a git tree. Choose --out elsewhere.")
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def _refuse_existing(paths):
    """Before anything is drawn: a run either writes all of its files or none of them."""
    for p in paths:
        if os.path.lexists(p):
            sys.exit(f"{p} already exists; refusing to overwrite a key file. Move it away first if you mean to replace it.")


def _write_secret(path, text):
    # O_EXCL: never overwrite a key that may already guard funds.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        sys.exit(f"{path} already exists; refusing to overwrite a key file. Move it away first if you mean to replace it.")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def _testnet_addresses():
    """Every address and emitter a testnet record under deploy/ names, lower-cased."""
    here, seen = os.path.dirname(os.path.abspath(__file__)), set()

    def walk(v):
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str):
            for tok in v.replace(",", " ").split():
                if tok.startswith("0x") and len(tok) in (42, 66):
                    seen.add(tok.lower())

    for root in (os.path.join(here, "keys"), os.path.join(here, "deployments")):
        for dirpath, _, files in os.walk(root):
            for name in files:
                if name.endswith(".json"):
                    try:
                        with open(os.path.join(dirpath, name)) as f:
                            walk(json.load(f))
                    except (OSError, ValueError):
                        pass
    return seen


def main():
    ap = argparse.ArgumentParser(description="Generate Rand bridge keys locally from a mixed entropy pool.")
    ap.add_argument("role", nargs="?", choices=["deployer", "guardian"])
    ap.add_argument("--network", default="mainnet", help="a label for the output directory and file headers (default: mainnet)")
    ap.add_argument("--out", help="output directory (default: ~/.rand-bridge/<network>)")
    ap.add_argument("--index", type=int, help="guardian: this operator's index in GUARDIANS (0-5), for the file name")
    ap.add_argument("--count", type=int, default=1, help="guardian: how many keys (more than 1 needs the flag below)")
    ap.add_argument("--i-accept-one-host-holds-the-quorum", action="store_true", dest="one_host")
    ap.add_argument("--no-typed-entropy", action="store_true", help="do not ask for typed entropy")
    ap.add_argument("--self-test", action="store_true", help="run the known-answer tests and exit")
    args = ap.parse_args()

    n = self_test()
    if args.self_test:
        print(f"self-test: {n}/{n} known-answer checks passed (Keccak-256, secp256k1, Tron base58check, Ed25519)")
        return
    if not args.role:
        ap.error("choose a role: deployer or guardian")
    if args.role == "guardian" and args.count > 1 and not args.one_host:
        sys.exit("more than one guardian key on one host defeats the 5-of-6 quorum. For a rehearsal, pass\n"
                 "--i-accept-one-host-holds-the-quorum; for a launch, run this once on each operator's host.")
    if args.role == "guardian" and not 1 <= args.count <= 255:
        sys.exit("--count must be 1..255")

    user = b""
    if not args.no_typed_entropy and sys.stdin.isatty():
        import getpass
        print("Optional: type 30+ random characters or dice rolls, then Enter (not echoed; Enter alone skips).")
        print("It is mixed into the pool and can only add unpredictability. It is not a password: you never need it again.")
        user = getpass.getpass("typed entropy> ").encode()

    out = os.path.expanduser(args.out or os.path.join("~", ".rand-bridge", args.network))
    _secure_dir(out)
    pool, testnet, stamp = Pool(user), _testnet_addresses(), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    header = (f"# Rand bridge {args.network} keys, generated {stamp} on this host by deploy/keygen.py.\n"
              f"# SECRET. Mode 0600. Never commit, paste, email or screenshot this file.\n")
    public, made = {"network": args.network, "generated": stamp}, []

    def fresh(label):
        s = pool.secp256k1(label.encode())
        addr = evm_address(s)
        if addr.lower() in testnet:
            sys.exit(f"{label}: drew a key that a testnet record names — that cannot happen by chance. Stop and investigate.")
        if addr in made:
            sys.exit("two keys of one run came out equal; the random source is broken. Do not use this host.")
        made.append(addr)
        return s, addr

    def guardian_tag(i):
        idx = args.index if (args.index is not None and args.count == 1) else (i if args.count > 1 else None)
        return f"guardian-{idx}" if idx is not None else "guardian"

    if args.role == "deployer":
        _refuse_existing([os.path.join(out, "deployer.env"), os.path.join(out, "solana-deployer.keypair.json")])
    else:
        _refuse_existing([os.path.join(out, f"{guardian_tag(i)}.env") for i in range(args.count)])

    if args.role == "deployer":
        lines = [header]
        for var, label in (("ETH_PRIVATE_KEY", "ethereum deployer"), ("BSC_PRIVATE_KEY", "bsc deployer"),
                           ("TRON_PRIVATE_KEY", "tron deployer")):
            s, addr = fresh(label)
            shown = f"{addr}  (Tron: {tron_address(addr)})" if var.startswith("TRON") else addr
            lines.append(f"# {label}: {shown}\n{var}=0x{s.hex()}\n")
            public[var.replace("_PRIVATE_KEY", "_DEPLOYER_ADDRESS")] = shown
        emitter = pool.draw(b"rand emitter")
        if ("0x" + emitter.hex()) in testnet:
            sys.exit("RAND_EMITTER collided with a testnet record; stop and investigate.")
        lines.append(f"# Not a secret, but it must be unique to this network and equal the Rand genesis bridge.emitter.\n"
                     f"RAND_EMITTER=0x{emitter.hex()}\n")
        public["RAND_EMITTER"] = "0x" + emitter.hex()
        seed = pool.draw(b"solana deployer")
        pub = ed25519_public(seed)
        sol_path = os.path.join(out, "solana-deployer.keypair.json")
        _write_secret(sol_path, json.dumps(list(seed + pub)))
        lines.append(f"# solana deployer: {b58encode(pub)}\nSOL_KEYPAIR={sol_path}\n")
        public["SOL_DEPLOYER_ADDRESS"] = b58encode(pub)
        env_path = os.path.join(out, "deployer.env")
        _write_secret(env_path, "\n".join(lines))
        written = [env_path, sol_path]
    else:
        written, addrs = [], []
        for i in range(args.count):
            tag = guardian_tag(i)
            s, addr = fresh(tag)
            path = os.path.join(out, f"{tag}.env")
            _write_secret(path, f"{header}# guardian address (send THIS, and only this, to whoever assembles GUARDIANS): {addr}\n"
                                f"GUARDIAN_KEY=0x{s.hex()}\n")
            written.append(path)
            addrs.append(addr)
        public["guardian_addresses"] = addrs
        if args.count > 1:
            public["GUARDIANS"] = ",".join(addrs)

    pub_path = os.path.join(out, f"{args.role}-public-{stamp.replace(':', '')}.json")
    with open(pub_path, "w") as f:
        json.dump(public, f, indent=2)
    os.chmod(pub_path, 0o644)

    print(f"\nentropy sources mixed per key: {', '.join(pool.sources)}")
    print("addresses (safe to share):")
    for k, v in public.items():
        if k not in ("network", "generated"):
            print(f"  {k}: {v if not isinstance(v, list) else ', '.join(v)}")
    print("\nsecret files (mode 0600 — back them up offline, e.g. an encrypted USB stick or paper in a safe):")
    for p in written:
        print(f"  {p}")
    print(f"public summary: {pub_path}")
    first = written[0]
    print(f"""
To use the keys:
  the deploy scripts   DEPLOY_ENV_FILE={first} deploy/eth.sh mainnet --dry-run
                       (preferred: the scripts load the file themselves and keep the keys un-exported,
                        so only the one signing process ever sees a key)
  from ~/.zshrc        add this line — it keeps the secrets in the 0600 file, not in ~/.zshrc itself:
                         [ -r {first} ] && set -a && . {first} && set +a
                       Every program you start from that shell can then read the keys. Prefer the line
                       above it for anything that guards real funds.
Fund the deployer addresses, then check each one on its explorer before broadcasting anything.""")


if __name__ == "__main__":
    main()
