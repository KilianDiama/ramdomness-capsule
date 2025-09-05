#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
randomness_battery.py — Pile d’entropie (charge & vérification)
---------------------------------------------------------------
But : charger une 'pile numérique' contenant de l'entropie (hasard) de haute qualité,
puis la sceller dans un fichier .caps avec un manifeste vérifiable :
- SHA-256 global du pool
- Arbre de Merkle des blocs (preuve/identité des segments)
- Diagnostics d'entropie (monobit, histogramme, Shannon)

Ce script ne gère PAS la 'décharge' (consommation). Il se concentre sur la CHARGE & la PREUVE.

Dépendances : Python 3.8+ (standard library uniquement)

Format du fichier .caps :
[4 bytes magic 'RND1'] [8 bytes BE manifest_len] [manifest JSON UTF-8] [pool bytes]

Commandes :
  - make     : génère une pile .caps
  - verify   : vérifie une pile .caps (hashs, merkle, tailles)
  - inspect  : imprime le manifeste + diagnostics entropie (sur un échantillon ou complet)

Exemples :
  python randomness_battery.py make --megabytes 64 --chunk-bytes 65536 --out piles/Random_64MB.caps
  python randomness_battery.py verify --caps piles/Random_64MB.caps
  python randomness_battery.py inspect --caps piles/Random_64MB.caps --sample-mb 8
"""

import argparse, os, sys, json, time, uuid, platform, hashlib, math, tempfile, shutil
from datetime import datetime, timezone
from typing import List, Tuple

MAGIC = b"RND1"
UTC = timezone.utc

# ---------------- Utilitaires I/O ----------------

def ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def read_uint64_be(b: bytes) -> int:
    return int.from_bytes(b, "big", signed=False)

def write_uint64_be(n: int) -> bytes:
    return int(n).to_bytes(8, "big", signed=False)

# ---------------- Entropie & mix léger ----------------

def os_entropy(n: int) -> bytes:
    """Entropie cryptographique fournie par l'OS (recommandée)."""
    return os.urandom(n)

def jitter_entropy(bytes_needed: int = 32, loops: int = 200000) -> bytes:
    """
    Source optionnelle : 'jitter' temporel (bruit d'horloge + micro-ops),
    hashée en SHA-256. N'améliore pas forcément au-delà d'os.urandom, mais peut
    diversifier les sources. Reste optionnelle.
    """
    h = hashlib.sha256()
    t0 = time.perf_counter_ns()
    acc = 0
    for i in range(loops):
        x = (i * 6364136223846793005 + 1) & 0xFFFFFFFFFFFFFFFF  # LCG 64b
        t = time.perf_counter_ns()
        acc ^= (t ^ (x << (i & 7))) & 0xFFFFFFFFFFFFFFFF
        if (i & 8191) == 0:
            h.update(acc.to_bytes(8, "little"))
    h.update(str(platform.uname()).encode())
    h.update(str(os.getpid()).encode())
    h.update(int(time.time_ns()).to_bytes(8, "little"))
    seed = h.digest()
    # Étend via SHA-256 en mode CTR simple
    out = bytearray()
    counter = 0
    while len(out) < bytes_needed:
        h2 = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        out.extend(h2)
        counter += 1
    return bytes(out[:bytes_needed])

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# ---------------- Merkle tree (SHA-256) ----------------

def merkle_root_from_leaf_hashes(leaf_hashes_hex: List[str]) -> str:
    """Calcule la racine Merkle (SHA-256) à partir des hashs hex des feuilles (ordre donné)."""
    if not leaf_hashes_hex:
        return sha256_hex(b"")
    level = [bytes.fromhex(h) for h in leaf_hashes_hex]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i+1] if i+1 < len(level) else level[i]  # doublement si impair
            nxt.append(hashlib.sha256(left + right).digest())
        level = nxt
    return level[0].hex()

# ---------------- Diagnostics entropie ----------------

def monobit_stats(data: bytes) -> Tuple[int, int, float]:
    """Retourne (bits_1, bits_0, balance) où balance = (ones - zeros)/total_bits."""
    ones = 0
    for b in data:
        ones += bin(b).count("1")
    total = len(data) * 8
    zeros = total - ones
    balance = (ones - zeros) / total if total else 0.0
    return ones, zeros, balance

def byte_histogram_entropy(data: bytes) -> Tuple[list, float]:
    """Histogramme (256) et entropie de Shannon (bits par octet)."""
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data)
    H = 0.0
    for c in freq:
        if c == 0: continue
        p = c / n
        H -= p * math.log2(p)
    return freq, H  # 8.0 bits/byte = parfait

def runs_test_bits(data: bytes) -> Tuple[int, float]:
    """Test simple : nombre de runs (alternances) dans le flux de bits, et ratio runs/bits."""
    if not data: return 0, 0.0
    runs = 1
    prev = (data[0] >> 7) & 1
    total_bits = len(data) * 8
    bitpos = 1
    for b in data:
        for i in range(8):
            if b & (1 << (7 - i)):
                curr = 1
            else:
                curr = 0
            if bitpos == 1:
                bitpos += 1
                continue
            if curr != prev:
                runs += 1
                prev = curr
            bitpos += 1
    return runs, runs / total_bits

# ---------------- Fabrication de la pile ----------------

def make_battery(megabytes: int,
                 chunk_bytes: int,
                 out_path: str,
                 mix_jitter: bool = True,
                 note: str = "") -> str:
    """
    Génère un fichier .caps 'pile d'entropie' :
    - pool de N MiB (en blocs)
    - hashs par bloc (+ racine Merkle)
    - SHA-256 global
    - manifeste JSON (métadonnées + diagnostics sur échantillon)
    """
    ensure_dir(os.path.dirname(out_path) or ".")
    pool_bytes = megabytes * 1024 * 1024
    if chunk_bytes <= 0 or chunk_bytes > pool_bytes:
        chunk_bytes = min(65536, pool_bytes)

    chunk_hashes = []
    total_written = 0
    global_hasher = hashlib.sha256()

    tmp_dir = tempfile.mkdtemp(prefix="rndcaps_")
    tmp_pool_path = os.path.join(tmp_dir, "pool.bin")
    jitter_seed = jitter_entropy(32, loops=200000) if mix_jitter else b""

    print(f"▶️  Charge pile : {megabytes} MiB | bloc={chunk_bytes} | jitter={'on' if mix_jitter else 'off'}")
    with open(tmp_pool_path, "wb") as f:
        idx = 0
        while total_written < pool_bytes:
            want = min(chunk_bytes, pool_bytes - total_written)
            block = os_entropy(want)
            if mix_jitter:
                # mélange léger : SHA-256(block || jitter || idx) XOR block
                h = hashlib.sha256(block + jitter_seed + idx.to_bytes(8, "big")).digest()
                mix = (h * ((want + 31)//32))[:want]  # étend à la taille du bloc
                block = xor_bytes(block, mix)
            f.write(block)
            global_hasher.update(block)
            chunk_hashes.append(sha256_hex(block))
            total_written += want
            idx += 1
            if idx % 128 == 0 or total_written == pool_bytes:
                print(f"… {total_written//1024//1024} MiB / {megabytes} MiB")

    global_sha = global_hasher.hexdigest()
    merkle_root = merkle_root_from_leaf_hashes(chunk_hashes)
    chunk_count = len(chunk_hashes)

    # Diagnostics sur échantillon (jusqu'à 16 MiB ou toute la pile si plus petit)
    sample_bytes = min(pool_bytes, 16 * 1024 * 1024)
    with open(tmp_pool_path, "rb") as f:
        sample = f.read(sample_bytes)
    ones, zeros, balance = monobit_stats(sample)
    freq, H = byte_histogram_entropy(sample)
    runs, runs_ratio = runs_test_bits(sample)

    pile_id = uuid.uuid4().hex[:12]
    created_at = datetime.now(UTC).isoformat()

    manifest = {
        "version": "1.0",
        "pile_id": pile_id,
        "created_at": created_at,
        "note": note,
        "pool_bytes": pool_bytes,
        "chunk_bytes": chunk_bytes,
        "chunk_count": chunk_count,
        "global_sha256": global_sha,
        "chunk_sha256": chunk_hashes,     # peut être volumineux ; utile pour preuves par bloc
        "merkle_root": merkle_root,
        "entropy_sources": {
            "os_urandom": True,
            "jitter_mixed": bool(mix_jitter)
        },
        "system": {
            "platform": platform.platform(),
            "python": sys.version.split()[0]
        },
        "diagnostics": {
            "sample_bytes": sample_bytes,
            "monobit": {"ones": ones, "zeros": zeros, "balance": balance},
            "shannon_bits_per_byte": H,
            "runs": {"count": runs, "ratio": runs_ratio}
        }
    }

    # Écrire le .caps final : MAGIC + manifest_len + manifest + pool
    manifest_bytes = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    out_tmp = out_path + ".tmp"
    with open(out_tmp, "wb") as out_f:
        out_f.write(MAGIC)
        out_f.write(write_uint64_be(len(manifest_bytes)))
        out_f.write(manifest_bytes)
        # stream copie du pool
        with open(tmp_pool_path, "rb") as src:
            shutil.copyfileobj(src, out_f, length=1024*1024)

    os.replace(out_tmp, out_path)
    shutil.rmtree(tmp_dir, ignore_errors=True)

    print("✅ Pile créée")
    print(f"   Fichier      : {out_path}")
    print(f"   Taille       : {os.path.getsize(out_path)} bytes  (~{pool_bytes/1024/1024:.1f} MiB payload)")
    print(f"   Global SHA   : {global_sha[:16]}…")
    print(f"   Merkle root  : {merkle_root[:16]}…")
    print(f"   Entropie H   : {H:.4f} bits/byte (8.0 ≈ idéal)")
    return out_path

# ---------------- Lecture / vérification ----------------

def read_capsule(path: str) -> Tuple[dict, int, int]:
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("Magic invalide (pas une .caps RND1)")
        mlen = read_uint64_be(f.read(8))
        mjson = f.read(mlen)
        manifest = json.loads(mjson.decode("utf-8"))
        pool_offset = 4 + 8 + mlen
        total_size = os.path.getsize(path)
        pool_size = total_size - pool_offset
        if pool_size != manifest.get("pool_bytes"):
            raise ValueError(f"Taille pool incohérente: fichier={pool_size}, manifest={manifest.get('pool_bytes')}")
        return manifest, pool_offset, total_size

def verify_capsule(path: str, sample_only: bool = False) -> bool:
    manifest, pool_off, total = read_capsule(path)
    pool_bytes = manifest["pool_bytes"]
    chunk_bytes = manifest["chunk_bytes"]
    chunk_count = manifest["chunk_count"]
    expected_global = manifest["global_sha256"]
    expected_merkle = manifest["merkle_root"]
    expected_chunk_hashes = manifest.get("chunk_sha256") or []

    print(f"▶️  Vérification : {os.path.basename(path)}")
    # SHA-256 global
    h = hashlib.sha256()
    with open(path, "rb") as f:
        f.seek(pool_off)
        left = pool_bytes if not sample_only else min(pool_bytes, 8*1024*1024)
        while left > 0:
            n = min(1024*1024, left)
            data = f.read(n)
            if not data: break
            h.update(data)
            left -= len(data)
    global_sha = h.hexdigest()
    if sample_only:
        print(f"   SHA256 (échantillon) : {global_sha[:16]}… (comparaison globale sautée)")
    else:
        ok_sha = (global_sha == expected_global)
        print(f"   SHA256 global        : {global_sha[:16]}…  [{'OK' if ok_sha else 'FAIL'}]")
        if not ok_sha: return False

    # Merkle (re-calcul par blocs)
    if not sample_only:
        chunk_hashes = []
        with open(path, "rb") as f:
            f.seek(pool_off)
            remaining = pool_bytes
            for i in range(chunk_count):
                want = min(chunk_bytes, remaining)
                block = f.read(want)
                if not block or len(block) != want:
                    print("   Lecture bloc incomplète."); return False
                chunk_hashes.append(sha256_hex(block))
                remaining -= want
        merkle = merkle_root_from_leaf_hashes(chunk_hashes)
        ok_merkle = (merkle == expected_merkle)
        print(f"   Merkle root          : {merkle[:16]}…  [{'OK' if ok_merkle else 'FAIL'}]")
        if expected_chunk_hashes:
            ok_chunks = (chunk_hashes == expected_chunk_hashes)
            print(f"   Hashs blocs (liste)  : [{'OK' if ok_chunks else 'DIFF'}]")
        return ok_merkle and (not expected_chunk_hashes or ok_chunks)
    return True

def inspect_capsule(path: str, sample_mb: int = 8):
    manifest, pool_off, total = read_capsule(path)
    print("🔎 MANIFESTE")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    sample_bytes = min(manifest["pool_bytes"], sample_mb * 1024 * 1024)
    print(f"\n🧪 DIAGNOSTICS (échantillon {sample_mb} MiB max)")
    with open(path, "rb") as f:
        f.seek(pool_off)
        data = f.read(sample_bytes)
    ones, zeros, balance = monobit_stats(data)
    freq, H = byte_histogram_entropy(data)
    runs, ratio = runs_test_bits(data)
    print(f" - Monobit : ones={ones}, zeros={zeros}, balance={balance:.6f}")
    print(f" - Shannon : {H:.5f} bits/byte (8.0 ≈ idéal)")
    # Histogramme succinct : min/max fréquence
    mn = min(freq); mx = max(freq)
    print(f" - Byte histogram : min={mn}, max={mx}, distinct={sum(1 for c in freq if c>0)}/256")
    print(f" - Runs (bits) : {runs} runs, ratio={ratio:.6f}")

# ---------------- CLI ----------------

def build_parser():
    p = argparse.ArgumentParser(description="Pile d'entropie — charge & vérification (.caps)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pm = sub.add_parser("make", help="Charger une pile .caps")
    pm.add_argument("--megabytes", type=int, required=True, help="Taille du pool d'entropie (MiB)")
    pm.add_argument("--chunk-bytes", type=int, default=65536, help="Taille des blocs Merkle (défaut 65536)")
    pm.add_argument("--out", required=True, help="Chemin de sortie .caps")
    pm.add_argument("--no-jitter", action="store_true", help="Désactive le mix 'jitter' optionnel")
    pm.add_argument("--note", default="", help="Note libre à mettre dans le manifeste")
    pm.set_defaults(func=lambda a: make_battery(
        megabytes=a.megabytes,
        chunk_bytes=a.chunk_bytes,
        out_path=a.out,
        mix_jitter=(not a.no_jitter),
        note=a.note))

    pv = sub.add_parser("verify", help="Vérifier une pile .caps")
    pv.add_argument("--caps", required=True, help="Fichier .caps")
    pv.add_argument("--sample-only", action="store_true", help="Vérifie uniquement un échantillon (SHA partiel, rapide)")
    def _v(a):
        ok = verify_capsule(a.caps, sample_only=a.sample_only)
        print("\n✅ Vérification OK" if ok else "\n❌ Vérification ÉCHOUÉE")
    pv.set_defaults(func=_v)

    pi = sub.add_parser("inspect", help="Afficher manifeste + diagnostics")
    pi.add_argument("--caps", required=True, help="Fichier .caps")
    pi.add_argument("--sample-mb", type=int, default=8, help="Taille d'échantillon pour diagnostics")
    pi.set_defaults(func=lambda a: inspect_capsule(a.caps, sample_mb=a.sample_mb))

    return p

def main():
    args = build_parser().parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
