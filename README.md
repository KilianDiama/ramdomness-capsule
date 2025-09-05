# Randomness Battery (.caps)

> **Charge a high‑quality entropy “battery” and seal it in a verifiable `.caps` file with global SHA‑256, per‑chunk Merkle tree, and onboard diagnostics.**

`randomness_battery.py` builds **entropy pools** and stores them as `.caps` files. Each capsule embeds a **manifest** (metadata + diagnostics), the **global SHA‑256** of the pool, **per‑chunk hashes**, and the **Merkle root** for efficient identity proofs. Focus: **CHARGE & PROVE** (consumption is intentionally out of scope).

> ⚠️ **Note**: This is a pragmatic engineering tool. It is **not** a formal cryptographic RNG/VDF audit. Use according to your security requirements.

---

## ✨ Features

* **OS‑grade entropy** (`os.urandom`) with optional **jitter mix** for source diversity.
* **Sealed capsule format**: magic header, length‑prefixed manifest, raw pool bytes.
* **Verifiability**: per‑chunk SHA‑256 + **Merkle root**; fast verification & proofs.
* **Diagnostics** baked in: monobit, Shannon entropy (bytes), runs test.
* **Streaming write** with temp file & atomic replace; handles large pools.
* **Standard library only** (Python ≥ 3.8). No external deps.

---

## 🧱 What is a Randomness Battery?

A single `.caps` file with:

```
[4B MAGIC 'RND1'] [8B BE manifest_len] [manifest JSON UTF‑8] [pool bytes]
```

**Manifest** fields include: `pile_id`, `created_at`, `pool_bytes`, `chunk_bytes`,
`chunk_count`, `global_sha256`, `chunk_sha256[]` (optional but included here),
`merkle_root`, `entropy_sources`, `system`, and **diagnostics** (monobit,
Shannon bits/byte, runs).

---

## 🚀 Quickstart

```bash
# 1) Build a 64 MiB entropy capsule with 64 KiB chunks and jitter mix
python3 randomness_battery.py make \
  --megabytes 64 \
  --chunk-bytes 65536 \
  --out piles/Random_64MB.caps

# 2) Verify a capsule (full hash + Merkle)
python3 randomness_battery.py verify --caps piles/Random_64MB.caps

# 3) Fast verification (sample only)
python3 randomness_battery.py verify --caps piles/Random_64MB.caps --sample-only

# 4) Inspect manifest + entropy diagnostics (on an 8 MiB sample by default)
python3 randomness_battery.py inspect --caps piles/Random_64MB.caps --sample-mb 8
```

---

## 🧩 CLI Overview

```
usage: randomness_battery.py {make,verify,inspect} [...]

make   : generate a .caps file
  --megabytes INT         pool size (MiB)
  --chunk-bytes INT       chunk size for Merkle/hash (default 65536)
  --out PATH              output .caps path
  --no-jitter             disable optional jitter mixing
  --note STR              freeform note stored in manifest

verify : verify a .caps file (hashes, Merkle, sizes)
  --caps PATH
  --sample-only           partial SHA over first 8 MiB (quick sanity)

inspect: print manifest + diagnostics
  --caps PATH
  --sample-mb INT         sample size for diagnostics (MiB, default 8)
```

---

## 🔒 Integrity & Security

* **Global SHA‑256** over the entire pool.
* **Per‑chunk SHA‑256** + **Merkle root** for identity proofs and partial checks.
* **Atomic write**: temp dir, then `os.replace` to finalize the capsule.
* **Recommendations**

  * Sign the `.caps` artifact (e.g., minisign/cosign) before distribution.
  * Store the manifest (via `inspect`) alongside your artifact metadata/attestations.
  * When compliance matters, record platform info (CPU/OS) present in the manifest.

---

## 📊 Diagnostics (built‑in)

* **Monobit**: counts ones/zeros & balance.
* **Shannon entropy**: bits per byte (8.0 ≈ ideal uniform).
* **Runs test**: number of bit runs and ratio.

> You can run extra suites (dieharder/NIST STS) against the pool bytes if required; the capsule stores raw pool bytes after the manifest.

---

## ⚙️ Implementation Highlights

* Entropy from **`os.urandom`**. Optional **jitter** source hashed & XOR‑mixed per block.
* **Merkle tree** computed from per‑chunk SHA‑256s (odd nodes duplicated).
* Streaming copy of the pool into the final file; scales to large sizes.

---

## 🧭 Best Practices

* Choose `--chunk-bytes` to match your proof granularity (e.g., 64–256 KiB).
* For portability, document the **chunk size** and **pool size** with the artifact.
* Keep jitter **enabled** unless a compliance profile forbids non‑OS sources.

---

## 🗺️ Roadmap

* Optional Merkle proofs export (`.caps.proof.json`).
* Configurable hash (SHA‑512/BLAKE3) with algorithm tag.
* Zero‑copy memory map for very large `inspect` runs.

Contributions welcome (see **CLA**).

---

## 💼 Commercial Use & Brand

This repository is dual‑licensed:

* **DECL‑C v3.1** — Non‑Commercial Community License
* **DECL‑X v3.1** — Commercial/SaaS/OEM/Enterprise

Any commercial use (paid product, SaaS, OEM, cloud/edge, consulting, direct or indirect monetization) **requires** DECL‑X.

👉 **Contact**: \[email\@domain] · [https://your‑site.example/licensing](https://your-site.example/licensing)

Add to your source headers:

```python
# SPDX-License-Identifier: DECL-C-3.1 OR DECL-X-3.1
# Copyright (c) 2025 [Your Entity]
```

**Trademarks**: “Digital Energy Capsule™ / Pile Numérique™” usage requires prior written authorization (see Guides in the commercial license).

---

## 🤝 Contributing

By contributing, you agree to the **DECL‑CLA v1.1** (`DECL-CLA.md`).

Workflow: fork → feature branch → PR. Keep **standard‑library‑only**; add tests/examples if you touch entropy mix, Merkle, or I/O.

---

## 📑 License

See `LICENSE-COMMUNITY.md` (DECL‑C v3.1) and `LICENSE-COMMERCIAL.md` (DECL‑X v3.1).

---

## 🙌 Acknowledgements

Built with ❤️ and the **Python standard library** only.
