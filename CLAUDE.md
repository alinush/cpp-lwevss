# CLAUDE.md

Reference notes for running the GHL21e PVSS benchmark in this fork and turning the raw output into the four metrics the blog table needs.

## What this repo benchmarks

A **fresh PVSS deal** (not re-sharing). `src/main.cpp` has been rewritten to:
- do exactly **one** `encrypt` call (the actual dealing, not `n-1` dummy "previous dealings"),
- skip `commit(sk)`, `proveDecryption`, `proveKeyGen` (those are re-share / one-time-setup specific),
- keep `proveEncryption`, `proveSmallness`, `proveReShare` (the Shamir parity-check),
- zero-pad `pd.linWitness` at indices the skipped proofs would have filled (without this, `aggregateProver`'s witness-trimming loop cascades and erases every witness — see code comment).

Proofs verify end-to-end at all tested `(t, n)`.

## End-to-end reproduction

```bash
# 1. Install dependencies
brew install gmp ntl libsodium cmake   # macOS
# Debian/Ubuntu: apt install libgmp-dev libntl-dev libsodium-dev cmake

# 2. Clone the fork and build
git clone https://github.com/alinush/cpp-lwevss
cd cpp-lwevss
mkdir -p build && cd build && cmake .. && make -j lwe-pvss-main && cd ..

# 3. Run sequentially (NOT in parallel: memory-bandwidth contention causes noise).
#    (t, n) pairs with t = ceil(2n/3).
mkdir -p /tmp/ghl21e
for tn in "3 4" "6 8" "11 16" "22 32" "43 64" "86 128" "171 256" "342 512" "683 1024"; do
    set -- $tn
    ./build/lwe-pvss-main $2 $1 > "/tmp/ghl21e/n$2t$1.log" 2>&1
done
```

## CLI

```
./build/lwe-pvss-main <n> <t>
```

`t` is optional and overrides the internal `gpk.tee = ⌊(n-1)/(2·ell)⌋·ell` default (which is always `< n/2`). Pass it when you want `t ≈ 2n/3` (the PVSS thresholds the blog uses). The upstream `main.cpp` clamped `n ∈ [32, 4096]`; this fork accepts any `n ≥ 4`.

Wall clock is dominated by the serial keygen loop (`~2-3s` per party × `n` parties). Proof work is a flat ~6s regardless of `n`. So n=1024 takes ~45 min, n=8 takes ~20s.

## Output format

Each run prints one line per timed step. Example from `n=256 t=171`:

```
256 keyGens in 645259 milliseconds, avg=2520.54 ...      # setup, not counted
encryption in 1568 milliseconds                           # THE dealer encryption
decryption in 0.527 milliseconds                          # decrypt-share
proveEncryption in 3859 milliseconds
proveShamir in 7 milliseconds                             # proveReShare, renamed
proveSmallness in 13 milliseconds
aggregate in 31 milliseconds                              # constraint aggregation + flatten
proveLinear in 985 milliseconds                           # linear bulletproof
verifyLinear in 381 milliseconds
proveQuadratic in 436 milliseconds
verifyQuadratic in 128 milliseconds
transcript bytes: ctxt=204800, linProof=960, quadProof=896, total=206656 (201.812 KiB)
```

## Extracting the four metrics

| Metric | Formula |
|--------|---------|
| **Deal (ms)** | `encryption + proveEncryption + proveShamir + proveSmallness + aggregate + proveLinear + proveQuadratic` |
| **Verify (ms)** | `verifyLinear + verifyQuadratic` |
| **Decrypt share (ms)** | `decryption` (last line) |
| **Transcript size** | `total=...` on the last line, or equivalently `ctxt + linProof + quadProof` |

Why the weird selection:
- `keyGens` is PKI setup; excluded from Deal.
- `aggregate` is where constraints get merged into the single linear + single quadratic bulletproof statement — it's part of producing the proof, so it counts toward Deal.
- `proveShamir` is the renamed `proveReShare` call. Despite the name, it's just the Shamir parity-check `H · [secret, share_1, …, share_n] = 0` — the PVSS structure proof. Keep it.

## Verifying the run

Both bulletproofs verify end-to-end; the binary prints `failed linear verification` / `failed quadratic verification` if not. Any output without those lines is a successful benchmark.

## Known gotchas

- **Don't run in parallel.** Each run uses ~1.5-3 GB RAM (dominated by `kay ≈ 2900` matrices) and fully saturates one core's memory bandwidth. Two concurrent runs slow each other ~2x.
- **Keygens dominate wall time**, not the thing we're benchmarking. In a real deployment those keys exist from before; the `n` keygens here are inline-setup for a self-contained bench.
- **`kay` is basically constant across `n`.** That's why Deal (~5.5-7s), Verify (~500ms), and transcript size (~178-202 KiB) grow very slowly with `n` — all the heavy work is on matrices sized by `kay`, not `n`.
- **Decrypt-share doesn't depend on `t` or `n`.** It's one lattice decryption ≈ 0.5 ms.
