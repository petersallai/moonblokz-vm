# moonblokz-vm

Bytecode execution engine for MoonBlokz chain-configuration parameters — a `no_std`, no-alloc stack machine over `u64` with fuel accounting and a single host seam (FR56).

- `no_std`, no-alloc, **no dependencies at all** — nothing beyond `core`. The dependency-graph gate (`cargo tree -p moonblokz-vm -e normal | grep -iE 'embassy|alloc'`) is empty, which is what keeps `moonblokz-blockchain` host-testable without an async runtime once it depends on this crate transitively.
- No `unsafe`, so no Miri obligation.
- Carries **no MoonBlokz domain concepts**. It receives a program, its arguments, a fuel budget and a host handle, and returns a typed outcome. What a parameter *is*, what the fuel limit should be, and what to do when a program fails all stay in `moonblokz-configuration`. That is also why the post-MVP smart-contract runtime can build on the same engine.

## Shape

`Vm<STACK_DEPTH, LOCAL_SLOTS, MAX_NESTING>::execute(program, args, fuel, host) -> VmOutcome`

The three bounds are the caller's: the operand stack and the local-slot array are the crate's only allocations, and their sizes follow from the memory budget of whoever hosts the VM. `VmOutcome` is `Completed(u64)`, `Trapped(TrapReason)` or `OutOfFuel` — the VM reports, it does not decide, so mapping a failure onto a fallback is the caller's policy.

## Correctness properties

Every value computed here feeds a consensus decision, so determinism is the correctness property rather than a quality goal:

- **Every arithmetic instruction is total.** Division and modulo by zero yield `0`, shifts of 64 or more yield `0`, subtraction saturates at `0`, addition and multiplication saturate at `u64::MAX`. What remains able to fail is structural — fuel, stack depth, nesting — never arithmetic.
- **Initial state is fully defined.** Local slots are zero-initialised; no instruction can read state that was never written.
- **Nothing node-local or non-deterministic is reachable.** No clock, no randomness, and no instruction that reads the remaining fuel — a program that could branch on its budget would freeze the cost table forever.
- **There is no load-time verifier**, deliberately. Fuel, stack depth and nesting are not decidable ahead of a run once the instruction set has backward jumps, so the runtime has to be total regardless; a verifier would duplicate a subset of the same checks in a second code path. Structural diagnostics belong in `vm-asm`.
- **Fuel is charged per instruction from a cost table** and is one budget per invocation, shared across `GETPARAM` nesting. Per-sub-evaluation budgets would let a program compose arbitrarily many sub-evaluations and evade the bound entirely.

## Tools

Two `std` binaries, each a **separate package** under `tools/` rather than a feature of the library — Cargo unifies features per package, so a `std` tool target sharing this package could pull `std` into the library's own build.

```
cargo run -p moonblokz-vm-asm -- program.asm -o program.bin
cargo run -p moonblokz-vm-dis -- --hex "70 01 00 10 02 43 01"
```

`vm-asm` is the only place structural mistakes are diagnosed, and it is a library as well as a binary because `config-encoder` assembles configuration bytecode itself. `vm-dis` emits the canonical text, and the round trip through both — `assemble(disassemble(bytes)) == bytes` — is the conformance test for the instruction set.

## Design authority

`moonblokz-info/moonblokz-configuration-specification.md` §7 (machine model, bytecode format, limits and failure, host seam, non-features, versioning) and §11 (tooling). Where this crate and that specification differ, the specification wins.

Implementation tracked story-by-story in `_bmad-output/implementation-artifacts/sprint-status.yaml` (Story 5.6).
