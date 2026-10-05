"""
qiling_engine.py - Qiling engine: concretely drive a firmware
binary to a memory-corruption sink and OBSERVE the overwrite, recovering the offset.

Why Qiling (vs the qemu-user runner in emulate.py): these firmware daemons are
socket servers, so qemu-user cannot deliver a packet through an env var, and when a
daemon dies early you get an opaque crash. Qiling is Unicorn plus a scriptable OS
layer, so we can:
  - start at an arbitrary handler (skip the nvram/config bring-up),
  - inject a De Bruijn payload as the input (env var, or straight into a buffer we
    point an argument register at),
  - hook every block / memory access to see WHERE and WHY it diverges,
  - stub a missing syscall / nvram key in Python and continue.

Two distinct outcomes to keep apart (this is the whole point of tracing):
  * ENVIRONMENTAL fail: emulation stops because the binary needed something we did
    not model (a syscall, a file, an nvram key). Not the bug: bring-up. Hook it.
  * TARGET fail: the binary crashes on our input (bad PC fetch / wild write). The
    bug. Read the faulting value, cyclic_find -> offset.

Modes:
  run_env(...)     load + run from the entry point with the payload in an env var
                   (validates the harness on a known target like firm_sink_mipsel).
  run_handler(...) start at a function, set the argument registers, point one at a
                   payload buffer, trap the return; catch the saved-ra overwrite.
"""
import logging

logging.disable(logging.CRITICAL)
import sys

from .emulate import cyclic, cyclic_find

try:
    import unicorn
    from qiling import Qiling
    from qiling.const import QL_VERBOSE
except Exception as e:                              # importable even if qiling absent
    Qiling = None
    _IMPORT_ERR = e

# a mapped-but-never-code address we set as the return target, so a clean return
# lands here and we stop; an overwritten saved-ra lands in pattern bytes instead.
SENTINEL = 0x5eef0000

# where we stage the injected input string that a hooked source returns a pointer to
PAYLOAD_STAGE = 0x44440000

EXEC_SINKS = ("system", "popen", "execl", "execlp", "execv", "execve", "execvp")


def _elf_syms(path):
    """name -> address for defined symbols (symtab first, then dynsym); also indexes
    the MIPS `.pic.<name>` PIC veneers that calls actually target."""
    from elftools.elf.elffile import ELFFile
    out = {}
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        for secname in (".symtab", ".dynsym"):
            sec = elf.get_section_by_name(secname)
            if not sec:
                continue
            for sym in sec.iter_symbols():
                v = sym["st_value"]
                if sym.name and v:
                    out.setdefault(sym.name, v)
    return out


def _cstr(ql, addr, cap=0x400):
    try:
        raw = ql.mem.read(addr, cap)
    except Exception:
        return b""
    n = raw.find(b"\x00")
    return bytes(raw[: n if n >= 0 else cap])


def _hook_source(ql, addr, name, env_var, payload_ptr, state):
    """replace a getenv-style source: if it is asked for `env_var`, return a pointer
    to our staged payload; otherwise return NULL. Returns immediately (MIPS: set the
    return value in v0/a0-return reg and jump to $ra)."""
    def cb(ql_, *_):
        want = _cstr(ql_, ql_.arch.regs.read("a0"))
        if want == env_var.encode():
            state.setdefault("source_hit", name)
            ql_.arch.regs.write("v0", payload_ptr)
        else:
            ql_.arch.regs.write("v0", 0)
        ql_.arch.regs.write("pc", ql_.arch.regs.read("ra"))
    ql.hook_address(cb, addr)


def _hook_exec(ql, addr, name, payload, state):
    """capture the command handed to an exec-family sink: if our payload is in it,
    that is a confirmed injection reaching the shell."""
    def cb(ql_, *_):
        cmd = _cstr(ql_, ql_.arch.regs.read("a0"))
        hit = {"sink": name, "cmd": cmd[:200]}
        # did attacker bytes reach the command line?
        marker = payload[:8]
        hit["attacker_controlled"] = marker in cmd
        state.setdefault("exec_hit", hit)
        # returning cleanly is fine; stop so we can report
        ql_.arch.regs.write("v0", 0)
        ql_.arch.regs.write("pc", ql_.arch.regs.read("ra"))
        ql_.emu_stop()
    ql.hook_address(cb, addr)


# unicorn access ids for an instruction fetch (a jump/return): the real control
# hijack we want to catch. Everything else (16/17 read/write, 19/20 r/w unmapped)
# is a data access; an unmapped one is usually a bring-up gap, not the bug.
FETCH_ACCESS = (18, 21)


def _fault_hooks(ql, state, trace, map_data=False, map_cap=400):
    """install hooks that record the first faulting access and (optionally) a block
    trace. A fetch of an unmapped address is a control-flow hijack: record and stop.
    A data access to an unmapped address is a bring-up gap: if `map_data`, map the
    page and continue (capped), else record and stop. This split is what separates
    an ENVIRONMENTAL fail from a real overwrite."""
    def on_unmapped(ql_, access, addr, size, value):
        if int(access) in FETCH_ACCESS:             # jumped/returned into bad memory
            state.setdefault("fault", {"addr": addr, "size": size, "access": int(access)})
            return False
        if map_data and state.get("maps", 0) < map_cap:
            try:
                ql_.mem.map(addr & ~0xfff, 0x1000)
                state["maps"] = state.get("maps", 0) + 1
                return True                          # data gap: bring-up, keep going
            except Exception:
                pass
        state.setdefault("fault", {"addr": addr, "size": size, "access": int(access)})
        return False

    ql.hook_mem_unmapped(on_unmapped)

    if trace:
        state.setdefault("blocks", [])

        def on_block(ql_, addr, size):
            if len(state["blocks"]) < 4000:
                state["blocks"].append(addr)

        ql.hook_block(on_block)


def _classify(state, payload, arch_bits):
    """turn the recorded fault into a verdict + offset."""
    f = state.get("fault")
    if not f:
        return {"result": "NO_CRASH",
                "reason": "ran to completion / trap without an invalid access"}
    addr = f["addr"]
    for width in (arch_bits // 8, 4):
        off = cyclic_find(addr & ((1 << (width * 8)) - 1), width=width)
        if off >= 0:
            return {"result": "CRASH_CONTROLLED", "fault_addr": addr, "offset": off,
                    "width": width,
                    "reason": f"invalid access at {addr:#x} is De Bruijn offset "
                              f"{off:#x}: attacker bytes reached the control value"}
    return {"result": "CRASH_UNCONTROLLED", "fault_addr": addr,
            "reason": f"invalid access at {addr:#x}, not a pattern chunk "
                      "(wild pointer / environmental, not a clean control overwrite)"}


def run_env(binary, rootfs, env_var="HTTP_SOAPACTION", length=0x400,
            payload=None, trace=False, timeout=20_000_000, inject_hook=True):
    """Load `binary` under `rootfs` and run from the entry point with the payload
    delivered through $env_var. Also hooks the source (getenv) to inject the payload
    directly (env-array delivery to a static libc is unreliable) and the exec-family
    sinks to confirm command injection. Returns a verdict dict."""
    if Qiling is None:
        return {"result": "UNAVAILABLE", "reason": f"qiling import failed: {_IMPORT_ERR}"}
    if payload is None:
        payload = cyclic(length)
    state = {}
    ql = Qiling([binary], rootfs, env={env_var: payload.decode("latin1")},
                verbose=QL_VERBOSE.OFF)
    # stage the payload as a C string the source hook can return a pointer to
    ql.mem.map(PAYLOAD_STAGE, 0x4000)
    ql.mem.write(PAYLOAD_STAGE, payload + b"\x00")
    if inject_hook:
        syms = _elf_syms(binary)
        for base in ("getenv",):
            for nm in (base, ".pic." + base):
                if nm in syms:
                    _hook_source(ql, syms[nm], nm, env_var, PAYLOAD_STAGE, state)
        for base in EXEC_SINKS:
            for nm in (base, ".pic." + base):
                if nm in syms:
                    _hook_exec(ql, syms[nm], base, payload, state)
    _fault_hooks(ql, state, trace)
    try:
        ql.run(timeout=timeout)
    except unicorn.UcError as e:
        state.setdefault("fault", {"addr": ql.arch.regs.arch_pc, "size": 0,
                                   "access": -1, "uc": str(e)})
    except Exception as e:
        state.setdefault("exc", str(e))
    out = _classify(state, payload, ql.arch.bits)
    if state.get("exec_hit"):
        h = state["exec_hit"]
        out["result"] = "CMDI_CONFIRMED" if h["attacker_controlled"] else "SINK_REACHED"
        out["sink"] = h["sink"]
        out["command"] = h["cmd"].decode("latin1", "replace")
        out["reason"] = (f"attacker bytes reached {h['sink']}() command line"
                         if h["attacker_controlled"] else
                         f"{h['sink']}() reached but our bytes were not in the command")
    out["source_hooked"] = state.get("source_hit")
    if trace:
        out["blocks_executed"] = len(state.get("blocks", []))
    out["payload_len"] = len(payload)
    return out


def run_handler(binary, rootfs, func_addr, arg_regs=("a0",), payload=None,
                length=0x400, ctx_size=0x20000, trace=False, timeout=20_000_000,
                sink_addr=None):
    """Start execution at `func_addr`, point each register in `arg_regs` at a
    payload region filled with a De Bruijn pattern, trap the return at SENTINEL, and
    catch the saved-ra overwrite. For socket-daemon handlers that take the packet
    (or a context holding it) by pointer."""
    if Qiling is None:
        return {"result": "UNAVAILABLE", "reason": f"qiling import failed: {_IMPORT_ERR}"}
    if payload is None:
        payload = cyclic(length)
    state = {}
    # Qiling needs an argv[0]; we then reposition PC to the handler.
    ql = Qiling([binary], rootfs, verbose=QL_VERBOSE.OFF)
    # a payload region the argument(s) point at
    base = 0x33330000
    ql.mem.map(base, ctx_size)
    pat = (payload * (ctx_size // len(payload) + 1))[:ctx_size]
    ql.mem.write(base, pat)
    for r in arg_regs:
        ql.arch.regs.write(r, base)
    # trap the return
    ql.arch.regs.write("ra", SENTINEL)
    _fault_hooks(ql, state, trace)
    if sink_addr is not None:
        def on_sink(ql_, *_):
            # record the sink's dest/len args when we hit it (MIPS o32: a0,a1,a2)
            state["sink_hit"] = {"a0": ql_.arch.regs.read("a0"),
                                 "a1": ql_.arch.regs.read("a1"),
                                 "a2": ql_.arch.regs.read("a2")}
        ql.hook_address(on_sink, sink_addr)
    try:
        ql.run(begin=func_addr, end=SENTINEL, timeout=timeout)
    except unicorn.UcError as e:
        state.setdefault("fault", {"addr": ql.arch.regs.arch_pc, "size": 0,
                                   "access": -1, "uc": str(e)})
    except Exception as e:
        state.setdefault("exc", str(e))
    out = _classify(state, payload, ql.arch.bits)
    if "sink_hit" in state:
        out["sink_args"] = {k: hex(v) for k, v in state["sink_hit"].items()}
    if "exc" in state and out["result"] == "NO_CRASH":
        out["result"] = "STOPPED"
        out["reason"] = "stopped before any invalid access: " + state["exc"]
    if trace:
        out["blocks_executed"] = len(state.get("blocks", []))
    out["payload_len"] = len(payload)
    return out


def run_recv(binary, rootfs, func_addr, main_addr, payload=None, length=0x600,
             ctx_size=0x20000, block_cap=3_000_000, trace=True):
    """Socket-daemon confirmation. Run through the dynamic loader / libc startup
    (so the GOT is relocated), hijack at `main_addr` into the handler at `func_addr`
    with a zeroed context in $a0, inject the payload into any recv/recvfrom/read
    buffer (via set_api), trap the return at SENTINEL, and catch the saved-ra
    overwrite. Hard-capped so it reports instead of hanging.

    Caveat: this needs the target's ld/libc startup to COMPLETE under Qiling. Some
    uClibc-MIPS firmware images do not start up cleanly yet (the loader relocates
    into an unmapped region); for those this returns STARTUP_INCOMPLETE, which is a
    bring-up problem to fix, not a statement about the bug."""
    if Qiling is None:
        return {"result": "UNAVAILABLE", "reason": f"qiling import failed: {_IMPORT_ERR}"}
    if payload is None:
        payload = cyclic(length)
    state = {"maps": 0}
    ql = Qiling([binary], rootfs, verbose=QL_VERBOSE.OFF)
    ctx = 0x33330000
    ql.mem.map(ctx, ctx_size)
    ql.mem.write(ctx, b"\x00" * ctx_size)
    ql.mem.map(SENTINEL & ~0xFFF, 0x1000)

    def recv_hook(ql_, *_):
        buf = ql_.arch.regs.read("a1")
        try:
            ql_.mem.write(buf, payload)
            state["recv_fired"] = state.get("recv_fired", 0) + 1
        except Exception:
            pass
        ql_.arch.regs.write("v0", len(payload))
        ql_.arch.regs.write("pc", ql_.arch.regs.read("ra"))

    from qiling.const import QL_INTERCEPT
    for nm in ("recvfrom", "recv", "read", "recvmsg"):
        try:
            ql.os.set_api(nm, recv_hook, QL_INTERCEPT.CALL)
        except Exception:
            pass

    def at_main(ql_, *_):
        if state.get("hijacked"):
            return
        state["hijacked"] = True
        ql_.arch.regs.write("a0", ctx)
        ql_.arch.regs.write("ra", SENTINEL)
        ql_.arch.regs.write("pc", func_addr)
    ql.hook_address(at_main, main_addr)

    _fault_hooks(ql, state, trace, map_data=True)
    n = {"b": 0}

    def cap(ql_, addr, size):
        n["b"] += 1
        if n["b"] > block_cap or addr == SENTINEL:
            ql_.emu_stop()
    ql.hook_block(cap)

    try:
        ql.run()
    except unicorn.UcError as e:
        state.setdefault("fault", {"addr": ql.arch.regs.arch_pc, "access": -1, "uc": str(e)})
    except Exception as e:
        state.setdefault("exc", str(e))

    if not state.get("hijacked"):
        return {"result": "STARTUP_INCOMPLETE", "blocks": n["b"],
                "reason": "ld/libc startup did not reach main under Qiling "
                          "(bring-up gap), so the handler was never entered"}
    out = _classify(state, payload, ql.arch.bits)
    out["blocks_after_hijack"] = n["b"]
    out["recv_injected"] = state.get("recv_fired", 0)
    out["payload_len"] = len(payload)
    return out


def main():
    a = sys.argv[1:]
    if len(a) < 2:
        print("usage:")
        print("  qiling_engine.py env     BINARY ROOTFS [ENV_VAR] [len]")
        print("  qiling_engine.py handler BINARY ROOTFS FUNC_ADDR [argregs a0,a1] [len]")
        print("  qiling_engine.py recv    BINARY ROOTFS FUNC_ADDR MAIN_ADDR [len]")
        return
    mode, binary, rootfs = a[0], a[1], a[2] if len(a) > 2 else "."
    print("=" * 78)
    print(f"QILING {mode}: {binary}")
    if mode == "env":
        env_var = a[3] if len(a) > 3 else "HTTP_SOAPACTION"
        length = int(a[4], 0) if len(a) > 4 else 0x400
        r = run_env(binary, rootfs, env_var, length, trace=True)
    elif mode == "recv":
        func_addr = int(a[3], 0)
        main_addr = int(a[4], 0)
        length = int(a[5], 0) if len(a) > 5 else 0x600
        r = run_recv(binary, rootfs, func_addr, main_addr, length=length)
    else:
        func_addr = int(a[3], 0)
        argregs = tuple(a[4].split(",")) if len(a) > 4 else ("a0",)
        length = int(a[5], 0) if len(a) > 5 else 0x400
        r = run_handler(binary, rootfs, func_addr, argregs, length=length, trace=True)
    for k, v in r.items():
        print(f"  {k:16}: {v}")


if __name__ == "__main__":
    main()
