"""
emulate.py - fire a proof-of-vulnerability input at the
real binary and OBSERVE the crash, closing the loop from static analysis to a
dynamically-triggered fault.

Runner selection:
  native  x86-64/x86 targets run directly on the host.
  qemu    other ISAs run under qemu-<arch>-static IF the binary is statically
          linked (no target libraries needed). A DYNAMIC cross-arch binary needs
          its firmware root filesystem (interpreter + libs); without a sysroot we
          honestly report that it cannot be run here.

What it does:
  - build a De Bruijn payload (so the crash address reveals the overflow offset),
  - set it in the chosen environment variable (default HTTP_SOAPACTION) and run,
  - classify the outcome by signal (SIGSEGV=11, SIGABRT=6 stack-smashing),
  - on native targets, use gdb to read the faulting PC and map it back to an
    offset (cyclic_find), which cross-checks the static 'room' number.
"""
import os
import subprocess
import sys


def cyclic(length, width=4, alphabet=b"abcdefghijklmnopqrstuvwxyz"):
    """First `length` bytes of a De Bruijn sequence B(len(alphabet), width): every
    aligned `width`-byte window is unique, so an overwritten chunk locates its
    offset (the pwntools cyclic idea)."""
    k, n = len(alphabet), width
    a = [0] * (k * n)
    seq = []

    def db(t, p):
        if len(seq) >= length:
            return
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    if len(seq) >= length:
                        return
                    seq.append(a[j])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return bytes(alphabet[i] for i in seq[:length])


def cyclic_find(sub, width=4, alphabet=b"abcdefghijklmnopqrstuvwxyz"):
    if isinstance(sub, int):
        sub = sub.to_bytes(width, "little")
    pat = cyclic(0x8000, width, alphabet)
    return pat.find(sub)


EM_QEMU = {
    ("EM_MIPS", True): "qemu-mipsel-static", ("EM_MIPS", False): "qemu-mips-static",
    ("EM_ARM", True): "qemu-arm-static", ("EM_AARCH64", True): "qemu-aarch64-static",
    ("EM_PPC", False): "qemu-ppc-static", ("EM_PPC64", False): "qemu-ppc64-static",
}


def elf_info(path):
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as f:
        elf = ELFFile(f)
        machine = elf["e_machine"]
        little = elf.little_endian
        static = not any(seg["p_type"] == "PT_INTERP" for seg in elf.iter_segments())
    return machine, little, static


def runner_for(path):
    """return (argv_prefix, can_run, reason)."""
    machine, little, static = elf_info(path)
    if machine in ("EM_X86_64", "EM_386"):
        return [], True, "native"
    q = EM_QEMU.get((machine, little))
    if q is None:
        return None, False, f"no qemu runner for {machine}"
    if not static:
        return None, False, (f"{machine} is dynamically linked; needs the firmware "
                             "root filesystem (interpreter + libs) as a qemu sysroot")
    if subprocess.run(["bash", "-c", f"command -v {q}"], capture_output=True).returncode:
        return None, False, f"{q} not installed"
    return [q], True, f"qemu ({q}, static)"


def _executable_copy(path):
    """qemu / native exec need the +x bit; copy to a temp path we can chmod."""
    import shutil
    import tempfile
    d = tempfile.mkdtemp(prefix="emu_")
    dst = os.path.join(d, os.path.basename(path))
    shutil.copy(path, dst)
    os.chmod(dst, 0o755)
    return dst


def gdb_offset(path, env):
    """native only: run under gdb, find the De Bruijn chunk in a register at the
    crash, map it to an offset. Uses a +x copy so gdb's `run` can exec."""
    if subprocess.run(["bash", "-c", "command -v gdb"], capture_output=True).returncode:
        return None
    exe = _executable_copy(path)
    try:
        r = subprocess.run(
            ["gdb", "-q", "-batch", "-nx", "-ex", "run", "-ex", "info registers",
             "--args", exe],
            env={**os.environ, **env}, capture_output=True, text=True, timeout=40)
    except Exception:
        return None
    finally:
        try:
            os.remove(exe)
            os.rmdir(os.path.dirname(exe))
        except Exception:
            pass
    # scan ALL registers for a De Bruijn chunk: the overflow may land in the saved
    # frame pointer (rbp) or a saved register, not necessarily the PC.
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[0].isalnum():
            continue
        try:
            val = int(parts[1], 16)
        except ValueError:
            continue
        for width in (8, 4):
            chunk = val & ((1 << (width * 8)) - 1)
            if chunk < 0x20202020:
                continue
            off = cyclic_find(chunk, width=width)
            if off >= 0:
                return (off, parts[0])
    return None


def fire(path, env_var="HTTP_SOAPACTION", length=600, timeout=30, payload=None):
    prefix, can_run, reason = runner_for(path)
    if not can_run:
        return {"result": "CANNOT_RUN", "reason": reason}
    if payload is None:
        payload = cyclic(length)          # De Bruijn so the crash reveals the offset
    if isinstance(payload, str):
        payload = payload.encode("latin1", "replace")
    env = {env_var: payload.decode("latin1", "replace")}
    exe = _executable_copy(path)
    try:
        r = subprocess.run(prefix + [exe], env={**os.environ, **env},
                           capture_output=True, timeout=timeout)
        rc = r.returncode
    except subprocess.TimeoutExpired:
        return {"result": "TIMEOUT", "runner": reason}
    finally:
        try:
            os.remove(exe)
            os.rmdir(os.path.dirname(exe))
        except Exception:
            pass
    crashed = rc < 0 or rc >= 128
    sig = (-rc) if rc < 0 else (rc - 128 if rc >= 128 else 0)
    signame = {11: "SIGSEGV", 6: "SIGABRT/stack-smashing", 4: "SIGILL",
               7: "SIGBUS"}.get(sig, f"signal {sig}" if sig else "none")
    out = {"result": "CRASH" if crashed else "NO_CRASH", "runner": reason,
           "signal": signame, "rc": rc}
    if crashed and prefix == []:                       # native: try to get the offset
        og = gdb_offset(path, env)
        if og is not None:
            out["offset"], out["offset_reg"] = og
    return out


def oracle(path, env_var="HTTP_SOAPACTION", length=600, payload=None):
    """PoV oracle: (ok|None, feedback)."""
    r = fire(path, env_var, length, payload=payload)
    if r["result"] == "CANNOT_RUN":
        return None, "emulation cannot run this binary: " + r["reason"]
    if r["result"] == "CRASH":
        extra = f", offset {r['offset']:#x}" if "offset" in r else ""
        return True, f"crash observed ({r['signal']}){extra} under {r['runner']}"
    return False, f"no crash ({r['result']}) under {r['runner']}"


def run(path, env_var="HTTP_SOAPACTION", length=600):
    """Fire a De Bruijn payload at `path` via $env_var under the native/qemu runner
    and print the outcome (crash + recovered offset, or why it could not run)."""
    print("=" * 78)
    print("BINARY:", path)
    machine, little, static = elf_info(path)
    print(f"  elf: {machine} {'LE' if little else 'BE'} "
          f"{'static' if static else 'dynamic'}")
    r = fire(path, env_var, length)
    print(f"  runner : {r.get('runner', '-')}")
    print(f"  result : {r['result']}", end="")
    if r["result"] == "CRASH":
        print(f"  ({r['signal']}, rc={r['rc']})", end="")
        if "offset" in r:
            print(f"   dynamic overflow offset = {r['offset']:#x} "
                  f"(in {r.get('offset_reg', '?')})", end="")
    print()
    if r.get("reason"):
        print(f"  reason : {r['reason']}")
    return 0 if r["result"] in ("CRASH", "NO_CRASH") else 1


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="vexhound emulate (qemu)",
        description="Fire a PoV payload at a binary and observe the crash.")
    ap.add_argument("target", help="binary to run")
    ap.add_argument("--env-var", default="HTTP_SOAPACTION",
                    help="environment variable that carries the payload")
    ap.add_argument("--length", type=int, default=600, help="De Bruijn payload length")
    a = ap.parse_args(argv)
    return run(a.target, a.env_var, a.length)


if __name__ == "__main__":
    sys.exit(main())
