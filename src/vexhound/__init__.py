"""VexHound: architecture-neutral firmware memory-safety analysis over VEX IR.

VexHound lifts firmware binaries to VEX IR with angr and finds memory-safety bugs
(primarily stack-buffer overflows, plus command injection and format strings) by
reasoning over the IR rather than per-CPU disassembly, so one analysis covers MIPS,
ARM, PowerPC, x86 and more. See the submodules for the individual pipeline stages.
"""

__version__ = "0.1.0"
