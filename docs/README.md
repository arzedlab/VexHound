# Documentation

- [`understanding-vexhound.md`](understanding-vexhound.md) is the guided
  introduction. Start here if you can read code but are new to binary analysis, IR,
  or vulnerability research. It explains, from first principles, what the tool does,
  how a binary becomes IR, how IR becomes a bug finding, and how findings are
  verified.
- [`llm-harness.md`](llm-harness.md) documents the optional `vexhound hunt-llm`
  layer: how a language model proposes candidates that the prover and symbolic
  engine must mechanically verify before anything is reported.

The top-level [`README.md`](../README.md) covers installation, the command-line
interface, and the project layout.
