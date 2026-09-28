# Hetzer Documentation Pack

This documentation pack describes the current direction and long-term architecture of Hetzer.

## Core thesis

> Hetzer is a security boundary for agentic systems.

Hetzer should protect not only credentials, but also private knowledge, memory, tool execution, and infrastructure from accidental or unauthorized agent behavior.

## Document map

- `VISION.md` — product vision and principles
- `ARCHITECTURE.md` — target architecture
- `JEV.md` — JEV concept and research direction
- `AGENTIC-SAFETY.md` — protection against honest but dangerous agent mistakes
- `MEMORY-SECURITY.md` — protected RAG, vector DB, and second-brain memory
- `SECRET-SECURITY.md` — zero-plaintext credential architecture
- `POLICY-ENGINE.md` — policy model and examples
- `CAPABILITY-MODEL.md` — dynamic, scoped capabilities
- `MCP-SECURITY.md` — MCP/tool security
- `THREAT-MODEL.md` — threats and security assumptions
- `ROADMAP.md` — staged implementation roadmap
- `DESIGN-PRINCIPLES.md` — engineering principles
- `EXAMPLES.md` — concrete scenarios
- `OPEN-QUESTIONS.md` — unresolved research questions

## Status

This is a design document, not a statement that all described capabilities currently exist.

Features must be marked separately as:

- **Implemented**
- **Prototype**
- **Planned**
- **Research**

Security claims must be supported by tests and documented assumptions.
