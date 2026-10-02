"""MCP tool layer — idempotent, structured JSON, shared across swarms.

Each server is a module with tool functions; the swarm runtime calls them
via A2A envelopes (task_id = ledger run id). No tool silently accepts risk
or changes pack constants.
"""
