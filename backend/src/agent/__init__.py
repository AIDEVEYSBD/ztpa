"""The review agent: an LLM that ORCHESTRATES deterministic engine tools.

It reasons and explains; it calls the engine for every fact. It never
reimplements reachability or subnet math. See agent/tools.py for the tool set
(named per the Review Agent doc) and agent/assistant.py for the tool-calling loop.
"""
