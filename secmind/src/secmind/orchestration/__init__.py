"""Cohesive helpers used by the orchestration façade.

Modules in this package must not own global run state or bypass the durable
checkpoint, policy, budget, or ToolBroker boundaries.
"""
