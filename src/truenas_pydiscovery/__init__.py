"""Unified discovery daemon orchestrator.

Hosts the mDNS, NetBIOS Name Service, and WS-Discovery server classes
in a single process/event loop under ``truenas-pydiscoveryd``.

The per-protocol packages (``truenas_pymdns``, ``truenas_pynetbiosns``,
``truenas_pywsd``) remain importable as libraries — this package
provides the consolidated daemon entry point and config schema.
"""
