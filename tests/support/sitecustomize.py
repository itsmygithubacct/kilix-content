"""Loaded when tests/support is on PYTHONPATH: refuse the live store and the network."""

from live_store_guard import install
from network_guard import install as install_network_guard

install()
install_network_guard()
