from .cisco import CiscoDriver
from .mikrotik import MikroTikDriver


def get_driver(device):
    return CiscoDriver(device) if device.family == "cisco" else MikroTikDriver(device)
