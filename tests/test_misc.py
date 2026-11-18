import json

import pytest
import yaml

from netmcp.drivers.mikrotik import parse_terse
from netmcp.errors import ConfigError, ConnectionFailed
from netmcp.home import Home
from netmcp.inventory import Device, Inventory, credentials
from netmcp.redact import redact


@pytest.mark.parametrize("raw,leak", [
    ("username bob secret 9 $9$abcdef", "$9$abcdef"),
    ("enable password 7 0822455D0A16", "0822455D0A16"),
    ("snmp-server community s3cr3t RO", "s3cr3t"),
    ("/user add name=x password=hunter2 group=full", "hunter2"),
    ('/interface wireless security-profiles set pre-shared-key="my pass phrase"', "my pass phrase"),
    ("enable secret hunter2", "hunter2"),
])
def test_redaction(raw, leak):
    assert leak not in redact(raw)


def test_password_in_inventory_rejected(tmp_path):
    p = tmp_path / "inv.yaml"
    p.write_text(yaml.safe_dump({"devices": {"r1": {"host": "h", "vendor": "cisco_ios", "username": "u", "password": "x"}}}))
    with pytest.raises(ConfigError):
        Inventory.load(p)


def test_credentials_from_env():
    d = Device("lab-r1", "h", "cisco_ios", "u")
    pw, secret = credentials(d, {"NETMCP_LAB_R1_PASSWORD": "pw", "NETMCP_SECRET": "en"})
    assert (pw, secret) == ("pw", "en")


def test_missing_credentials_has_hint():
    d = Device("r1", "h", "cisco_ios", "u")
    with pytest.raises(ConnectionFailed) as e:
        credentials(d, {})
    assert "NETMCP_R1_PASSWORD" in e.value.hint


def test_parse_terse():
    rows = parse_terse('0 R name=ether1 mtu=1500 comment="uplink to isp"\n1 name=ether2 mtu=1500')
    assert rows[0] == {"_id": "0", "name": "ether1", "mtu": "1500", "comment": "uplink to isp"}
    assert rows[1]["name"] == "ether2"
