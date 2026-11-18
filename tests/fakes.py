"""In-memory fake devices so the whole plan/apply/rollback flow is testable without hardware."""
from netmcp.errors import ConnectionFailed


class FakeNet:
    def __init__(self, vendor="cisco_ios"):
        self.family = "mikrotik" if vendor.startswith("mikrotik") else "cisco"
        self.config = (["/ip address add address=192.0.2.1/24 interface=ether1"] if self.family == "mikrotik"
                       else ["hostname r1", "interface GigabitEthernet0/0", " ip address 192.0.2.1 255.255.255.0"])
        self.timer_armed = False
        self.saved = False
        self.log = []
        self.connects = 0
        self.fail_connect_from = None  # fail the Nth and later connections (simulates lockout)
        self.bad_apply = False
        self.arm_fails = False
        self.cancel_fails = False

    def connect(self, device):
        self.connects += 1
        if self.fail_connect_from and self.connects >= self.fail_connect_from:
            raise ConnectionFailed("lost management access")
        return FakeConn(self)


class FakeConn:
    def __init__(self, net):
        self.n = net
        self.pending = False

    def disconnect(self):
        pass

    def save_config(self):
        self.n.saved = True
        return ""

    def send_command(self, cmd, **kw):
        n = self.n
        n.log.append(cmd)
        if n.family == "cisco":
            if cmd.startswith("show running-config"):
                return "\n".join(n.config)
            if cmd == "show reload":
                return "Reload scheduled for 12:00 (in 5 minutes)" if n.timer_armed else "No reload is scheduled."
            if cmd == "show clock":
                return "12:00:00 UTC"
            if cmd.startswith("show "):
                return f"out:{cmd}"
            return ""
        if cmd.startswith("/export"):
            return "\n".join(n.config)
        if cmd.startswith("/system scheduler add"):
            if n.arm_fails:
                return "failure: cannot add scheduler"
            n.timer_armed = True
            return ""
        if cmd == "/system scheduler print where name=netmcp-rollback":
            return "0 name=netmcp-rollback" if n.timer_armed else ""
        if cmd.startswith("/system scheduler remove"):
            if not n.cancel_fails:
                n.timer_armed = False
            return ""
        if cmd == "/system scheduler print count-only where name=netmcp-rollback":
            return "1" if n.timer_armed else "0"
        if cmd == "/system identity print":
            return "name: r1"
        if "print" in cmd:
            return "0 R name=ether1 mtu=1500\n1 name=ether2 mtu=1500"
        return ""

    def send_command_timing(self, cmd, **kw):
        n = self.n
        n.log.append(cmd)
        if cmd.startswith("reload in"):
            if n.arm_fails:
                return "% Invalid input"
            self.pending = True
            return "Proceed with reload? [confirm]"
        if cmd == "" and self.pending:
            n.timer_armed = True
            self.pending = False
            return "Reload scheduled"
        if cmd == "reload cancel" and not n.cancel_fails:
            n.timer_armed = False
        return ""

    def send_config_set(self, lines, **kw):
        n = self.n
        n.log.append(("config", list(lines)))
        if n.bad_apply:
            return "% Invalid input detected at '^' marker." if n.family == "cisco" else "bad command name foo (line 1 column 1)"
        n.config.extend(lines)
        return ""
