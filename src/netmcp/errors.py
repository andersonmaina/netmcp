class NetmcpError(Exception):
    code = "error"
    exit_code = 1

    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message)
        self.hint = hint


class ConfigError(NetmcpError):
    code = "config_error"


class PolicyDenied(NetmcpError):
    code = "policy_denied"
    exit_code = 2


class ApprovalRequired(NetmcpError):
    code = "approval_required"
    exit_code = 3


class ConnectionFailed(NetmcpError):
    code = "connection_failed"
    exit_code = 4


class DeviceError(NetmcpError):
    code = "device_error"
    exit_code = 5


class VerifyFailed(DeviceError):
    code = "verify_failed"


class NotFound(NetmcpError):
    code = "not_found"
    exit_code = 6
