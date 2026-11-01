class TunnelCtlError(Exception):
    exit_code = 1


class InputError(TunnelCtlError):
    exit_code = 2


class NotFound(TunnelCtlError):
    exit_code = 3


class Conflict(TunnelCtlError):
    exit_code = 4
