from jostedal import stun

MSG_CHANNEL = 0b01


METHOD_ALLOCATE = 0x003  # only request/response semantics defined
METHOD_REFRESH = 0x004  # only request/response semantics defined
METHOD_SEND = 0x006  # only indication semantics defined
METHOD_DATA = 0x007  # only indication semantics defined
METHOD_CREATE_PERMISSION = 0x008  # only request/response semantics defined
METHOD_CHANNEL_BIND = 0x009  # only request/response semantics defined


ATTR_CHANNEL_NUMBER = 0x000C
ATTR_LIFETIME = 0x000D
ATTR_XOR_PEER_ADDRESS = 0x0012
ATTR_DATA = 0x0013
ATTR_XOR_RELAYED_ADDRESS = 0x0016
ATTR_EVEN_PORT = 0x0018
ATTR_REQUESTED_TRANSPORT = 0x0019
ATTR_DONT_FRAGMENT = 0x001A
ATTR_RESERVATION_TOKEN = 0x0022


TRANSPORT_UDP = 0x11


# Error codes (class, number) and recommended reason phrases:
class ForbiddenError(stun.Error):
    error_code = 403
    reason = "Forbidden"

class AllocationMismatchError(stun.Error):
    error_code = 437
    reason = "Allocation Mismatch"

class WrongCredentialsError(stun.Error):
    error_code = 441
    reason = "Wrong Credentials"

class UnsupportedTransportProtocolError(stun.Error):
    error_code = 442
    reason = "Unsupported Transport Protocol"

class AllocationQuotaReachedError(stun.Error):
    error_code = 486
    reason = "Allocation Quota Reached"

class InsufficientCapacityError(stun.Error):
    error_code = 508
    reason = "Insufficient Capacity"
