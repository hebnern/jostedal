from jostedal.stun.server import StunUdpServer
from jostedal import turn, stun
from jostedal.stun.attributes import ErrorCode, XorMappedAddress
from jostedal.turn.attributes import XorRelayedAddress, ReservationToken, Lifetime
from jostedal.stun.agent import Address
from jostedal.turn.relay import Relay, ChannelMessage


class TurnUdpServer(StunUdpServer):
    max_lifetime = 3600
    default_lifetime = 600

    def __init__(
        self, reactor, interface, port, software, credential_mechanism, overrides={}
    ):
        StunUdpServer.__init__(self, reactor, interface, port, software, overrides)
        self._relays = {}
        self.credential_mechanism = credential_mechanism

        self._handlers.update(
            {
                # Allocate handlers
                (turn.METHOD_ALLOCATE, stun.CLASS_REQUEST): self._stun_allocate_request,
                # Refresh handlers
                (turn.METHOD_REFRESH, stun.CLASS_REQUEST): self._stun_refresh_request,
                # Create permission handlers
                (
                    turn.METHOD_CREATE_PERMISSION,
                    stun.CLASS_REQUEST,
                ): self._stun_create_permission_request,
                # Send handlers
                (turn.METHOD_SEND, stun.CLASS_INDICATION): self._stun_send_indication,
                # ChannelBind handler
                (
                    turn.METHOD_CHANNEL_BIND,
                    stun.CLASS_REQUEST,
                ): self._stun_channel_bind_request,
            }
        )

    def _stun_allocate_request(self, msg, addr):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-6.2
        """
        # Detect retransmission, resend success response
        relay_allocation = self._relays.get(addr)
        if relay_allocation and relay_allocation.transaction_id == msg.transaction_id:
            # TODO: handle allocate retransmission
            raise NotImplementedError("Allocation retransmission")

        # 1. require request to be authenticated
        self.credential_mechanism.authenticate(msg)

        # 2. Check if the 5-tuple is currently in use
        if relay_allocation:
            raise turn.AllocationMismatchError()

        # 3. Check REQUESTED-TRANSPORT attribute
        requested_transport = msg.get_attr(turn.ATTR_REQUESTED_TRANSPORT)
        if not requested_transport:
            raise stun.BadRequestError()
        elif requested_transport.protocol != turn.TRANSPORT_UDP:
            raise turn.UnsupportedTransportProtocolError()

        # 4. handle DONT-FRAGMENT attribute

        # 5. Check RESERVATION-TOKEN attribute
        reservation_token = msg.get_attr(turn.ATTR_RESERVATION_TOKEN)
        even_port = msg.get_attr(turn.ATTR_EVEN_PORT)
        if reservation_token:
            if even_port:
                pass  # TODO: reject with 400
            relay_addr = self.get_reserved_transport_address(reservation_token)
            # TODO: check that token is in range and has not expired
            # and that corresponding relayed address is still available
            # if token not valid, reject with 508
        # 7. reject with 486 if username allocation quota reached
        # 8. reject with 300 if we want to redirect to another server RFC5389
        # 6. Check EVEN-PORT
        else:
            relay, token = self._allocate_relay_addr(even_port, addr)
            relay.transaction_id = msg.transaction_id
            relay_addr = relay.relay_addr

        # Determine initial time-to-expiry
        time_to_expiry = self._time_to_expiry(msg.get_attr(turn.ATTR_LIFETIME))

        response = msg.create_response(stun.CLASS_RESPONSE_SUCCESS)
        response.add_attr(XorRelayedAddress, *relay_addr)
        if token:
            response.add_attr(ReservationToken, token)
        response.add_attr(Lifetime, time_to_expiry)
        family = Address.aftof(self.transport.addressFamily)
        host, port = self.overrides.get("mapped_address", addr)
        response.add_attr(XorMappedAddress, family, port, host)

        self.respond(response, addr)

    def _allocate_relay_addr(self, even_port, addr):
        """
        :param even_port: If True, the allocated addres port number will be even
        :param even_port.reserve: Wether to reserve the next port number and assign a token
                #TODO: find pair of port-numbers N, N+1 on same IP where
                #      N is even, set relayed transport addr with N and
                #      reserve N+1 for atleast 30s (until N released)
                #      and assign a token to that reservation
        """
        if even_port:
            raise NotImplementedError("EVEN-PORT handling")
        relay = Relay.allocate(self, addr)
        self._relays[addr] = relay
        return relay, None

    def _time_to_expiry(self, lifetime):
        if lifetime:
            time_to_expiry = max(
                self.default_lifetime, min(self.max_lifetime, lifetime.time_to_expiry)
            )
        else:
            time_to_expiry = self.default_lifetime
        return time_to_expiry

    def _stun_refresh_request(self, msg, addr):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-7.2
        """
        lifetime = msg.get_attr(turn.ATTR_LIFETIME)
        if lifetime and lifetime.time_to_expiry == 0:
            desired_lifetime = 0
        else:
            desired_lifetime = self._time_to_expiry(lifetime)

        if desired_lifetime:
            response = msg.create_response(stun.CLASS_RESPONSE_SUCCESS)
            response.add_attr(Lifetime, desired_lifetime)
            self.respond(response, addr)
        elif addr in self._relays:
            del self._relays[addr]

    def _stun_create_permission_request(self, msg, addr):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-9.2
        """
        # 1. require request to be authenticated
        message_integrity = msg.get_attr(stun.ATTR_MESSAGE_INTEGRITY)
        if not message_integrity:
            raise stun.UnauthorizedError()

        relay = self._relays[addr]
        peer_addr = msg.get_attr(turn.ATTR_XOR_PEER_ADDRESS)
        relay.add_permission(peer_addr.address)
        response = msg.create_response(stun.CLASS_RESPONSE_SUCCESS)
        self.respond(response, addr)

    def _stun_send_indication(self, msg, addr):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-10.2
        """
        # TODO: [preliminary implementation]
        relay = self._relays[addr]
        peer_addr = msg.get_attr(turn.ATTR_XOR_PEER_ADDRESS)
        data = msg.get_attr(turn.ATTR_DATA)
        relay.send(data, (peer_addr.address, peer_addr.port))

    def _stun_channel_bind_request(self, msg, addr):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-11.2
        """
        # 1. require request to be authenticated
        message_integrity = msg.get_attr(stun.ATTR_MESSAGE_INTEGRITY)
        if not message_integrity:
            raise stun.UnauthorizedError()

        # 2. require CHANNEL-NUMBER and XOR-PEER-ADDRESS attributes
        # 3. require channel number is in valid range (0x4000 - 0x4FFF inclusive)
        # 4. require channel number is not currently bound to a different transport address (same transport address is OK)
        # 5. require transport address is not currently bound to a different channel number

        relay = self._relays[addr]
        peer_addr = msg.get_attr(turn.ATTR_XOR_PEER_ADDRESS)
        channel_number = msg.get_attr(turn.ATTR_CHANNEL_NUMBER)
        relay.bind_channel(channel_number.channel_number, peer_addr)
        response = msg.create_response(stun.CLASS_RESPONSE_SUCCESS)
        self.respond(response, addr)

    def _stun_unhandled_datagram(self, datagram, addr):
        msg_type = datagram[0] >> 6
        if msg_type == turn.MSG_CHANNEL:
            msg = ChannelMessage.decode(datagram)
            relay = self._relays[addr]
            relay.send_channel(msg.channel_number, memoryview(msg)[4:])
        else:
            super()._stun_unhandled_datagram(datagram, addr)

    def __str__(self):
        return (
            "interface={0.interface}, port={0.port}, "
            "{0.credential_mechanism}".format(self)
        )

    def __repr__(self):
        return "TurnUdpServer({})".format(self)
