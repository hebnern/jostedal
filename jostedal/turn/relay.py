from twisted.internet.protocol import DatagramProtocol
from jostedal.stun.agent import Address, Message
import logging
from jostedal import stun, turn
from jostedal.turn import attributes


logger = logging.getLogger(__name__)

import struct
class ChannelMessage(bytearray):
    """TURN channel message structure
    :see: http://tools.ietf.org/html/rfc8656#section-12.4
    """

    _struct = struct.Struct('>2H')

    def __init__(self, data, channel_number):
        bytearray.__init__(self, data)
        self.channel_number = channel_number

    @classmethod
    def encode(cls, channel_number, data):
        header = cls._struct.pack(channel_number, len(data))
        message = cls(header, channel_number)
        message.extend(data)
        return message

    @classmethod
    def decode(cls, data):
        assert data[0] >> 6 == turn.MSG_CHANNEL, \
            "Channel message MUST start with 0b01"
        channel_number, msg_length = cls._struct.unpack_from(data)
        return cls(memoryview(data)[:cls._struct.size + msg_length], channel_number)

    @property
    def length(self):
        return len(self) - self._struct.size

    def __repr__(self):
        return ("{}(length={}, channel_number={})".format(
                    type(self).__name__, len(self) - self._struct.size, self.channel_number))

    def format(self):
        string = '\n'.join([
            "{0.__class__.__name__}",
            "    length:         {0.length}",
            ]).format(self)
        return string

class Relay(DatagramProtocol):
    relay_addr = (None, None, None)

    def __init__(self, server, client_addr):
        self.server = server
        self.client_addr = client_addr

        self.permissions = []#('ipaddr', 'lifetime'),]
        self._channels = {} # channel to peer bindings
        self._addresses = {} # channel to peer bindings

    @classmethod
    def allocate(cls, server, client_addr, port=0):
        relay = cls(server, client_addr)
        port = server.reactor.listenUDP(port, relay, server.interface)
        family = Address.aftof(relay.transport.socket.family)
        relay_ip, port = relay.transport.socket.getsockname()[:2]
        relay.relay_addr = (family, port, relay_ip)
        logger.info("%s Allocated", relay)
        return relay

    def add_permission(self, peer_addr):
        logger.info("%s Added permission for %s", self, peer_addr)
        self.permissions.append(peer_addr)

    def bind_channel(self, channel_number, peer_addr):
        logger.info("%s Added channel binding for %s on channel 0x%04x", self, peer_addr, channel_number)
        if peer_addr.address not in self.permissions:
            self.add_permission(peer_addr.address)
        if peer_addr.address not in self._channels:
            self._channels[peer_addr.address] = channel_number
        if channel_number not in self._addresses:
            self._addresses[channel_number] = peer_addr

    def send_channel(self, channel_number, data):
        peer_addr = self._addresses[channel_number]
        self.send(data, (peer_addr.address, peer_addr.port))

    def send(self, data, addr):
        logger.info("%s -> %s:%d", self, *addr)
        host, _port = addr
        if host in self.permissions:
            self.transport.write(data, addr)
        else:
            logger.warning("No permissions for %s: Dropping Send request", host)
            logger.debug(data.hex())

    def datagramReceived(self, datagram, addr):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-10.3
        """
        logger.info("%s <- %s:%d", self, *addr)
        host, port = addr
        if host in self.permissions:
            channel = self._channels.get(host)
            if channel:
                msg = ChannelMessage.encode(channel, datagram)
            else:
                msg = Message.from_str(turn.METHOD_DATA, stun.CLASS_INDICATION)
                family = Address.aftof(self.transport.addressFamily)
                msg.add_attr(attributes.XorPeerAddress, family, port, host)
                msg.add_attr(attributes.Data, datagram)
            self.server.transport.write(msg, self.client_addr)
        else:
            logger.warning("No permissions for %s: Dropping datagram", host)
            logger.debug(datagram.hex())

    def __str__(self):
        return "Relay(relay-addr={0[2]}:{0[1]}, client-addr={1[0]}:{1[1]})".format(
            self.relay_addr, self.client_addr
        )
