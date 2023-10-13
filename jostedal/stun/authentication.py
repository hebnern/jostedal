from jostedal import stun
from jostedal.utils import saslprep, ha1
from jostedal.stun import attributes

import os
import logging
from datetime import datetime
import hashlib
import hmac
import base64
import time


logger = logging.getLogger(__name__)


class CredentialMechanism(object):
    def update(self, message):
        pass


class ShortTermCredentialMechanism(CredentialMechanism):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-10.1
    """

    def __init__(self, username, password):
        self.username = username
        self.hmac_key = saslprep(password)

    def update(self, msg):
        msg.add_attr(attributes.Username, self.username)
        msg.add_attr(attributes.MessageIntegrity, self.hmac_key)


class LongTermCredentialMechanism(CredentialMechanism):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-10.2
    """

    def __init__(self, realm, users={}):
        self.nonce = self.generate_nonce()
        self.realm = realm
        self.hmac_keys = {}
        for username, credentials in users.items():
            password = credentials.get("password")
            if not password:
                logger.warning("Invalid credentials for %s", username)
                continue

            self.add_user(username, password)

    def add_user(self, username, password):
        self.hmac_keys[username] = ha1(username, self.realm, password)

    def generate_nonce(self, length=16):
        return os.urandom(length // 2).hex()

    def authenticate(self, msg):
        realm = msg.get_attr(stun.ATTR_REALM)
        username = msg.get_attr(stun.ATTR_USERNAME)
        nonce = msg.get_attr(stun.ATTR_NONCE)
        message_integrity = msg.get_attr(stun.ATTR_MESSAGE_INTEGRITY)
        if not (realm and username and nonce and message_integrity):
            raise stun.UnauthorizedError()

    def update(self, msg):
        msg.add_attr(attributes.Nonce, self.nonce.encode())
        msg.add_attr(attributes.Realm, self.realm.encode())
        msg.add_attr(attributes.MessageIntegrity, list(self.hmac_keys.values())[0])

    def __str__(self):
        return "realm={}".format(self.realm)

    def __repr__(self, *args, **kwargs):
        return "LongTermCredentialMechanism({})".format(self)

class TimeLimitedCredentialMechanism(LongTermCredentialMechanism):
    """
    CoTURN-style time-limited credential mechanism
    :see: "TURN REST API" section at https://github.com/coturn/coturn/blob/master/README.turnserver
    """

    def __init__(self, realm, shared_secret):
        super().__init__(realm)
        self.shared_secret = shared_secret

    def generate_credentials(self, username, time_to_expiry=600):
        username = f"{int(time.time()) + time_to_expiry}:{username}"
        password_bytes = hmac.digest(self.shared_secret.encode(), username.encode(), hashlib.sha1)
        password = base64.b64encode(password_bytes).decode()
        self.add_user(username, password)
        return username, password

    def __repr__(self, *args, **kwargs):
        return "TimeLimitedCredentialMechanism({})".format(self)
