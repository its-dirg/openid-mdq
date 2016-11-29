import base64
import logging
import urlparse
from jwkest.jws import JWS, NoSuitableSigningKeys
import requests

__author__ = 'regu0004'

logger = logging.getLogger(__name__)


class SigningFailedError(Exception):
    pass


class Signer(object):
    def sign(self, data, algorithm=None):
        raise NotImplementedError


class LocalSigner(Signer):
    def __init__(self, signing_keys):
        self.signing_keys = signing_keys

    def sign(self, data, algorithm=None):
        try:
            return JWS(data, alg=algorithm).sign_compact(keys=self.signing_keys)
        except NoSuitableSigningKeys as e:
            logger.exception("Failed to sign: no suitable keys known.")
            raise SigningFailedError("Failed to sign.")


class RemoteSigner(object):
    PATH = "/0/{kid}/sign"

    def __init__(self, url, kid):
        self.url = url
        self.kid = kid

    def sign(self, data, algorithm=None):
        url = urlparse.urljoin(self.url, RemoteSigner.PATH.format(self.kid))
        req_data = {
            "mech": "RSAPKCS1",
            "data": base64.b64encode(data)
        }

        try:
            response = requests.post(url, json=req_data)
        except requests.exceptions.RequestException as e:
            logger.exception("Failed to connect to signing server.")
            raise SigningFailedError("Failed to sign.")

        if response.status_code == 200:
            signed = base64.b64decode(response.text["signed"])
            return signed
        else:
            logger.error(
                "Failed to sign: {http_code} {message}".format(http_code=response.status_code, message=response.text))
            raise SigningFailedError("Failed to sign.")

