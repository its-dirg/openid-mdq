import base64
import json
import os
import unittest
import urllib

import cherrypy
from cryptlib.ecc import P256
from jwkest.jwk import RSAKey, import_rsa_key_from_file, SYMKey, ECKey
from jwkest.jws import JWS
from mock import patch
import requests

from mdq.server import MDQHandler, CHERRYPY_CONFIG, MIME_TYPE_JWT
from mdq.signers import LocalSigner


__author__ = 'regu0004'


def full_test_path(file_path):
    test_dir_path = os.path.dirname(os.path.realpath(__file__))
    return os.path.join(test_dir_path, file_path)


class TestMDQHandler(unittest.TestCase):
    SERVER_PORT = 9090
    HEADERS = {"Accept": "application/json"}
    CLIENT_ID = "https://client1.example.com"
    BASE_URL = "http://localhost:{port}/entities".format(port=SERVER_PORT)
    URL = "{base}/{client_id}".format(base=BASE_URL, client_id=urllib.quote(CLIENT_ID, safe=''))

    SYM_KEY_PHRASE = "The matrix consents with another spread lyric."

    @classmethod
    def setUpClass(cls):
        file_name = full_test_path("test_data/clients.json")
        with open(full_test_path("test_data/clients.json")) as f:
            cls.METADATA_FROM_FILE = json.load(f)

        rsa_key = RSAKey(key=import_rsa_key_from_file(full_test_path("test_data/certs/rsa2048")))
        cls.EC_KEY = ECKey().load_key(P256)

        signing_keys = {
            "RS256": rsa_key,
            "ES256": cls.EC_KEY
        }

        cls.SIGNING_ALGS_SUPPORTED = signing_keys.keys()
        cls.MDQ = MDQHandler(file_name, 36000, LocalSigner(signing_keys.values()))

        cherrypy.config.update({"environment": "test_suite"})
        cherrypy.server.socket_host = "0.0.0.0"
        cherrypy.server.socket_port = cls.SERVER_PORT
        cherrypy.tree.mount(cls.MDQ, "/", CHERRYPY_CONFIG)
        cherrypy.engine.start()

    @classmethod
    def tearDownClass(cls):
        cherrypy.engine.exit()

    def setUp(self):
        TestMDQHandler.MDQ.metadata_store.update(TestMDQHandler.METADATA_FROM_FILE)

    def test_reject_POST(self):
        response = requests.post(TestMDQHandler.URL, {"foo": "bar"})
        assert response.status_code == 405

    def test_non_existing_client_id(self):
        url = "{base}/no_exist".format(base=TestMDQHandler.BASE_URL)
        response = requests.get(url, headers=TestMDQHandler.HEADERS)
        assert response.status_code == 404

    def test_existing_client_id(self):
        response = requests.get(TestMDQHandler.URL, headers=TestMDQHandler.HEADERS)
        assert json.loads(response.text) == TestMDQHandler.METADATA_FROM_FILE[TestMDQHandler.CLIENT_ID]

        # The same result should be obtained when sending base64url-encoded client id
        enc_client_id = base64.urlsafe_b64encode(TestMDQHandler.CLIENT_ID)
        url = "{base}/{{b64}}{client_id}".format(base=TestMDQHandler.BASE_URL, client_id=enc_client_id)
        requests.get(url, headers=TestMDQHandler.HEADERS)
        assert json.loads(response.text) == TestMDQHandler.METADATA_FROM_FILE[TestMDQHandler.CLIENT_ID]

    def test_get_all_entities(self):
        response = requests.get(TestMDQHandler.BASE_URL, headers=TestMDQHandler.HEADERS)
        assert json.loads(response.text) == TestMDQHandler.METADATA_FROM_FILE

    def test_not_modified(self):
        # Make first request
        r1 = requests.get(TestMDQHandler.URL, headers=TestMDQHandler.HEADERS)
        assert r1.status_code == 200

        # Make the same request again, but supply the ETag from the first request
        with patch.dict(TestMDQHandler.HEADERS, {"If-None-Match": r1.headers["ETag"]}):
            r2 = requests.get(TestMDQHandler.URL, headers=TestMDQHandler.HEADERS)
        assert r2.status_code == 304  # Verify the server responds not modified
        assert r2.headers["ETag"] == r1.headers["ETag"]

        # Make the same request again with ETag, but force modification of data
        with patch.dict(TestMDQHandler.HEADERS, {"If-None-Match": r1.headers["ETag"]}), patch.dict(
                TestMDQHandler.METADATA_FROM_FILE[TestMDQHandler.CLIENT_ID],
                {"redirect_uris": ["https://new.example.com"]}):
            TestMDQHandler.MDQ.metadata_store.update(TestMDQHandler.METADATA_FROM_FILE)
            r3 = requests.get(TestMDQHandler.URL, headers=TestMDQHandler.HEADERS)
        assert r3.status_code == 200
        assert r3.headers["ETag"] != r1.headers["ETag"]

    def test_gzip_compression(self):
        with patch.dict(TestMDQHandler.HEADERS, {"Accept-Encoding": "gzip"}):
            response = requests.get(TestMDQHandler.URL, headers=TestMDQHandler.HEADERS)
        assert response.status_code == 200
        assert response.headers["Content-Encoding"] == "gzip"

    def test_unsecured_jws(self):
        # No signing algorithm specified, should default to "alg": "none" -> Unsecured JWS
        with patch.dict(TestMDQHandler.HEADERS, {"Accept": MIME_TYPE_JWT}):
            response = requests.get(TestMDQHandler.URL, headers=TestMDQHandler.HEADERS)
        assert response.headers["Content-Type"] == MIME_TYPE_JWT
        payload = JWS().verify_compact(response.text)
        assert json.loads(payload) == TestMDQHandler.METADATA_FROM_FILE[TestMDQHandler.CLIENT_ID]

        # Signing algorithm: "none"
        with patch.dict(TestMDQHandler.HEADERS, {"Accept": MIME_TYPE_JWT}):
            response = requests.get(TestMDQHandler.URL, params={MDQHandler.SIGNING_ALG_QUERY_PARAM: "none"},
                                    headers=TestMDQHandler.HEADERS)
        assert response.headers["Content-Type"] == MIME_TYPE_JWT
        payload = JWS().verify_compact(response.text)
        assert json.loads(payload) == TestMDQHandler.METADATA_FROM_FILE[TestMDQHandler.CLIENT_ID]

    @patch.dict(HEADERS, {"Accept": MIME_TYPE_JWT})
    def test_jws(self):
        keys = [
            SYMKey(key=TestMDQHandler.SYM_KEY_PHRASE, alg="HS256"),
            RSAKey(key=import_rsa_key_from_file(full_test_path("test_data/certs/rsa2048.pub"))),
            TestMDQHandler.EC_KEY
        ]

        # Test support for algorithms with supplied keys are working
        for alg in TestMDQHandler.SIGNING_ALGS_SUPPORTED:
            response = requests.get(TestMDQHandler.URL, params={MDQHandler.SIGNING_ALG_QUERY_PARAM: alg},
                                    headers=TestMDQHandler.HEADERS)

            payload = JWS().verify_compact(response.text, keys)
            assert json.loads(payload) == TestMDQHandler.METADATA_FROM_FILE[TestMDQHandler.CLIENT_ID]

        # Unsupported signing algorithm
        response = requests.get(TestMDQHandler.URL, params={MDQHandler.SIGNING_ALG_QUERY_PARAM: "HS256"},
                                headers=TestMDQHandler.HEADERS)
        assert response.status_code == 400
