import unittest

from mock import Mock, patch
import pytest

from mdq.validation import RequestValidator, MalformedRequestError


__author__ = 'regu0004'


class TestRequestValidator(unittest.TestCase):
    BASE_REQUEST = {
        "protocol": (1, 1),
        "method": "GET",
        "headers": {"Accept": "application/json"},
        "params": {}
    }

    def setUp(self):
        self.validator = RequestValidator(["application/json", "application/jwt"], ["HS256"])
        self.request = Mock(**TestRequestValidator.BASE_REQUEST)

    def test_valid_request(self):
        assert self.validator.validate(self.request)

    def test_http_protocol_version(self):
        # http version 1.1
        assert self.validator.validate(self.request)

        # allow higher http versions
        self.request.protocol = (2, 0)
        self.validator.validate(self.request)

        # too low version
        self.request.protocol = (0, 9)
        self._verify_expected_http_status_code(505)

    def test_reject_POST(self):
        self.request.method = "POST"
        self._verify_expected_http_status_code(405)

    def test_missing_accept_header(self):
        # Remove all headers
        with patch.dict(self.request.headers, clear=True):
            self._verify_expected_http_status_code(406)

    @patch.dict(BASE_REQUEST["headers"], {"Accept": "application/jwt"})
    def test_jwt_handling(self):
        # accept missing query parameter
        self.validator.validate(self.request)

        with patch.dict(self.request.params, {"signing_alg": "HS256"}):
            assert self.validator.validate(self.request)

    def _verify_expected_http_status_code(self, expected_status_code):
        with pytest.raises(MalformedRequestError) as exc_info:
            self.validator.validate(self.request)
        assert exc_info.value.http_status_code == expected_status_code