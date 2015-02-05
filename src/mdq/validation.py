__author__ = 'regu0004'


class MalformedRequestError(Exception):
    def __init__(self, http_status_code=400, message=None):
        super(MalformedRequestError, self).__init__(message)
        self.http_status_code = http_status_code


class RequestValidator(object):
    """
    Validate a HTTP request according to the OpenID Connect Profile for the Metadata Query Protocol.
    """

    def __init__(self, mime_types_supported=None, signing_algs_supported=None, signing_alg_query_param="signing_alg"):
        self.mime_types_supported = mime_types_supported or []
        self.signing_algs_supported = signing_algs_supported or []
        self.signing_alg_query_param = signing_alg_query_param

    def validate(self, request):
        if request.protocol < (1, 1):
            raise MalformedRequestError(http_status_code=505)

        if request.method != "GET":
            raise MalformedRequestError(http_status_code=405)

        try:
            content_type = request.headers["Accept"]
            assert content_type in self.mime_types_supported
        except (KeyError, AssertionError):
            raise MalformedRequestError(http_status_code=406)

        if content_type == "application/jwt":
            try:
                # signing and/or encryption must be specified
                if self.signing_alg_query_param in request.params:
                    assert request.params[self.signing_alg_query_param] in self.signing_algs_supported
            except AssertionError:
                raise MalformedRequestError(
                    message="JWT requested, but the signing algorithm '{}' is not supported.".format(
                        request.params[self.signing_alg_query_param]))

        return True
