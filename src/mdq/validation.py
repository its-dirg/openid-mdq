__author__ = 'regu0004'


class MalformedRequestError(Exception):
    def __init__(self, http_status_code=400, message=None):
        super(MalformedRequestError, self).__init__(message)
        self.http_status_code = http_status_code

    def __repr__(self):
        return "{}: {}".format(self.http_status_code, super(MalformedRequestError, self).__repr__())

    def __str__(self):
        return "{}: {}".format(self.http_status_code, super(MalformedRequestError, self).__str__())

class RequestValidator(object):
    """
    Validate a HTTP request according to the OpenID Connect Profile for the Metadata Query Protocol.
    """

    def __init__(self, mime_types_supported=None):
        self.mime_types_supported = mime_types_supported or []

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

        return True
