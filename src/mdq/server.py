import argparse
import base64
import json
import logging

import cherrypy
from cherrypy.process.plugins import Monitor

from mdq.metadata import MetadataStore, MetadataUpdate
from mdq.signers import SigningFailedError
from mdq.validation import RequestValidator, MalformedRequestError


__author__ = 'regu0004'

MIME_TYPE_JWT = "application/jwt"
MIME_TYPE_JSON = "application/json"
MIME_TYPES_SUPPORTED = [MIME_TYPE_JSON, MIME_TYPE_JWT]

logger = logging.getLogger(__name__)


class MDQHandler(object):
    """
    Implementation of the OpenID Connect Profile for the Metadata Query Protocol.
    """

    SIGNING_ALG_QUERY_PARAM = "signing_alg"

    def __init__(self, metadata_file, metadata_update_frequency, signer=None):
        self.update_frequency = metadata_update_frequency
        self.signer = signer

        self.validator = RequestValidator(MIME_TYPES_SUPPORTED)

        self.metadata_store = MetadataStore()
        md_update = MetadataUpdate(metadata_file, self.metadata_store)
        # Force populate the metadata store with initial data
        md_update()
        # Start updates in the background
        Monitor(cherrypy.engine, md_update,
                frequency=metadata_update_frequency).subscribe()

    @cherrypy.expose
    def index(self):
        """
        Show all known metadata.
        :return:
        """
        clients = json.dumps(self.metadata_store.all().metadata, sort_keys=True, indent=2)
        return "<h1>Known clients</h1><pre>{clients}</pre>".format(clients=clients)

    @cherrypy.expose
    def status(self):
        """
        Return 200 OK if we are up and alive.
        """
        return

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["GET"])
    @cherrypy.tools.etags(autotags=True)
    def entities(self, entity_id=None, **kwargs):
        """
        Get the metadata for specific entity id (client_id in the case OpenIDConnect) or all known entities.
        """
        content_type = cherrypy.tools.accept.callable(media=MIME_TYPES_SUPPORTED)  # get the clients preferred mime type

        try:
            self.validator.validate(cherrypy.request)
        except MalformedRequestError as e:
            logger.info("Malformed request, reason: '{}'".format(str(e)))
            if e.http_status_code == 405:
                cherrypy.response.headers['Allow'] = 'GET'
            raise cherrypy.HTTPError(e.http_status_code, e.message)

        # Handle b64-encoded entity id's
        if entity_id is not None and entity_id.startswith("{b64}"):
            entity_id = base64.urlsafe_b64decode(entity_id[5:])

        # No entity id specified
        if entity_id is None:
            entity = self.metadata_store.all()
        else:
            try:
                entity = self.metadata_store[entity_id]
            except KeyError:
                _msg = "Unknown entity id '{}'".format(entity_id)
                logger.info(_msg)
                raise cherrypy.HTTPError(404, _msg)

        cherrypy.response.headers["Content-Type"] = MIME_TYPE_JSON
        cherrypy.response.headers["Cache-Control"] = "max-age={}".format(self.update_frequency)
        cherrypy.response.headers["Last-Modified"] = entity.last_modified

        data = json.dumps(entity.metadata)

        if content_type == MIME_TYPE_JWT:
            if self.signer is not None:
                algorithm = kwargs.get(MDQHandler.SIGNING_ALG_QUERY_PARAM, "none")
                try:
                    data = self.signer.sign(data, algorithm)
                except SigningFailedError as e:
                    raise cherrypy.HTTPError(400, "Signing failed, maybe unsupported algorithm.")
                cherrypy.response.headers["Content-Type"] = MIME_TYPE_JWT
            else:
                raise cherrypy.HTTPError(400, "Signed responses are not supported.")

        return data


CHERRYPY_CONFIG = {
    "/": {
        "tools.gzip.on": True,
        "tools.gzip.mime_types": MIME_TYPES_SUPPORTED,
    }
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", dest="host", default="0.0.0.0", type=str, help="host address")
    parser.add_argument("-P", dest="port", default=8089, type=int, help="port")
    parser.add_argument('--frequency', dest="frequency", default=60 * 60 * 24, type=int,
                        help='time (in seconds) between updates')
    parser.add_argument('file', type=str, help='backing JSON file for client metadata')
    args = parser.parse_args()

    cherrypy.server.socket_host = args.host
    cherrypy.server.socket_port = args.port
    cherrypy.tree.mount(MDQHandler(args.file, args.frequency), "/", config=CHERRYPY_CONFIG)

    cherrypy.engine.signals.subscribe()
    cherrypy.engine.start()
    cherrypy.engine.block()


if __name__ == "__main__":
    main()