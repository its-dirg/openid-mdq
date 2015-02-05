import json
import logging
from multiprocessing import Lock
import time

__author__ = 'regu0004'

logger = logging.getLogger(__name__)


class MetadataUpdate(object):
    """
    Read updated metadata from file and update the referenced metadata store.
    """

    def __init__(self, file_name, metadata_store):
        self.file_name = file_name
        self.metadata_store = metadata_store

    def __call__(self):
        """
        Read data from the backing file and store the new data in the metadata store.

        If the file could not be parsed the metadata store is emptied to avoid stale data.
        """

        try:
            with open(self.file_name, "r") as f:
                file_data = json.load(f)
            self.metadata_store.update(file_data)
            logger.info("Metadata update successful: {n} clients known.".format(n=len(file_data)))
        except (IOError, ValueError) as e:
            self.metadata_store.update({})
            logger.exception("Metadata update failed".format(e))


class MetadataEntry(object):
    """
    Metadata coupled with the time it was last updated.
    """

    def __init__(self, metadata, last_modified):
        self.metadata = metadata
        self.last_modified = last_modified

    def __repr__(self):
        return "(" + self.last_modified + ", " + repr(self.metadata) + ")"


class MetadataStore(object):
    """
    Simple thread-safe dict-like object.
    """

    def __init__(self):
        self.lock = Lock()
        self._metadata = {}
        self.last_update = None

    def __getitem__(self, client_id):
        with self.lock:
            return MetadataEntry(self._metadata[client_id], self.last_update)

    def update(self, new_metadata):
        with self.lock:
            self._metadata = new_metadata

        self.last_update = time.time()

    def all(self):
        with self.lock:
            return MetadataEntry(self._metadata.copy(), self.last_update)

    def __repr__(self):
        return repr(self._metadata)