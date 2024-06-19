import logging
import pathlib
from threading import Event, Thread
from urllib import parse
from typing import Optional
import requests

from millegrilles_messages.chiffrage.Mgs4 import DecipherMgs4


class DownloadItem:

    def __init__(self, download_info):
        self.__info = download_info
        self.cle_secrete = download_info['cle_secrete']
        version_courante = download_info['version_courante']
        self.fuuid = version_courante['fuuid']
        self.nom = download_info['nom']
        self.taille_chiffree = version_courante['taille']

        self.nonce = version_courante['nonce']
        self.format = version_courante['format']

        self.path_destination = pathlib.Path('/tmp')

        self.__download_complete = Event()

    def wait(self):
        return self.__download_complete.wait()


class Downloader:

    def __init__(self, stop_event: Event, connexion):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event
        self.__connexion = connexion
        self.__download_queue = list()
        self.__download_pret = Event()
        self.__url_download: Optional[parse.ParseResult] = None

        self.__thread = Thread(name="downloader", target=self.download_thread)
        self.__thread.start()

        self.__https_session: Optional[requests.Session] = None

    def quit(self):
        self.__download_pret.set()

    def set_url_download(self, url_download: parse.ParseResult):
        self.__url_download = url_download

    def ajouter_download(self, download) -> DownloadItem:
        download_item = DownloadItem(download)
        self.__download_queue.append(download_item)
        self.__download_pret.set()
        return download_item

    def download_thread(self):
        while self.__stop_event.is_set() is False:
            self.__download_pret.wait()
            self.__download_pret.clear()

            while True:
                try:
                    download = self.__download_queue.pop(0)
                except IndexError:
                    break
                else:
                    if self.__stop_event.is_set():
                        return  # Stopping
                    self.download(download)

    def download(self, item: DownloadItem):
        self.__connexion.connect_event.wait()
        if self.__stop_event.is_set():
            raise Exception('Stopping')

        if item.format != 'mgs4':
            raise Exception('Format de chiffrage non supporte')

        if self.__https_session is None:
            self.__https_session = self.__connexion.get_https_session()

        url_collections = self.__connexion.url_collections
        url_fichier = f'https://{url_collections.hostname}:444{url_collections.path}/fichiers/{item.fuuid}'

        path_reception = pathlib.Path(item.path_destination, item.nom)
        self.__logger.debug("Debut download fichier %s (taille : %d)" % (path_reception, item.taille_chiffree))
        with open(path_reception, 'xb') as output:
            response = self.__https_session.get(url_fichier)
            response.raise_for_status()

            decipher = DecipherMgs4(item.cle_secrete, item.nonce)

            for chunk in response.iter_content(chunk_size=64*1024):
                chunk = decipher.update(chunk)
                if chunk:
                    output.write(chunk)
            chunk = decipher.finalize()
            if chunk:
                output.write(chunk)

        self.__logger.debug("Fichier %s recu" % path_reception)

        pass
