import logging
import os
import pathlib
from threading import Event, Thread
from urllib import parse
from typing import Optional
import requests

from millegrilles_messages.chiffrage.Mgs4 import DecipherMgs4
from tksample1.Navigation import sync_collection


class DownloadFichier:

    def __init__(self, download_info, destination: pathlib.Path):
        self.__info = download_info
        self.cle_secrete = download_info['cle_secrete']
        version_courante = download_info['version_courante']
        self.fuuid = version_courante['fuuid']
        self.nom = download_info['nom']
        self.taille_chiffree = version_courante['taille']

        self.nonce = version_courante['nonce']
        self.format = version_courante['format']

        self.path_destination = destination

        self.download_complete = Event()

        self.taille_recue = 0
        self.taille_dechiffree = 0

    def wait(self):
        return self.download_complete.wait()


class DownloadRepertoire:

    def __init__(self, repertoire, destination: pathlib.Path):
        self.__info = repertoire
        self.cuuid = repertoire['tuuid']
        self.nom = repertoire['nom']
        self.download_complete = Event()
        self.repertoire = None
        self.destination = destination

    def wait(self):
        return self.download_complete.wait()


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

        self.__navigation = None

        self.__destination = pathlib.Path('/tmp')

    def quit(self):
        self.__download_pret.set()

    def set_navigation(self, navigation):
        self.__navigation = navigation

    def set_url_download(self, url_download: parse.ParseResult):
        self.__url_download = url_download

    def ajouter_download_fichier(self, download, destination = None) -> DownloadFichier:
        destination = destination or self.__destination
        download_item = DownloadFichier(download, destination)
        self.__download_queue.append(download_item)
        self.__download_pret.set()
        return download_item

    def ajouter_download_repertoire(self, repertoire, destination = None):
        destination = destination or self.__destination
        download_item = DownloadRepertoire(repertoire, destination)
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
                    try:
                        if isinstance(download, DownloadFichier):
                            self.download_fichier(download)
                            self.__logger.debug("Fin download fichier %s" % download.nom)
                        elif isinstance(download, DownloadRepertoire):
                            self.download_repertoire(download)
                            self.__logger.debug("Fin download repertoire %s" % download.nom)
                        else:
                            self.__logger.error("Type download non supporte : %s" % download)
                    except Exception:
                        self.__logger.exception("Erreur download")

    def download_repertoire(self, item: DownloadRepertoire):
        tuuid = item.cuuid
        rep = sync_collection(self.__connexion, tuuid)

        # Generer les downloads
        nom_repertoire = item.nom
        path_destination = pathlib.Path(item.destination, nom_repertoire)
        path_destination.mkdir(exist_ok=True)
        for t in rep.fichiers:
            type_node = t['type_node']
            if type_node == 'Fichier':
                try:
                    download_fichier = DownloadFichier(t, path_destination)
                except KeyError:
                    self.__logger.warning("Cle fichier manquante, skip : %s" % t)
                else:
                    try:
                        self.download_fichier(download_fichier)
                    except FileExistsError:
                        pass  # OK
            else:
                # Download recursif des sous-repertoires
                download_repertoire = DownloadRepertoire(t, path_destination)
                self.download_repertoire(download_repertoire)

    def download_fichier(self, item: DownloadFichier):
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
        if path_reception.exists():
            raise FileExistsError()

        path_reception_work = pathlib.Path(item.path_destination, item.nom + '.work')
        self.__logger.debug("Debut download fichier %s (taille : %d)" % (path_reception_work, item.taille_chiffree))
        with open(path_reception_work, 'xb') as output:
            response = self.__https_session.get(url_fichier)
            response.raise_for_status()

            for chunk in response.iter_content(chunk_size=64*1024):
                output.write(chunk)
                item.taille_recue += len(chunk)

        self.__logger.debug("Download fichier %s complete, dechiffrage en cours" % path_reception_work)
        try:
            dechiffrer_in_place(item, path_reception_work)
        except Exception as e:
            self.__logger.exception("Erreur dechiffrage, on supprime %s" % path_reception_work)
            path_reception_work.unlink()
            raise e

        # Marquer le fichier comme pret (dechiffre)
        path_reception_work.rename(path_reception)
        self.__logger.debug("Fichier %s dechiffre OK" % path_reception)

        item.download_complete.set()


def dechiffrer_in_place(item, path_reception):
    """
    Dechiffre un fichier en reutilisant l'espace deja occupe (overwrite).
    :param item:
    :param path_reception:
    :return:
    """
    with open(path_reception, 'rb+') as fichier:
        decipher = DecipherMgs4(item.cle_secrete, item.nonce)
        position_read = 0
        position_write = 0
        while True:
            chunk = fichier.read(64 * 1024)
            if chunk is None or len(chunk) == 0:
                break
            position_read += len(chunk)
            item.taille_dechiffree = position_read

            chunk_dechiffre = decipher.update(chunk)
            if chunk_dechiffre:
                fichier.seek(position_write)
                fichier.write(chunk_dechiffre)
                position_write += len(chunk_dechiffre)
                fichier.seek(position_read)

        chunk_dechiffre = decipher.finalize()
        if chunk_dechiffre:
            fichier.seek(position_write)
            fichier.write(chunk_dechiffre)
            position_write += len(chunk_dechiffre)

        # Tronquer fichier a la position d'ecriture courante
        fichier.truncate()
