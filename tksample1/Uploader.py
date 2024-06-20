import logging
import uuid

import requests
import tkinter as tk
import pathlib
import mimetypes

from threading import Event, Thread
from typing import Optional
from urllib import parse

from millegrilles_messages.messages import Constantes
from millegrilles_messages.chiffrage.Mgs4 import CipherMgs4, chiffrer_document
from millegrilles_messages.messages.Hachage import Hacheur
from millegrilles_messages.chiffrage.SignatureDomaines import SignatureDomaines
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat


class UploadFichier:

    def __init__(self, cuuid: str, path_fichier: pathlib.Path):
        self.cuuid = cuuid
        self.__path_fichier = path_fichier

    @property
    def path(self):
        return self.__path_fichier

    @property
    def mimetype(self):
        return mimetypes.guess_type(self.__path_fichier)[0]


class UploadRepertoire:

    def __init__(self, cuuid_parent: str, path_dir: pathlib.Path):
        self.__cuuid_parent = cuuid_parent
        self.__path_dir = path_dir


class Uploader:

    def __init__(self, stop_event, connexion):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event
        self.__connexion = connexion

        self.__upload_queue = list()
        self.__upload_pret = Event()

        self.__https_session: Optional[requests.Session] = None
        self.__certificats_chiffrage: Optional[list[EnveloppeCertificat]] = None

        self.__navigation = None

        self.__thread = Thread(name="uploader", target=self.upload_thread)
        self.__thread.start()

    def set_navigation(self, navigation):
        self.__navigation = navigation

    def quit(self):
        self.__upload_pret.set()

    def set_url_upload(self, url_upload: parse.ParseResult):
        self.__url_upload = url_upload

    def ajouter_upload(self, cuuid_parent: str, path_upload: str) -> UploadFichier:
        path_upload = pathlib.Path(path_upload)
        if path_upload.is_dir():
            upload_item = UploadRepertoire(cuuid_parent, path_upload)
        else:
            upload_item = UploadFichier(cuuid_parent, path_upload)
        self.__upload_queue.append(upload_item)
        self.__upload_pret.set()
        return upload_item

    def upload_thread(self):
        while self.__stop_event.is_set() is False:
            self.__upload_pret.wait()
            self.__upload_pret.clear()

            while True:
                try:
                    upload = self.__upload_queue.pop(0)
                except IndexError:
                    break
                else:
                    if self.__stop_event.is_set():
                        return  # Stopping
                    try:
                        if isinstance(upload, UploadFichier):
                            self.upload_fichier(upload)
                        elif isinstance(upload, UploadRepertoire):
                            self.upload_repertoire(upload)
                        else:
                            self.__logger.error("Type upload non supporte : %s" % upload)
                    except Exception:
                        self.__logger.exception("Erreur upload")

    def upload_repertoire(self, upload: UploadRepertoire):
        raise NotImplementedError('todo')

    def upload_fichier(self, upload: UploadFichier):
        if self.__certificats_chiffrage is None:
            self.__certificats_chiffrage = self.__connexion.get_certificats_chiffrage()

        requete_token = dict()
        requete, message_id = self.__connexion.formatteur.signer_message(
            Constantes.KIND_REQUETE, requete_token)
        batch_upload_token = self.__connexion.call('getBatchUpload', data=requete, timeout=5)

        # Preparer transaction
        stat_fichier = upload.path.stat()
        taille = stat_fichier.st_size
        date_fichier = int(stat_fichier.st_ctime)
        # info_upload = {
        #     'nom': upload.path.name,
        #     'mimetype': upload.mimetype,
        #     'taille': taille,
        #     'dateFichier': date_fichier,
        #     'cuuid': upload.cuuid,
        # }

        # Preparer chiffrage
        cle_ca = self.__connexion.ca.get_public_x25519()
        cipher = CipherMgs4(cle_ca)
        hacheur = Hacheur(hashing_code='blake2b-512', encoding='base58btc')

        SPLIT_SIZE = 128_000

        if self.__https_session is None:
            # Initialiser holder de session https
            self.__https_session = self.__connexion.get_https_session()

        batch_id = batch_upload_token['batchId']
        url_collections = self.__connexion.url_collections

        headers = {
            'content-type': 'application/data',
            'x-token-jwt': batch_upload_token['token'],
        }

        with open(upload.path, 'rb') as fichier:
            while cipher.hachage is None:
                position = fichier.tell()
                stream = file_iterator(fichier, cipher, hacheur, SPLIT_SIZE)
                url_put = f'https://{url_collections.hostname}:444{url_collections.path}/fichiers/upload/{batch_id}/{position}'
                response = self.__https_session.put(url_put, headers=headers, data=stream)
                response.raise_for_status()

        hachage = hacheur.finalize()
        info_dechiffrage = cipher.get_info_dechiffrage(self.__certificats_chiffrage)
        fuuid = info_dechiffrage['hachage_bytes']
        cle_secrete = cipher.cle_secrete
        cle_ca_chiffree = info_dechiffrage['cle']
        cles_chiffrees = info_dechiffrage['cles']
        taille_chiffree = cipher.taille_chiffree
        taille_dechiffree = cipher.taille_dechiffree

        # Signer cle secrete pour GrosFichiers
        signature_cle = SignatureDomaines.signer_domaines(cle_secrete, ['GrosFichiers'], cle_ca_chiffree)

        # Preparer et chiffrer la transaction
        data_dechiffre_transaction = {
            'nom': upload.path.name,
            'taille': taille,
            'dateFichier': date_fichier,
            'hachage_original': hachage,
        }
        doc_chiffre = chiffrer_document(cle_secrete, signature_cle.get_cle_ref(), data_dechiffre_transaction)
        # {
        #   "cle_id": "zCR7nbmPhCeseeBAsdFtF5ES8cmNRSGUNsBbt8MPLeLNw",
        #   "cuuid": "83923bf72a78b827996df7c2f8f415beb99751605d941aeab8cc3e0835827f3b",
        #   "format": "mgs4",
        #   "fuuid": "zSEfXUBNo43kqfz1jVDwP3KxEAPFHTS9e1EiRADbafLVoVjABSwXxNKJZSWXLJ31WY5ant4vFJ2zjdeHpEcmy7ZYnuWV7N",
        #   "metadata": {
        #     "cle_id": "zCR7nbmPhCeseeBAsdFtF5ES8cmNRSGUNsBbt8MPLeLNw",
        #     "data_chiffre": "bbLOtJGMLfAWRKSo88KW40pU1/bBADQitzKD7HnZN4ppPjfxVUSFSltXTxp9cyu/gHyTVKR1xjClY8PiEag2t3LrkXamcyfI2wGydtEX97OxQ3dnXc31zEqABEaa352F98CFG8/XgSNJS55DxfL3DQfis27Xik18nXPotj8YTdLKnatAYE72OLqbRWNnUh3/iBp1JgDjDEzb7GKSkFJx2bxZOCHs4b129wmcKE25pw",
        #     "format": "mgs4",
        #     "nonce": "uwQyT8aoq/1vx0NftZhgnR25Sz0ejQEb"
        #   },
        #   "mimetype": "image/jpeg",
        #   "nonce": "s3xRlsbWt8WZ5jA6/EJMPLp9tsyYbReF",
        #   "taille": 1385933
        # }
        transaction = {
            'cle_id': signature_cle.get_cle_ref(),
            'cuuid': upload.cuuid,
            'format': 'mgs4',
            'fuuid': fuuid,
            'metadata': doc_chiffre,
            'mimetype': upload.mimetype,
            'nonce': info_dechiffrage['header'],
            'taille': taille_dechiffree,
        }
        transaction, message_id = self.__connexion.formatteur.signer_message(
            Constantes.KIND_COMMANDE, transaction,
            domaine="GrosFichiers", action="nouvelleVersion", ajouter_chaine_certs=True)

        transaction_cle = {
            'signature': signature_cle.to_dict(),
            'cles': cles_chiffrees,
        }
        transaction_cle, message_id = self.__connexion.formatteur.signer_message(
            Constantes.KIND_COMMANDE, transaction_cle,
            domaine="MaitreDesCles", action="ajouterCleDomaines", ajouter_chaine_certs=True)
        transaction['attachements'] = {'cle': transaction_cle}

        confirmation_data = {
            'etat': {'correlation': batch_id, 'hachage': fuuid},
            'transaction': transaction
        }
        url_confirmation = f'https://{url_collections.hostname}:444{url_collections.path}/fichiers/upload/{batch_id}'

        headers = {
            'x-token-jwt': batch_upload_token['token'],
        }
        reponse = self.__https_session.post(url_confirmation, headers=headers, json=confirmation_data, timeout=30)
        if reponse.status_code == 200:
            reponse_status = reponse.json()
            raise Exception('Erreur post : %s' % reponse_status)
        else:
            reponse.raise_for_status()


def file_iterator(fp, cipher, hacheur, maxsize):
    CHUNK_SIZE = 64*1024
    current_output_size = 0
    maxsize = maxsize - CHUNK_SIZE
    while current_output_size < maxsize:
        chunk = fp.read(CHUNK_SIZE)
        if len(chunk) == 0:
            chunk = cipher.finalize()
            yield chunk
            return
        hacheur.update(chunk)
        chunk = cipher.update(chunk)
        if len(chunk) > 0:
            current_output_size += len(chunk)
            yield chunk


class UploaderFrame(tk.Frame):

    def __init__(self, stop_event, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event
