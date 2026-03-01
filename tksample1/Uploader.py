from __future__ import annotations

import datetime
import json
import logging
import mimetypes
import os.path
import pathlib
import tempfile
import time
import tkinter as tk
from threading import Event, Thread
from typing import Optional, Union
from urllib import parse

import requests
import socketio.exceptions
from millegrilles_messages.chiffrage.Mgs4 import (
    CipherMgs4,
    CipherMgs4WithSecret,
    chiffrer_document,
    chiffrer_document_nouveau,
)
from millegrilles_messages.chiffrage.SignatureDomaines import SignatureDomaines
from millegrilles_messages.messages import Constantes
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.Hachage import Hacheur
from wakepy import keep

from tksample1.AuthUsager import Authentification
from tksample1.Navigation import Repertoire, sync_collection


class UploadRepertoire:
    def __init__(
        self,
        cuuid_parent: str,
        path_dir: pathlib.Path,
        parent: Optional[UploadRepertoire] = None,  # type: ignore[no-redef]
    ):
        self.__cuuid_parent = cuuid_parent
        self.__path_dir = path_dir
        self.__parent = parent
        self.taille = None
        self.nombre_sous_fichiers = None
        self.__taille_uploade = 0
        self.fichiers_uploades = 0

    def add_chunk_uploade(self, taille: int):
        if self.__parent is not None:
            self.__parent.add_chunk_uploade(taille)
        else:
            self.__taille_uploade += taille

    def add_fichiers_traite(self, compte: int):
        self.fichiers_uploades += compte

    @property
    def taille_uploade(self):
        return self.__taille_uploade

    @property
    def cuuid_parent(self):
        return self.__cuuid_parent

    @property
    def path(self):
        return self.__path_dir

    def preparer_taille(self):
        if self.taille is None:
            taille_rep, nombre_fichiers_reps = self.__preparer_recursif(self.__path_dir)
            self.taille = taille_rep
            self.nombre_sous_fichiers = nombre_fichiers_reps

    def __preparer_recursif(self, path_rep: pathlib.Path) -> tuple[int, int]:
        compte_fichiers = 0
        taille_fichiers = 0
        for f in path_rep.iterdir():
            if f.is_file():
                taille_fichiers += f.stat().st_size
                compte_fichiers += 1
            else:
                taille_rep, nombre_fichiers_reps = self.__preparer_recursif(f)
                compte_fichiers += nombre_fichiers_reps
                taille_fichiers += taille_rep

        return taille_fichiers, compte_fichiers


class UploadFichier:
    def __init__(
        self,
        cuuid: str,
        path_fichier: pathlib.Path,
        parent: Optional[UploadRepertoire] = None,  # type: ignore
    ):
        self.cuuid = cuuid
        self.__path_fichier = path_fichier
        self.__parent = parent
        self.taille = path_fichier.stat().st_size
        self.__taille_uploade = 0
        self.batch_token = None

    def add_chunk_uploade(self, taille: int):
        if self.__parent:
            self.__parent.add_chunk_uploade(taille)
        else:
            self.__taille_uploade += taille

    def reset_taille_uploade(self):
        self.add_chunk_uploade(-1 * self.__taille_uploade)
        self.__taille_uploade = 0

    @property
    def taille_uploade(self):
        return self.__taille_uploade

    @property
    def path(self):
        return self.__path_fichier

    @property
    def mimetype(self):
        guess = mimetypes.guess_type(self.__path_fichier)[0]
        if guess is None:
            return "application/octet-stream"
        return guess


# UPLOAD_SPLIT_SIZE = 100_000_000
UPLOAD_SPLIT_SIZE = 1_000_000


class Uploader:
    def __init__(self, stop_event, connexion: Authentification):
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__stop_event = stop_event
        self.__connexion = connexion
        self.__tmp_path = connexion.tmp_path
        self.__upload_queue = list()
        self.__upload_pret = Event()

        self.__https_session: Optional[requests.Session] = None
        self.__certificats_chiffrage: Optional[list[EnveloppeCertificat]] = None

        self.__navigation = None
        self.__upload_en_cours: Optional[Union[UploadFichier, UploadRepertoire]] = None
        self.__event_upload_in_progress = Event()

        self.__thread = Thread(name="uploader", target=self.upload_thread, daemon=False)
        self.__thread.start()
        # self.__thread_label = Thread(name="uploader_label", target=self.__upload_label_thread, daemon=False)
        # self.__thread_label.start()

        self.__init_mime_types()

    def __init_mime_types(self):
        import tksample1

        path_module = pathlib.Path(os.path.abspath(tksample1.__file__))
        path_json = pathlib.Path(path_module.parent, "mimetypes.json")
        with open(path_json) as fichier:
            json_mt = json.load(fichier)
            for ext, mt in json_mt.items():
                mimetypes.add_type(mt, "." + ext)

    def set_navigation(self, navigation):
        self.__navigation = navigation

    def quit(self):
        self.__upload_pret.set()

    def set_url_upload(self, url_upload: parse.ParseResult):
        self.__url_upload = url_upload

    def ajouter_upload(
        self, cuuid_parent: str, path_upload: str | pathlib.Path
    ) -> UploadFichier | UploadRepertoire:
        path_upload = pathlib.Path(path_upload)  # type: ignore
        if path_upload.is_dir():  # type: ignore
            upload_item = UploadRepertoire(cuuid_parent, path_upload)  # type: ignore
        else:  # type: ignore
            upload_item = UploadFichier(cuuid_parent, path_upload)  # type: ignore
        self.__upload_queue.append(upload_item)
        self.__upload_pret.set()
        return upload_item  # type: ignore

    def upload_thread(self):
        try:
            while self.__stop_event.is_set() is False:
                # self.update_upload_status()
                self.__event_upload_in_progress.clear()
                if self.__navigation is not None:
                    self.__navigation.refresh()
                self.__upload_pret.wait()
                self.__upload_pret.clear()

                with keep.running():  # Empecher sleep mode
                    while True:
                        # self.update_upload_status()
                        try:
                            self.__upload_en_cours = self.__upload_queue.pop(0)
                            self.__event_upload_in_progress.set()
                        except IndexError:
                            break
                        else:
                            if self.__stop_event.is_set():
                                return  # Stopping
                            try:
                                # self.update_upload_status()
                                if isinstance(self.__upload_en_cours, UploadFichier):
                                    self.upload_fichier(self.__upload_en_cours)
                                elif isinstance(
                                    self.__upload_en_cours, UploadRepertoire
                                ):
                                    self.upload_repertoire(self.__upload_en_cours)
                                else:
                                    self.__logger.error(
                                        "Type upload non supporte : %s"
                                        % self.__upload_en_cours
                                    )
                            except Exception:  # type: ignore
                                self.__logger.exception("Erreur upload")
                            finally:
                                self.__upload_en_cours = None
        except Exception:  # type: ignore
            self.__logger.exception("upload_thread interrompue par error")
            self.__stop_event.set()  # Causer l'arret de l'application
            self.__upload_queue.clear()
        finally:
            self.__upload_en_cours = None  # S'assurer que le label est mis a Inactif

    def upload_status(self):
        status = self.__upload_status()
        return status, self.__upload_en_cours, self.__upload_queue

    def __upload_status(self):
        if isinstance(self.__upload_en_cours, UploadRepertoire):
            if self.__upload_en_cours.taille is None:
                self.__upload_en_cours.preparer_taille()

        if self.__upload_en_cours is not None:
            try:
                progres = int(
                    self.__upload_en_cours.taille_uploade
                    * 100.0
                    / self.__upload_en_cours.taille  # type: ignore
                )  # type: ignore
                fichiers_restants = len(self.__upload_queue)
                if isinstance(self.__upload_en_cours, UploadRepertoire):
                    fichiers_restants += (
                        self.__upload_en_cours.nombre_sous_fichiers
                        - self.__upload_en_cours.fichiers_uploades  # type: ignore[arg-type]
                    )  # type: ignore
                if fichiers_restants > 0:
                    return "Uploading %d%% (%d fichiers restants)" % (
                        progres,
                        fichiers_restants,
                    )
                else:
                    return "Uploading %d%%" % progres
            except Exception:
                self.__logger.debug("Erreur update upload")
                return "Uploading ..."
        elif len(self.__upload_queue) > 0:
            return "Uploading ..."
        else:
            return "Upload inactif"

    def upload_repertoire(
        self, upload: UploadRepertoire, rep_parent: Optional[Repertoire] = None
    ):
        if rep_parent is None:
            cuuid_parent = upload.cuuid_parent
            while True:
                if self.__stop_event.is_set() is True:
                    return  # Stopping
                try:
                    rep_parent = sync_collection(self.__connexion, cuuid_parent)
                    break
                except socketio.exceptions.TimeoutError:
                    self.__logger.exception(
                        "upload_repertoire Erreur sync collection (1), retry dans 20 secondes"
                    )
                    time.sleep(20)
        else:
            cuuid_parent = rep_parent.cuuid

        # Verifier si le repertoire existe deja dans le parent
        nom_repertoire = upload.path.name

        try:
            rep_existant = [
                f for f in rep_parent.fichiers if f["nom"] == nom_repertoire
            ].pop()
            cuuid_courant = rep_existant["tuuid"]
            while True:
                if self.__stop_event.is_set() is True:
                    return  # Stopping
                try:
                    rep_courant = sync_collection(self.__connexion, cuuid_courant)
                    break
                except socketio.exceptions.TimeoutError:
                    self.__logger.exception(
                        "upload_repertoire Erreur sync collection (2), retry dans 20 secondes"
                    )
                    time.sleep(20)

        except IndexError:
            rep_existant = None
            while True:
                if self.__stop_event.is_set() is True:
                    return  # Stopping
                try:
                    # Creer repertoire
                    cuuid_courant = self.creer_collection(nom_repertoire, cuuid_parent)
                    rep_courant = Repertoire(list(), cuuid_courant)
                    break
                except socketio.exceptions.TimeoutError:
                    self.__logger.exception(
                        "upload_repertoire Erreur sync collection (1), retry dans 20 secondes"
                    )
                    time.sleep(20)

        # Generer dict des fichiers/sous-repertoires
        rep_map = dict()
        for item in rep_courant.fichiers:
            rep_map[item["nom"]] = item

        path_src = pathlib.Path(upload.path)
        liste_sous_items = list()
        for t in path_src.iterdir():
            liste_sous_items.append(t)

        # Trier contenu du repertoire : repertoires alphabetiques puis fichiers alphabetiques
        liste_sous_items = sorted(liste_sous_items, key=path_key)

        for t in liste_sous_items:
            nom_item = t.name
            if t.is_dir():
                rep_item = UploadRepertoire(cuuid_courant, t, upload)
                try:
                    item = rep_map[nom_item]
                    # Repertoire existe
                    self.upload_repertoire(rep_item, rep_courant)
                except KeyError:
                    # Nouveau repertoire
                    while True:
                        if self.__stop_event.is_set() is True:
                            return  # Stopping
                        try:
                            self.creer_collection(nom_item, cuuid_courant)
                            break
                        except socketio.exceptions.TimeoutError:
                            self.__logger.exception(
                                "upload_repertoire Erreur creer collection (2), retry dans 20 secondes"
                            )
                            time.sleep(20)
                    self.upload_repertoire(rep_item, None)  # Parent none force resync
            else:
                # Fichier
                try:
                    item = rep_map[nom_item]
                    # Fichier existe, on l'ignore (TODO : verifier hachage si changement)
                except KeyError:
                    fichier_item = UploadFichier(cuuid_courant, t, upload)
                    self.upload_fichier(fichier_item)
                upload.add_fichiers_traite(1)

        pass

    def upload_fichier(self, upload: UploadFichier):
        retry_count = 0
        interval_retry = datetime.timedelta(seconds=20)
        while self.__stop_event.is_set() is False:
            try:
                if retry_count > 0:
                    self.__logger.info(
                        "Upload fichier %s retry %d" % (upload.path, retry_count)
                    )
                    upload.reset_taille_uploade()
                self.__upload_fichier_1pass(upload)
                break
            except Exception:
                self.__logger.exception(
                    "Erreur upload fichier - retry in %s" % interval_retry
                )
                if upload.batch_token is not None:
                    # Delete le contenu partiellement uploade
                    batch_id = upload.batch_token["batchId"]
                    url_collections = self.__connexion.url_collections
                    url_put = f"https://{url_collections.hostname}:444{url_collections.path}/fichiers/upload/{batch_id}"
                    headers = {"x-token-jwt": upload.batch_token["token"]}
                    response = self.__https_session.delete(url_put, headers=headers)
                    if response.status_code not in (200, 404):
                        self.__logger.warning(
                            "Erreur suppression upload partiel, code : %d"
                            % response.status_code
                        )

                    # Reset token
                    upload.batch_token = None

                # Attendre pour retry
                self.__stop_event.wait(timeout=interval_retry.seconds)
                retry_count += 1

    def __upload_fichier_1pass(self, upload: UploadFichier):
        if self.__certificats_chiffrage is None:
            self.__certificats_chiffrage = self.__connexion.get_certificats_chiffrage()

        if self.__https_session is None:
            # Initialiser holder de session https
            self.__https_session = self.__connexion.get_https_session(certs=False)
            self.__connexion.authenticate(self.__https_session)

        # First pass, encrypt the file / get the fuuid
        cle_ca = self.__connexion.ca.get_public_x25519()
        cipher = CipherMgs4(cle_ca)

        with tempfile.NamedTemporaryFile(dir=self.__tmp_path, delete=False) as tmpfile:
            with open(upload.path, "rb") as fichier:
                while cipher.hachage is None:
                    # Preparer chiffrage
                    hacheur = Hacheur(hashing_code="blake2b-512", encoding="base58btc")
                    prepare_file(self.__stop_event, fichier, tmpfile, cipher, hacheur)
            hachage_original = hacheur.finalize()
            secret_key = cipher.cle_secrete
            info_dechiffrage = cipher.get_info_dechiffrage(self.__certificats_chiffrage)
            fuuid = info_dechiffrage["hachage_bytes"]
            encrypted_size = cipher.taille_chiffree

            # Preparer transaction
            stat_fichier = upload.path.stat()
            taille = stat_fichier.st_size
            date_fichier = int(stat_fichier.st_ctime)

            debut_upload = datetime.datetime.now()
            # Move pointer back to beginning of file
            tmpfile.seek(0)
            tmp_name = tmpfile.name
            while True:
                position = tmpfile.tell()
                if position == encrypted_size:
                    break  # Done
                stream = file_iterator(
                    self.__stop_event, tmpfile, UPLOAD_SPLIT_SIZE, upload
                )
                url_put = f"{self.__connexion.filehost_url}/files/{fuuid}/{position}"
                response = self.__https_session.put(url_put, data=stream)
                response.raise_for_status()

        fuuid_rechiffre = cipher.hachage
        # Clean up temporary file
        try:
            os.unlink(tmp_name)
        except Exception:
            pass
        if fuuid != fuuid_rechiffre:
            raise Exception("Digest uploaded mismatches initial value (fuuid)")
        cle_ca_chiffree = info_dechiffrage["cle"]
        cles_chiffrees = info_dechiffrage["cles"]
        taille_chiffree = cipher.taille_chiffree
        taille_dechiffree = cipher.taille_dechiffree

        # Signer cle secrete pour GrosFichiers
        signature_cle = SignatureDomaines.signer_domaines(
            secret_key, ["GrosFichiers"], cle_ca_chiffree
        )

        # Preparer et chiffrer la transaction
        data_dechiffre_transaction = {
            "nom": upload.path.name,
            "taille": taille,
            "dateFichier": date_fichier,
            "hachage_original": hachage_original,
        }
        doc_chiffre = chiffrer_document(
            secret_key, signature_cle.get_cle_ref(), data_dechiffre_transaction
        )
        transaction = {
            "cle_id": signature_cle.get_cle_ref(),
            "cuuid": upload.cuuid,
            "format": "mgs4",
            "fuuid": fuuid,
            "metadata": doc_chiffre,
            "mimetype": upload.mimetype,
            "nonce": info_dechiffrage["header"],
            "taille": taille_dechiffree,
        }

        transaction_cle = {
            "signature": signature_cle.to_dict(),
            "cles": cles_chiffrees,
        }
        transaction_cle, message_id = self.__connexion.formatteur.signer_message(
            Constantes.KIND_COMMANDE,
            transaction_cle,
            domaine="MaitreDesCles",
            action="ajouterCleDomaines",
            ajouter_chaine_certs=True,
        )
        self.__connexion.command(
            transaction,
            "GrosFichiers",
            "nouvelleVersion",
            attachments={"cle": transaction_cle},
        )

        url_confirmation = f"{self.__connexion.filehost_url}/files/{fuuid}"
        confirmation_response = self.__https_session.post(url_confirmation, timeout=300)

        if confirmation_response.status_code == 401:
            # Authenticate and retry
            self.__connexion.authenticate(self.__https_session)
            confirmation_response = self.__https_session.post(
                url_confirmation, timeout=300
            )

        # Note: should handle codes 200, 201 and 202 differently later on (200=>DONE, 202=>ONGOING)
        confirmation_response.raise_for_status()

        fin_upload = datetime.datetime.now()
        duree_upload = fin_upload - debut_upload
        self.__logger.debug(
            "%s Fin upload %s (%d bytes), duree %s"
            % (fin_upload, upload.path.name, taille_chiffree, duree_upload)
        )

    def creer_collection(self, nom: str, cuuid_parent: Optional[str] = None) -> str:
        metadata = {"nom": nom}
        cipher, doc_chiffre = chiffrer_document_nouveau(self.__connexion.ca, metadata)
        info_dechiffrage = cipher.get_info_dechiffrage(
            self.__connexion.get_certificats_chiffrage()
        )
        cle_ca = info_dechiffrage["cle"]
        cles_dechiffrage = info_dechiffrage["cles"]

        # Signer cle
        signature_cle = SignatureDomaines.signer_domaines(
            cipher.cle_secrete, ["GrosFichiers"], cle_ca
        )

        # Ajouter information de cle a metadata de la collection
        doc_chiffre["cle_id"] = signature_cle.get_cle_ref()
        doc_chiffre["format"] = "mgs4"
        doc_chiffre["verification"] = info_dechiffrage["hachage_bytes"]

        transaction = {"metadata": doc_chiffre}

        if cuuid_parent:
            transaction["cuuid"] = cuuid_parent
        else:
            transaction["favoris"] = True

        commande_cle = {
            "signature": signature_cle.to_dict(),
            "cles": cles_dechiffrage,
        }
        commande_cle, message_id = self.__connexion.formatteur.signer_message(
            Constantes.KIND_COMMANDE,
            commande_cle,
            domaine="MaitreDesCles",
            action="ajouterCleDomaines",
            ajouter_chaine_certs=True,
        )

        reponse = self.__connexion.command(
            transaction,
            "GrosFichiers",
            "nouvelleCollection",
            attachments={"cle": commande_cle},
        )

        contenu = json.loads(reponse["contenu"])
        cuuid = contenu["tuuid"]

        return cuuid


UPLOAD_CHUNK_SIZE = 64 * 1024


# def file_iterator(stop_event: Event, fp, cipher, hacheur, maxsize, upload: UploadFichier):
#     current_output_size = 0
#     maxsize = maxsize - UPLOAD_CHUNK_SIZE
#     while current_output_size < maxsize:
#         if stop_event.is_set():
#             raise Exception("Stopping")
#         chunk = fp.read(UPLOAD_CHUNK_SIZE)
#         if len(chunk) == 0:
#             chunk = cipher.finalize()
#             yield chunk
#             return
#         chunk_size = len(chunk)
#         upload.add_chunk_uploade(chunk_size)
#         hacheur.update(chunk)
#         chunk = cipher.update(chunk)
#         if len(chunk) > 0:
#             current_output_size += len(chunk)
#             yield chunk


def file_iterator(stop_event: Event, fp, maxsize, upload: UploadFichier):
    current_output_size = 0
    maxsize = maxsize - UPLOAD_CHUNK_SIZE
    while current_output_size < maxsize:
        if stop_event.is_set():
            raise Exception("Stopping")
        chunk = fp.read(UPLOAD_CHUNK_SIZE)
        if len(chunk) == 0:
            yield chunk
            return
        chunk_size = len(chunk)
        upload.add_chunk_uploade(chunk_size)
        if len(chunk) > 0:
            current_output_size += len(chunk)
            yield chunk


def prepare_file(stop_event: Event, fp, fp_out, cipher, hacheur) -> int:
    current_output_size = 0
    while True:
        if stop_event.is_set():
            raise Exception("Stopping")
        chunk = fp.read(UPLOAD_CHUNK_SIZE)
        if len(chunk) == 0:
            chunk = cipher.finalize()
            if len(chunk) > 0:
                fp_out.write(chunk)
            return current_output_size
        hacheur.update(chunk)
        chunk = cipher.update(chunk)
        if len(chunk) > 0:
            current_output_size += len(chunk)
            fp_out.write(chunk)


class UploaderFrame(tk.Frame):
    def __init__(self, stop_event, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__stop_event = stop_event


def path_key(item: pathlib.Path):
    if item.is_dir():
        key_type = 1
    elif item.is_file():
        key_type = 2
    else:
        key_type = 3
    return key_type, item.name
