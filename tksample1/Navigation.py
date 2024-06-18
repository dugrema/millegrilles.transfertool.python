import logging
import tkinter as tk
import json
import multibase

from typing import Optional
from threading import Event, Thread

from millegrilles_messages.messages import Constantes

from tksample1.AuthUsager import Authentification


from millegrilles_messages.chiffrage.DechiffrageUtils import dechiffrer_reponse, dechiffrer_document_secrete


class Navigation:

    def __init__(self, stop_event, connexion: Authentification):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event
        self.frame = None
        self.connexion = connexion
        self.nav_frame = None

        self.__event_dirty = Event()

        self.__tuuid_courant = None

        self.__thread = Thread(name="Navigation", target=self.run)
        self.__thread.start()

    def charger_tuuid(self, tuuid: Optional[str] = None):
        self.__event_dirty.clear()

        if tuuid is None:
            reponse = sync_collection(self.connexion)
            self.__tuuid_courant = True  # Favoris
        else:
            raise NotImplementedError()

    def run(self):
        self.__event_dirty.set()

        while self.__stop_event.is_set() is False:
            self.connexion.connect_event.wait()
            if self.__stop_event.is_set():
                return  # Stopping

            self.__event_dirty.wait()

            # Determiner action
            if self.__tuuid_courant is None:
                # Charger les favoris
                self.charger_tuuid()


class NavigationFrame(tk.Frame):

    def __init__(self, navigation, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__navigation = navigation

    def pack(self):
        super().pack()


def sync_collection(connexion, cuuid: Optional[str] = None):

    limit = 100
    skip = 0

    requete = {
        'limit': limit,
        'skip': skip,
        'cuuid': cuuid,
    }

    requete_favoris, message_id = connexion.formatteur.signer_message(
        Constantes.KIND_REQUETE, requete, 'GrosFichiers', True, 'syncCollection')

    reponse_sync = connexion.call('syncCollection', requete_favoris, timeout=5)
    contenu_sync = json.loads(reponse_sync['contenu'])

    if contenu_sync['complete'] is False:
        raise NotImplementedError('TODO : liste incomplete')

    favoris = [f for f in contenu_sync['liste'] if f['supprime'] is False]
    tuuids = [f['tuuid'] for f in favoris]

    # Charger les documents
    requete_documents = {'tuuids_documents': tuuids, 'partage': False, 'contact_id': None}
    requete_documents, message_id = connexion.formatteur.signer_message(
        Constantes.KIND_REQUETE, requete_documents, 'GrosFichiers', True, 'documentsParTuuid')
    reponse_documents = connexion.call('getDocuments', requete_documents, timeout=30)
    contenu_documents = json.loads(reponse_documents['contenu'])
    fichiers = contenu_documents['fichiers']
    cle_ids = set()
    for fichier in fichiers:
        try:
            cle_id = fichier['metadata']['cle_id']
            cle_ids.add(cle_id)
        except KeyError:
            pass

    cle_ids = list(cle_ids)

    # Charger les cles de dechiffrage
    #   const params = { fuuids, partage, version: 2 }
    #   return connexionClient.emitWithAck(
    #     'getPermissionCles', params,
    #     {
    #       kind: MESSAGE_KINDS.KIND_REQUETE, domaine: CONST_DOMAINE_GROSFICHIERS, action: 'getClesFichiers',
    #       timeout: 30_000, ajouterCertificat: true
    #     }
    #   )
    requete_cles = {'fuuids': cle_ids, 'partage': False, 'version': 2}
    requete_cles, message_id = connexion.formatteur.signer_message(
        Constantes.KIND_REQUETE, requete_cles, 'GrosFichiers', True, 'getClesFichiers')

    reponse_cles = connexion.call('getPermissionCles', requete_cles, timeout=30)
    cles_dechiffrees = dechiffrer_reponse(connexion.clecert, reponse_cles)

    cles = dict()
    for cle in cles_dechiffrees['cles']:
        cle['cle_secrete'] = multibase.decode('m'+cle['cle_secrete_base64'])
        cles[cle['cle_id']] = cle

    # Dechiffrer metadata des fichiers et repertoires
    for fichier in fichiers:
        metadata_chiffre = fichier['metadata']
        cle_id = metadata_chiffre.get('cle_id') or metadata_chiffre.get('ref_hachage_bytes') or metadata_chiffre['hachage_bytes']
        cle_secrete = cles[cle_id]['cle_secrete']
        info_dechiffree = dechiffrer_document_secrete(cle_secrete, metadata_chiffre)

        fichier.update(info_dechiffree)

    pass
