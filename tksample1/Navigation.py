import logging
import tkinter as tk
from tkinter import ttk
import json
import multibase
import datetime
import pathlib
import pytz

from typing import Optional
from threading import Event, Thread

from millegrilles_messages.messages import Constantes

from tksample1.AuthUsager import Authentification


from millegrilles_messages.chiffrage.DechiffrageUtils import dechiffrer_reponse, dechiffrer_document_secrete


class Repertoire:

    def __init__(self, fichiers: list, cuuid: Optional[str] = None):
        self.fichiers = fichiers
        self.cuuid = cuuid


class Navigation:

    def __init__(self, stop_event, connexion: Authentification):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event
        self.frame = None
        self.connexion = connexion
        self.nav_frame = None

        self.__event_dirty = Event()

        self.breadcrumb = list()

        self.__cuuid_a_charger = None
        self.__repertoire = None

        self.__thread = Thread(name="Navigation", target=self.run)
        self.__thread.start()

    def changer_cuuid(self, cuuid: Optional[str] = None):
        self.__cuuid_a_charger = cuuid
        self.__event_dirty.set()

    def __charger_cuuid(self, cuuid: Optional[str] = None):
        # self.__event_dirty.clear()
        cuuid = cuuid or self.__cuuid_a_charger
        self.__cuuid_a_charger = None

        if cuuid is None:
            self.__repertoire = sync_collection(self.connexion)
        else:
            try:
                if self.breadcrumb[-1]['tuuid'] != cuuid:
                    append_cuuid = True
                else:
                    append_cuuid = False
            except IndexError:
                append_cuuid = True

            if append_cuuid:
                # Changer breadcrumb, ajouter repertoire selectionne
                repertoire = [c for c in self.__repertoire.fichiers if c['tuuid'] == cuuid].pop()
                self.breadcrumb.append(repertoire)
                breadcrumb_path = [p['nom'] for p in self.breadcrumb]
                breadcrumb_path = pathlib.Path('favoris', *breadcrumb_path)
                self.nav_frame.set_breadcrumb(breadcrumb_path)

            # Recuperer contenu du repertoire
            self.__repertoire = sync_collection(self.connexion, cuuid)

        self.nav_frame.afficher_repertoire(self.__repertoire)

    def naviguer_up(self):
        if len(self.breadcrumb) == 0:
            return
        self.breadcrumb = self.breadcrumb[:-1]
        breadcrumb_path = [p['nom'] for p in self.breadcrumb]
        self.nav_frame.set_breadcrumb(pathlib.Path('favoris', *breadcrumb_path))

        # Naviguer vers
        try:
            self.__cuuid_a_charger = self.breadcrumb[-1]['tuuid']
        except (KeyError, IndexError, AttributeError):
            self.__cuuid_a_charger = None

        self.__event_dirty.set()

    def run(self):
        self.__event_dirty.set()

        while self.__stop_event.is_set() is False:
            self.connexion.connect_event.wait()
            if self.__stop_event.is_set():
                return  # Stopping

            self.__event_dirty.wait()
            self.__event_dirty.clear()

            # Charger le repertoire
            self.__charger_cuuid()


class NavigationFrame(tk.Frame):

    def __init__(self, navigation, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__navigation = navigation
        self.__repertoire: Optional[Repertoire] = None

        self.__breadcrumb_path = pathlib.Path('Favoris/')
        self.breadcrumb = tk.StringVar(master=self, value=str(self.__breadcrumb_path))
        self.__breadcrumb_label = tk.Label(master=self, textvariable=self.breadcrumb, justify="left")
        self.__btn_up = tk.Button(master=self, text="Up", command=self.btn_up_handler)

        self.dirlist = ttk.Treeview(master=self, columns=('taille', 'type', 'date'))
        self.dirlist['columns'] = ('taille', 'type', 'date')

        self.widget_bind()

    def widget_bind(self):
        self.dirlist.bind('<Button-3>', self.dirlist_rightclick_fichier)
        self.dirlist.bind('<Double-Button-1>', self.dirlist_doubleclick_fichier)

    def pack(self):
        self.__breadcrumb_label.pack()
        self.__btn_up.pack()
        self.dirlist.pack()
        super().pack()

    def btn_up_handler(self):
        self.__navigation.naviguer_up()

    def set_breadcrumb(self, breadcrumb: pathlib.Path):
        self.breadcrumb.set(str(breadcrumb))

    def afficher_repertoire(self, repertoire: Repertoire):
        self.__repertoire = repertoire
        children = self.dirlist.get_children()
        if len(children) > 0:
            for c in children:
                self.dirlist.delete(c)

        def sort_nom(item):
            if item['type_node'] == 'Fichier':
                tn = '2'
            else:
                tn = '1'
            return tn + item['nom']

        fichiers_tries = sorted(self.__repertoire.fichiers, key=sort_nom)

        for fichier in fichiers_tries:
            nom_fichier = fichier['nom']
            taille_fichier = ''
            type_node = fichier['type_node']
            tuuid = fichier['tuuid']
            if type_node in ['Collection', 'Repertoire']:
                type_fichier = 'Repertoire'
                date_fichier = datetime.datetime.fromtimestamp(fichier['derniere_modification'], tz=pytz.UTC)
            else:
                type_fichier = 'Fichier'
                date_fichier = None
            self.dirlist.insert('', 'end', iid=tuuid, text=nom_fichier, values=(taille_fichier, type_fichier, date_fichier))

    def dirlist_rightclick_fichier(self, event):
        pass

    def dirlist_doubleclick_fichier(self, event):
        tuuid = self.dirlist.focus()
        item = self.dirlist.item(tuuid)
        values = item['values']
        if values[1] != 'Fichier':
            self.__navigation.changer_cuuid(tuuid)
        else:
            raise NotImplementedError('todo - download fichier')


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

    fichiers_recus = [f for f in contenu_sync['liste'] if f['supprime'] is False]
    tuuids = [f['tuuid'] for f in fichiers_recus]

    if len(tuuids) == 0:
        # Aucun fichier a charger (repertoire vide)
        return Repertoire(list(), cuuid)

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

    rep = Repertoire(fichiers, cuuid)

    return rep
