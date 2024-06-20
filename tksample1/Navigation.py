import logging
import tkinter as tk
import tkinter.filedialog
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

    def __init__(self, stop_event, connexion: Authentification, downloader, uploader):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event
        self.frame = None
        self.connexion = connexion
        self.downloader = downloader
        self.uploader = uploader
        self.nav_frame = None

        downloader.set_navigation(self)
        uploader.set_navigation(self)

        self.__event_dirty = Event()

        self.breadcrumb = list()

        self.__cuuid_a_charger = None
        self.__repertoire = None

        self.__thread = Thread(name="Navigation", target=self.run)
        self.__thread.start()

    def quit(self):
        self.__event_dirty.set()

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
            if self.__stop_event.is_set():
                return  # Stopping

            self.__event_dirty.clear()

            # Charger le repertoire
            self.__charger_cuuid()

    def ajouter_download(self, tuuid):
        tuuid_node = [f for f in self.__repertoire.fichiers if f['tuuid'] == tuuid].pop()
        if tuuid_node['type_node'] == 'Fichier':
            self.downloader.ajouter_download_fichier(tuuid_node)
        else:
            self.downloader.ajouter_download_repertoire(tuuid_node)

    def upload_fichier(self, path_fichier: str):
        cuuid = self.__repertoire.cuuid
        if cuuid is None:
            raise Exception('Upload dans Favoris non supporte')
        self.uploader.ajouter_upload(cuuid, path_fichier)

    def upload_directory(self, path_dir: str):
        cuuid = self.__repertoire.cuuid
        if cuuid is None:
            raise Exception('Upload dans Favoris non supporte')
        self.uploader.ajouter_upload(cuuid, path_dir)


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

        self.__btn_download = tk.Button(master=self, text="Download", command=self.btn_download_handler)
        self.__btn_upload = tk.Button(master=self, text="Upload", command=self.btn_upload_handler)
        self.__btn_upload_dir = tk.Button(master=self, text="Upload Dir", command=self.btn_upload_dir_handler)
        self.__btn_refresh = tk.Button(master=self, text="Refresh", command=self.btn_refresh)

        self.dirlist = ttk.Treeview(master=self, columns=('taille', 'type', 'date'))
        self.dirlist['columns'] = ('taille', 'type', 'date')

        self.widget_bind()

    def widget_bind(self):
        self.dirlist.bind('<Button-3>', self.dirlist_rightclick_fichier)
        self.dirlist.bind('<Double-Button-1>', self.dirlist_doubleclick_fichier)

    def pack(self):
        self.__breadcrumb_label.pack()
        self.__btn_up.pack()
        self.__btn_refresh.pack()
        self.__btn_download.pack()
        self.__btn_upload.pack()
        self.__btn_upload_dir.pack()
        self.dirlist.pack()
        super().pack()

    def btn_up_handler(self):
        self.__navigation.naviguer_up()

    def btn_download_handler(self):
        selection = self.dirlist.selection()
        for tuuid in selection:
            self.__navigation.ajouter_download(tuuid)

    def btn_upload_handler(self):
        fichiers = tkinter.filedialog.askopenfilenames()
        for fichier in fichiers:
            self.__navigation.upload_fichier(fichier)

    def btn_upload_dir_handler(self):
        path_dir = tkinter.filedialog.askdirectory()
        if path_dir != '':
            self.__navigation.upload_directory(path_dir)

    def btn_refresh(self):
        cuuid = self.__repertoire.cuuid
        self.__navigation.changer_cuuid(cuuid)

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
            self.__navigation.ajouter_download(tuuid)


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

        fichier['cle_secrete'] = cle_secrete

        info_dechiffree = dechiffrer_document_secrete(cle_secrete, metadata_chiffre)

        fichier.update(info_dechiffree)

    rep = Repertoire(fichiers, cuuid)

    return rep
