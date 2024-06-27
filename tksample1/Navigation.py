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
from millegrilles_messages.chiffrage.SignatureDomaines import SignatureDomaines

from tksample1.AuthUsager import Authentification


from millegrilles_messages.chiffrage.DechiffrageUtils import dechiffrer_reponse, dechiffrer_document_secrete
from millegrilles_messages.chiffrage.Mgs4 import chiffrer_document_nouveau

LOGGER = logging.getLogger(__name__)


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

    def creer_collection(self, nom: str):
        cuuid_parent = self.__repertoire.cuuid
        self.uploader.creer_collection(nom, cuuid_parent)

    def set_upload_status(self, status: str):
        if self.nav_frame is None:
            return  # Init en cours
        self.nav_frame.set_upload_status(status)

    def set_download_status(self, status: str):
        if self.nav_frame is None:
            return  # Init en cours
        self.nav_frame.set_download_status(status)


class NavigationFrame(tk.Frame):

    def __init__(self, navigation, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__navigation = navigation
        self.__repertoire: Optional[Repertoire] = None

        self.__frame_actions = tk.Frame(master=self)
        self.__btn_creer_collection = tk.Button(master=self.__frame_actions, text="+ Collection", command=self.btn_creer_collection)
        self.__btn_creer_collection.grid(row=0, column=0)
        self.__btn_download = tk.Button(master=self.__frame_actions, text="Download", command=self.btn_download_handler)
        self.__btn_download.grid(row=0, column=1)
        self.__btn_upload = tk.Button(master=self.__frame_actions, text="Upload", command=self.btn_upload_handler)
        self.__btn_upload.grid(row=0, column=2)
        self.__btn_upload_dir = tk.Button(master=self.__frame_actions, text="Upload Dir", command=self.btn_upload_dir_handler)
        self.__btn_upload_dir.grid(row=0, column=3)
        self.__btn_refresh = tk.Button(master=self.__frame_actions, text="Refresh", command=self.btn_refresh)
        self.__btn_refresh.grid(row=0, column=4)

        self.__frame_breadcrumb = tk.Frame(master=self)
        self.__breadcrumb_path = pathlib.Path('Favoris/')
        self.breadcrumb = tk.StringVar(master=self.__frame_breadcrumb, value=str(self.__breadcrumb_path))
        self.__breadcrumb_label = tk.Label(master=self.__frame_breadcrumb, textvariable=self.breadcrumb, justify="left")
        self.__btn_up = tk.Button(master=self.__frame_breadcrumb, text="Up", command=self.btn_up_handler)
        # self.__btn_up.grid(row=0, column=0)
        # self.__breadcrumb_label.grid(row=0, column=1)
        self.__btn_up.pack(side=tk.LEFT)
        self.__breadcrumb_label.pack(side=tk.LEFT)

        self.__frame_transfer_status = tk.Frame(master=self)
        self.upload_status_var = tk.StringVar(master=self.__frame_transfer_status, value='Upload inactif')
        self.download_status_var = tk.StringVar(master=self.__frame_transfer_status, value='Download inactif')
        self.__upload_status_label = tk.Label(master=self.__frame_transfer_status, textvariable=self.upload_status_var, justify="left")
        self.__download_status_label = tk.Label(master=self.__frame_transfer_status, textvariable=self.download_status_var, justify="left")
        self.__upload_status_label.pack(fill=tk.X)
        self.__download_status_label.pack(fill=tk.X)

        self.__dir_frame = ttk.Frame(master=self)
        self.dirlist = ttk.Treeview(master=self.__dir_frame, columns=('taille', 'type', 'date'), height=25)
        self.dirlist['columns'] = ('taille', 'type', 'date')

        self.dirlist.heading("taille", text="Taille")
        self.dirlist.heading("type", text="Type")
        self.dirlist.heading("date", text="Date")

        self.dirlist.column("taille", width=90, anchor='se')
        self.dirlist.column("type", width=100)
        self.dirlist.column("date", width=145)

        self.dirlist.pack(side=tk.LEFT, fill=tk.BOTH)

        # Calling pack method w.r.to vertical
        # scrollbar
        verscrlbar = ttk.Scrollbar(self.__dir_frame,
                                  orient="vertical",
                                  command=self.dirlist.yview)
        # Configuring treeview
        verscrlbar.pack(side=tk.LEFT, fill='y')
        self.dirlist.configure(xscrollcommand=verscrlbar.set)

        self.widget_bind()

    def widget_bind(self):
        self.dirlist.bind('<Button-3>', self.dirlist_rightclick_fichier)
        self.dirlist.bind('<Double-Button-1>', self.dirlist_doubleclick_fichier)

    # def pack(self):
    #     # self.__btn_refresh.pack()
    #     # self.__btn_creer_collection.pack()
    #     # self.__btn_download.pack()
    #     # self.__btn_upload.pack()
    #     # self.__btn_upload_dir.pack()
    #     self.__frame_actions.grid(row=0, column=0)
    #
    #     self.__frame_actions.grid(row=1, column=0)
    #     self.__frame_breadcrumb.grid(row=2, column=0)
    #     # self.__breadcrumb_label.pack()
    #     # self.__btn_up.grid(row=0, column=0)
    #     # self.__breadcrumb_label.pack()
    #
    #     self.__dir_frame.grid(row=3, column=0)
    #     # self.dirlist.pack(side="right")
    #
    #     super().grid(row=0, column=1)

    def grid(self, *args, **kwargs):
        self.__frame_actions.grid(row=0, column=0)
        self.__frame_actions.grid(row=1, column=0)
        self.__frame_breadcrumb.grid(row=2, column=0)
        self.__frame_transfer_status.grid(row=3, column=0)
        self.__dir_frame.grid(row=4, column=0)

        super().grid(*args, **kwargs)

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

    def btn_creer_collection(self):
        nom_collection = tkinter.simpledialog.askstring(title="Creer repertoire", prompt="Nom du repertoire")
        self.__navigation.creer_collection(nom_collection)

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
            return tn + (item.get('nom') or item['tuuid'])

        fichiers_tries = sorted(self.__repertoire.fichiers, key=sort_nom)

        for fichier in fichiers_tries:
            nom_fichier = fichier.get('nom') or fichier['tuuid']
            taille_fichier = ''
            type_node = fichier['type_node']
            tuuid = fichier['tuuid']
            if type_node in ['Collection', 'Repertoire']:
                type_fichier = 'Repertoire'
                date_fichier = datetime.datetime.fromtimestamp(fichier['derniere_modification'], tz=pytz.UTC)
            else:
                version_courante = fichier['version_courante']
                taille_fichier = version_courante['taille']
                type_fichier = 'Fichier'
                date_fichier = datetime.datetime.fromtimestamp(fichier['dateFichier'], tz=pytz.UTC)
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

    def set_download_status(self, status: str):
        self.download_status_var.set(status)

    def set_upload_status(self, status: str):
        self.upload_status_var.set(status)


def sync_collection(connexion, cuuid: Optional[str] = None):

    limit = 100
    skip = 0

    tuuids = list()
    while True:
        requete = {
            'limit': limit,
            'skip': skip,
            'cuuid': cuuid,
        }

        requete_favoris, message_id = connexion.formatteur.signer_message(
            Constantes.KIND_REQUETE, requete, 'GrosFichiers', True, 'syncCollection')

        reponse_sync = connexion.call('syncCollection', requete_favoris, timeout=5)
        contenu_sync = json.loads(reponse_sync['contenu'])

        fichiers_recus = [f for f in contenu_sync['liste'] if f['supprime'] is False]
        tuuids_recus = [f['tuuid'] for f in fichiers_recus]

        skip += len(tuuids_recus)
        tuuids.extend(tuuids_recus)

        if contenu_sync['complete'] is True:
            break

    if len(tuuids) == 0:
        # Aucun fichier a charger (repertoire vide)
        return Repertoire(list(), cuuid)

    # Charger les documents
    fichiers_complet = list()
    while len(tuuids) > 0:
        batch_tuuids = tuuids[0:50]
        tuuids = tuuids[50:]
        fichiers = recevoir_metadata_fichiers(connexion, batch_tuuids)
        fichiers_complet.extend(fichiers)

    rep = Repertoire(fichiers_complet, cuuid)

    return rep


def recevoir_metadata_fichiers(connexion, tuuids):
    requete_documents = {'tuuids_documents': tuuids, 'partage': False, 'contact_id': None}
    requete_documents, message_id = connexion.formatteur.signer_message(
        Constantes.KIND_REQUETE, requete_documents, 'GrosFichiers', True, 'documentsParTuuid')
    reponse_documents = connexion.call('getDocuments', requete_documents, timeout=30)
    contenu_documents = json.loads(reponse_documents['contenu'])
    fichiers = contenu_documents['fichiers']
    cle_ids = set()
    for fichier in fichiers:
        try:
            metadata_chiffre = fichier['metadata']
            cle_id = metadata_chiffre.get('cle_id') or metadata_chiffre.get('ref_hachage_bytes') or metadata_chiffre[
                'hachage_bytes']
            cle_ids.add(cle_id)
        except KeyError:
            cle_id = fichier['version_courante']['fuuid']
            cle_ids.add(cle_id)
    cle_ids = list(cle_ids)
    # Charger les cles de dechiffrage
    requete_cles = {'fuuids': cle_ids, 'partage': False, 'version': 2}
    requete_cles, message_id = connexion.formatteur.signer_message(
        Constantes.KIND_REQUETE, requete_cles, 'GrosFichiers', True, 'getClesFichiers')
    reponse_cles = connexion.call('getPermissionCles', requete_cles, timeout=30)
    cles_dechiffrees = dechiffrer_reponse(connexion.clecert, reponse_cles)
    cles = dict()
    for cle in cles_dechiffrees['cles']:
        cle['cle_secrete'] = multibase.decode('m' + cle['cle_secrete_base64'])
        cles[cle['cle_id']] = cle
    # Dechiffrer metadata des fichiers et repertoires
    for fichier in fichiers:
        metadata_chiffre = fichier['metadata']
        try:
            cle_id = metadata_chiffre.get('cle_id') or metadata_chiffre.get('ref_hachage_bytes') or metadata_chiffre[
                'hachage_bytes']
        except KeyError:
            cle_id = fichier['version_courante']['fuuid']
        try:
            info_cle = cles[cle_id]
            cle_secrete = info_cle['cle_secrete']
        except KeyError:
            LOGGER.warning('Cle manquante pour %s, SKIP', fichier)
        else:
            fichier['info_cle'] = info_cle
            fichier['cle_secrete'] = cle_secrete
            info_dechiffree = dechiffrer_document_secrete(cle_secrete, metadata_chiffre)
            fichier.update(info_dechiffree)

    return fichiers
