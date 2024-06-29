import logging
import tkinter as tk
from tkinter import ttk
from typing import Optional
from threading import Event, Thread

from tksample1.AuthUsager import Authentification
from tksample1.Downloader import Downloader
from tksample1.Uploader import Uploader
from tksample1.Downloader import DownloadFichier
from tksample1.Uploader import UploadFichier


class TransferHandler:

    def __init__(self, stop_event, connexion: Authentification):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event
        self.frame = None
        self.connexion = connexion
        self.transfer_frame = None

        self.downloader = Downloader(self.__stop_event, connexion)
        self.uploader = Uploader(self.__stop_event, connexion)

        self.__navigation = None

        self.__transfer_dirty = Event()
        self.__download_dirty = False
        self.__upload_dirty = False

        self.__thread_status = Thread(name="TransferStatus", target=self.thread_status, daemon=False)
        self.__thread_status.start()

    def quit(self):
        self.uploader.quit()
        self.downloader.quit()

    def set_navigation(self, navigation):
        self.__navigation = navigation
        self.downloader.set_navigation(navigation)
        self.uploader.set_navigation(navigation)

    def set_upload_dirty(self):
        self.__upload_dirty = True
        self.__transfer_dirty.set()

    def set_download_dirty(self):
        self.__download_dirty = True
        self.__transfer_dirty.set()

    def ajouter_download_fichier(self, download, destination=None) -> DownloadFichier:
        return self.downloader.ajouter_download_fichier(download, destination)

    def ajouter_download_repertoire(self, repertoire, destination=None):
        return self.downloader.ajouter_download_repertoire(repertoire, destination)

    def ajouter_upload(self, cuuid_parent: str, path_upload: str) -> UploadFichier:
        return self.uploader.ajouter_upload(cuuid_parent, path_upload)

    def creer_collection(self, nom: str, cuuid_parent: Optional[str] = None) -> str:
        return self.uploader.creer_collection(nom, cuuid_parent)

    def thread_status(self):
        upload_comp = None
        upload_q_comp = None
        download_comp = None
        download_q_comp = None
        while self.__stop_event.is_set() is False:
            self.__transfer_dirty.clear()
            try:
                if self.transfer_frame is not None:
                    # Update status
                    # status_download = 'Download inactif'
                    status_download, download_en_cours, q_download = self.downloader.download_status()
                    self.transfer_frame.download_status_var.set(status_download)

                    status_upload, upload_en_cours, q_upload = self.uploader.upload_status()
                    self.transfer_frame.upload_status_var.set(status_upload)
                    if upload_comp is not upload_en_cours:
                        upload_comp = upload_en_cours
                        self.__upload_dirty = True
                    if upload_q_comp != q_upload:
                        upload_q_comp = q_upload.copy()
                        self.__upload_dirty = True

                    if self.__upload_dirty:
                        self.__upload_dirty = False
                        # Refresh liste uploads
                        self.transfer_frame.refresh_upload(upload_en_cours, q_upload)

                    if download_comp is not download_en_cours:
                        download_comp = download_en_cours
                        self.__download_dirty = True
                    if download_q_comp != q_download:
                        download_q_comp = q_download.copy()
                        self.__download_dirty = True

                    if self.__download_dirty:
                        self.__download_dirty = False
                        # Refresh liste downloads
                        self.transfer_frame.refresh_download(download_en_cours, q_download)
            except:
                self.__logger.exception("Erreur refresh transferts")
                self.__transfer_dirty.wait(timeout=10)

            self.__transfer_dirty.wait(timeout=1)


class TransferFrame(tk.Frame):

    def __init__(self, transfer_handler, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__transfer_handler = transfer_handler

        self.__frame_upload = tk.Frame(master=self)
        self.upload_status_var = tk.StringVar(master=self.__frame_upload, value='Upload ...')
        self.__upload_status_label = tk.Label(master=self.__frame_upload, textvariable=self.upload_status_var, justify="left")
        self.__upload_status_label.grid(row=0, column=0)
        self.__treeview_upload = self.__add_treeview(self.__frame_upload)

        self.__frame_download = tk.Frame(master=self)
        self.download_status_var = tk.StringVar(master=self.__frame_download, value='Download ...')
        self.__download_status_label = tk.Label(master=self.__frame_download, textvariable=self.download_status_var, justify="left")
        self.__download_status_label.grid(row=0, column=0)
        self.__treeview_download = self.__add_treeview(self.__frame_download)

        self.add_widgets()

    def __add_treeview(self, master):
        treeview = ttk.Treeview(master=master, columns=('taille', 'etat'), height=10)
        treeview['columns'] = ('taille', 'etat')

        treeview.heading("taille", text="Taille")
        treeview.heading("etat", text="Etat")

        treeview.column("#0", width=600)
        treeview.column("taille", width=100, anchor='se')
        treeview.column("etat", width=75)

        treeview.grid(row=1, column=0)

        # Calling pack method w.r.to vertical

        return treeview

    def add_widgets(self):
        self.__frame_upload.grid(row=0, column=0)
        self.__frame_download.grid(row=1, column=0)

    def grid(self, *args, **kwargs):
        super().grid(*args, **kwargs)

    def refresh_upload(self, courant, q: list):
        self.__treeview_upload.delete(*self.__treeview_upload.get_children())
        if courant is not None:
            nom_fichier = str(courant.path)
            self.__treeview_upload.insert('', 'end', iid=nom_fichier, text=nom_fichier, values=(courant.taille, "En cours"))
        for item in q:
            path_item = str(item.path)
            if isinstance(item, UploadFichier):
                self.__treeview_upload.insert('', 'end', iid=path_item, text=path_item,
                                              values=(item.taille, "Attente"))
            else:
                item.preparer_taille()
                self.__treeview_upload.insert('', 'end', iid=path_item, text=path_item,
                                              values=(item.taille, "Attente"))

    def refresh_download(self, courant, q: list):
        self.__treeview_download.delete(*self.__treeview_download.get_children())
        if courant is not None:
            nom_fichier = courant.nom
            try:
                taille = str(courant.taille_chiffree)
            except AttributeError:
                taille = "N/D"
            self.__treeview_download.insert('', 'end', iid=courant.tuuid, text=nom_fichier, values=(taille, "En cours"))
        for item in q:
            nom_item = item.nom
            if isinstance(item, DownloadFichier):
                self.__treeview_download.insert('', 'end', iid=item.tuuid, text=nom_item,
                                              values=(item.taille_chiffree, "Attente"))
            else:
                item.preparer_taille()
                self.__treeview_download.insert('', 'end', iid=item.tuuid, text=nom_item,
                                              values=("N/D", "Attente"))
