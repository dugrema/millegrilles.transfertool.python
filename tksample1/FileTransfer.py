import logging
import tkinter as tk
from tkinter import ttk
from typing import Optional

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

    def quit(self):
        self.uploader.quit()
        self.downloader.quit()

    def set_navigation(self, navigation):
        self.__navigation = navigation
        self.downloader.set_navigation(navigation)
        self.uploader.set_navigation(navigation)

    def ajouter_download_fichier(self, download, destination=None) -> DownloadFichier:
        return self.downloader.ajouter_download_fichier(download, destination)

    def ajouter_download_repertoire(self, repertoire, destination=None):
        return self.downloader.ajouter_download_repertoire(repertoire, destination)

    def ajouter_upload(self, cuuid_parent: str, path_upload: str) -> UploadFichier:
        return self.uploader.ajouter_upload(cuuid_parent, path_upload)

    def creer_collection(self, nom: str, cuuid_parent: Optional[str] = None) -> str:
        return self.uploader.creer_collection(nom, cuuid_parent)


class TransferFrame(tk.Frame):

    def __init__(self, transfer_handler, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__transfer_handler = transfer_handler

        self.__frame_upload = tk.Frame(master=self)
        self.upload_status_var = tk.StringVar(master=self.__frame_upload, value='Upload inactif')
        self.__upload_status_label = tk.Label(master=self.__frame_upload, textvariable=self.upload_status_var, justify="left")
        self.__upload_status_label.grid(row=0, column=0)
        self.__treeview_upload = self.__add_treeview_upload()

        self.__frame_download = tk.Frame(master=self)
        self.download_status_var = tk.StringVar(master=self.__frame_download, value='Download inactif')
        self.__download_status_label = tk.Label(master=self.__frame_download, textvariable=self.download_status_var, justify="left")
        self.__download_status_label.grid(row=0, column=0)

        self.__add_treeview_upload()

        self.add_widgets()

    def __add_treeview_upload(self):
        treeview = ttk.Treeview(master=self.__frame_upload, columns=('taille', 'etat'), height=25)
        treeview['columns'] = ('taille', 'etat')

        treeview.heading("taille", text="Taille")
        treeview.heading("etat", text="Etat")

        treeview.column("#0", width=500)
        treeview.column("taille", width=100, anchor='se')
        treeview.column("etat", width=50)

        treeview.grid(row=1, column=0)

        # Calling pack method w.r.to vertical

        return treeview

    def add_widgets(self):
        self.__frame_upload.grid(row=0, column=0)
        self.__frame_download.grid(row=1, column=0)

    def grid(self, *args, **kwargs):
        super().grid(*args, **kwargs)

