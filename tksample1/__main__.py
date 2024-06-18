import asyncio
import logging

import tkinter as tk
from tkinter import ttk
import requests
from threading import Event, Thread
from urllib import parse

from tksample1.AuthUsager import Authentification


class App:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = Event()
        self.__exit_code = 0
        self.auth = Authentification(self.__stop_event)

        self.window = Window(self.__stop_event, self.auth)

    def exec(self):
        self.__logger.info("Debut mainloop")
        Thread(name="Stop thread", target=self.stop_thread).start()
        self.window.mainloop()
        if self.__stop_event.is_set() is False:
            self.__stop_event.set()
            self.__exit_code = 0  # Sortie normale par fermeture de la fenetre

    def stop_thread(self):
        self.__logger.info("Attente arret app")
        self.__stop_event.wait()

        # Arreter toutes les threads
        self.__logger.info("Arret App")
        self.window.quit()
        self.auth.quit()

        self.__logger.info("Arret complete, exit code : %d" % self.__exit_code)
        exit(self.__exit_code)


class Window(tk.Tk):

    def __init__(self, stop_event: Event, auth: Authentification, *args, **kwargs):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event

        super().__init__(*args, **kwargs)

        self.auth = auth

        self.label_nomusager = tk.Label(text="Nom usager")
        self.entry_nomusager = tk.Entry(width=20)
        self.label_url_serveur = tk.Label(text="URL serveur")
        self.entry_serveur = tk.Entry(width=60)

        self.button_connecter = tk.Button(text="Connecter", command=self.connecter_usager)
        self.button_deconnecter = tk.Button(text="Deconnecter", command=self.deconnecter_usager)

        self.label_nomusager.pack()
        self.entry_nomusager.pack()
        self.label_url_serveur.pack()
        self.entry_serveur.pack()
        self.button_connecter.pack()
        self.button_deconnecter.pack()

        self.init_config()

    def init_config(self):
        if self.auth.charger_configuration():
            self.entry_nomusager.insert(0, self.auth.nom_usager)
            serveur_url = self.auth.url_fiche_serveur.hostname
            self.entry_serveur.insert(0, serveur_url)
            self.connecter_usager()

    def connecter_usager(self):
        nom_usager = self.entry_nomusager.get()
        valeur_url = self.entry_serveur.get()
        self.auth.authentifier(nom_usager, valeur_url)

    def deconnecter_usager(self):
        self.auth.effacer_usager()
        self.auth.deconnecter()
        self.__logger.info("Usager deconnecte, configuration supprimee")


if __name__ == '__main__':
    logging.basicConfig(level=logging.ERROR)
    logging.getLogger('__main__').setLevel(logging.DEBUG)
    logging.getLogger('tksample1').setLevel(logging.DEBUG)
    App().exec()
