import logging
import tkinter as tk

from tksample1.AuthUsager import Authentification

class Navigation:

    def __init__(self, connexion: Authentification):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.frame = None
        self.connexion = connexion


class NavigationFrame(tk.Frame):

    def __init__(self, navigation, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__navigation = navigation

    def pack(self):
        super().pack()
