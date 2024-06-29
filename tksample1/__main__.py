import logging
import time

import tkinter as tk
from tkinter import ttk
from threading import Event, Thread, active_count, enumerate

from tksample1.AuthUsager import Authentification, AuthFrame
from tksample1.Navigation import Navigation, NavigationFrame
from tksample1.FileTransfer import TransferHandler, TransferFrame


class App:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = Event()
        self.__exit_code = 0
        self.auth = Authentification(self.__stop_event)
        self.transfer_handler = TransferHandler(self.__stop_event, self.auth)
        self.navigation = Navigation(self.__stop_event, self.auth, self.transfer_handler)
        self.window = Window(self.__stop_event, self.auth, self.navigation, self.transfer_handler)

    def exec(self):
        self.__logger.info("Debut mainloop")
        Thread(name="Stop thread", target=self.stop_thread).start()
        self.auth.init_config()
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
        self.navigation.quit()
        # self.downloader.quit()
        # self.uploader.quit()
        self.transfer_handler.quit()

        self.__logger.info("Arret complete, exit code : %d" % self.__exit_code)

        active_threads = active_count()
        if active_threads > 0:
            self.__logger.warning("Active threads : %d" % active_threads)
            time.sleep(10)
            for t in enumerate():
                self.__logger.warning("Active thread : %s" % t)

        exit(self.__exit_code)


class Window(tk.Tk):

    def __init__(self, stop_event: Event, auth: Authentification, navigation: Navigation, transfer_handler: TransferHandler, *args, **kwargs):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event

        super().__init__(*args, **kwargs)

        self.title("Transfer Tool - MilleGrilles")

        self.geometry("800x600")

        self.auth = auth

        self.__frame_notebook = ttk.Notebook(self)

        self.__frame_auth = AuthFrame(auth)
        # self.__frame_auth.pack()
        self.__frame_auth.grid(row=0, column=0)

        self.__frame_notebook.grid(row=1, column=0)

        self.__frame_navigation = NavigationFrame(navigation, master=self.__frame_notebook)
        # self.__frame_navigation.pack()
        self.__frame_notebook.add(self.__frame_navigation, text="Navigation")
        # grid(row=0, column=0)

        self.__frame_transfert = TransferFrame(transfer_handler)
        self.__frame_notebook.add(self.__frame_transfert, text="Transferts")

        # Wiring du frame dans Authentification - permet changer affichage
        self.auth.auth_frame = self.__frame_auth
        navigation.nav_frame = self.__frame_navigation
        transfer_handler.transfer_frame = self.__frame_transfert


if __name__ == '__main__':
    logging.basicConfig(level=logging.ERROR)
    logging.getLogger('__main__').setLevel(logging.DEBUG)
    logging.getLogger('tksample1').setLevel(logging.DEBUG)
    App().exec()
