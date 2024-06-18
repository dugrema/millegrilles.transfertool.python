import logging

import tkinter as tk
from threading import Event, Thread

from tksample1.AuthUsager import Authentification, AuthFrame
from tksample1.Navigation import NavigationFrame

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

        self.__logger.info("Arret complete, exit code : %d" % self.__exit_code)
        exit(self.__exit_code)


class Window(tk.Tk):

    def __init__(self, stop_event: Event, auth: Authentification, *args, **kwargs):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event

        super().__init__(*args, **kwargs)

        self.auth = auth

        self.__frame_auth = AuthFrame(auth)
        self.__frame_auth.pack()
        # Wiring du frame dans Authentification - permet changer affichage
        self.auth.auth_frame = self.__frame_auth


if __name__ == '__main__':
    logging.basicConfig(level=logging.ERROR)
    logging.getLogger('__main__').setLevel(logging.DEBUG)
    logging.getLogger('tksample1').setLevel(logging.DEBUG)
    App().exec()
