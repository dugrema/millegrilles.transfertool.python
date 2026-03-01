import argparse
import logging
import time
import tkinter as tk
from threading import Event, Thread, active_count, enumerate
from tkinter import ttk
from typing import Optional

from tksample1.AuthUsager import Authentification, AuthFrame
from tksample1.Configuration import Configuration
from tksample1.FileTransfer import TransferFrame, TransferHandler
from tksample1.Navigation import Navigation, NavigationFrame


class App:
    def __init__(self, config: Optional[Configuration] = None):
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__stop_event = Event()
        self.__exit_code = 0
        self.config = config or Configuration.default()

        # Initialize Authentification with configuration paths
        self.auth = Authentification(
            self.__stop_event, downdir=self.config.downdir, tmpdir=self.config.tmpdir
        )
        self.transfer_handler = TransferHandler(self.__stop_event, self.auth)
        self.navigation = Navigation(
            self.__stop_event, self.auth, self.transfer_handler
        )
        self.window = Window(
            self.__stop_event, self.auth, self.navigation, self.transfer_handler
        )

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
    def __init__(
        self,
        stop_event: Event,
        auth: Authentification,
        navigation: Navigation,
        transfer_handler: TransferHandler,
        *args,
        **kwargs,
    ):
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__stop_event = stop_event

        super().__init__(*args, **kwargs)

        self.title("Transfer Tool - MilleGrilles")

        self.geometry("800x600")

        self.auth: Authentification = auth
        self.auth_frame: Optional[AuthFrame] = None

        self.__frame_notebook = ttk.Notebook(self)

        self.__frame_auth = AuthFrame(auth)
        # self.__frame_auth.pack()
        self.__frame_auth.grid(row=0, column=0)

        self.__frame_notebook.grid(row=1, column=0)

        self.__frame_navigation = NavigationFrame(
            navigation, master=self.__frame_notebook
        )
        # self.__frame_navigation.pack()
        self.__frame_notebook.add(self.__frame_navigation, text="Navigation")
        # grid(row=0, column=0)

        self.__frame_transfert = TransferFrame(transfer_handler)
        self.__frame_notebook.add(self.__frame_transfert, text="Transferts")

        # Wiring du frame dans Authentification - permet changer affichage
        self.auth_frame = self.__frame_auth
        self.auth.auth_frame = self.__frame_auth
        navigation.nav_frame = self.__frame_navigation
        transfer_handler.transfer_frame = self.__frame_transfert


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="MilleGrilles Transfer Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--downdir",
        type=str,
        default=None,
        help="Download directory (overrides config)",
    )

    parser.add_argument(
        "--tmpdir", type=str, default=None, help="Temporary directory for processing"
    )

    return parser.parse_args()


def main():
    """Main entry point with argument parsing."""
    args = parse_arguments()

    # Create configuration from arguments or defaults
    config = Configuration.default()

    # Override with command-line arguments if provided
    if args.downdir:
        config.downdir = args.downdir
    if args.tmpdir:
        config.tmpdir = args.tmpdir

    logging.basicConfig(level=logging.ERROR)
    logging.getLogger("__main__").setLevel(logging.DEBUG)
    logging.getLogger("tksample1").setLevel(logging.DEBUG)

    App(config).exec()


if __name__ == "__main__":
    main()
