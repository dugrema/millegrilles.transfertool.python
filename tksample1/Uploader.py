import logging
import requests
import tkinter as tk

from threading import Event, Thread
from typing import Optional
from urllib import parse


class UploadItem:

    def __init__(self, upload_info):
        self.__info = upload_info


class Uploader:

    def __init__(self, stop_event, connexion):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event
        self.__connexion = connexion

        self.__upload_queue = list()
        self.__upload_pret = Event()
        self.__url_upload: Optional[parse.ParseResult] = None

        self.__https_session: Optional[requests.Session] = None

        self.__navigation = None

        self.__thread = Thread(name="uploader", target=self.upload_thread)
        self.__thread.start()

    def set_navigation(self, navigation):
        self.__navigation = navigation

    def quit(self):
        self.__upload_pret.set()

    def set_url_download(self, url_upload: parse.ParseResult):
        self.__url_upload = url_upload

    def ajouter_upload(self, upload) -> UploadItem:
        upload_item = UploadItem(upload)
        self.__upload_queue.append(upload_item)
        self.__upload_pret.set()
        return upload_item

    def upload_thread(self):
        while self.__stop_event.is_set() is False:
            self.__upload_pret.wait()
            self.__upload_pret.clear()

            while True:
                try:
                    upload = self.__upload_queue.pop(0)
                except IndexError:
                    break
                else:
                    if self.__stop_event.is_set():
                        return  # Stopping
                    self.upload(upload)

    def upload(self, upload: UploadItem):
        raise NotImplementedError('todo')


class UploaderFrame(tk.Frame):

    def __init__(self, stop_event, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event
