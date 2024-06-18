import asyncio
import binascii
import requests
import logging
import json
import os

from urllib import parse
from typing import Optional, Union

from threading import Thread, Event, Lock
import tkinter as tk

import socketio

from millegrilles_messages.messages import Constantes
from millegrilles_messages.certificats.Generes import CleCsrGenere
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages.FormatteurMessages import SignateurTransactionSimple, FormatteurMessageMilleGrilles
from millegrilles_messages.messages.ValidateurCertificats import ValidateurCertificatCache
from millegrilles_messages.messages.ValidateurMessage import ValidateurMessage


class Authentification:

    def __init__(self, stop_event: Event):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event

        self.thread = Thread(name="Authentification", target=self.run)
        self.__pret = Event()
        self.__entretien_event = Event()

        self.nom_usager = None
        self.url_fiche_serveur = None
        self.__cle_csr_genere: Optional[CleCsrGenere] = None
        self.__sio: Optional[socketio.Client] = None

        # Certificat + cle de l'usager active
        self._cle_certificat: Optional[CleCertificat] = None

        self.thread.start()
        self.__url_collection: Optional[parse.ParseResult] = None

        self.__path_cert = '/tmp/usager.cert'
        self.__path_cle = '/tmp/usager.cle'
        self.__path_ca = '/tmp/usager.ca'
        self.__path_config = '/tmp/config.json'

        self.__formatteur: Optional[FormatteurMessageMilleGrilles] = None
        self.__validateur: Optional[ValidateurMessage] = None

        self.auth_frame = None

        self.__lock_emit = Lock()

    @property
    def formatteur(self):
        return self.__formatteur

    @property
    def validateur(self):
        return self.__validateur

    def emit(self, *args, **kwargs):
        with self.__lock_emit:
            return self.__sio.emit(*args, **kwargs)

    def call(self, *args, **kwargs):
        with self.__lock_emit:
            return self.__sio.call(*args, **kwargs)

    def init_config(self):
        if self.charger_configuration():
            self.auth_frame.entry_nomusager.insert(0, self.nom_usager)
            serveur_url = self.url_fiche_serveur.hostname
            self.auth_frame.entry_serveur.insert(0, serveur_url)
            self.auth_frame.btn_connecter_usager()

    def charger_configuration(self):
        # Verifier si on a deja une connexion de configuree
        try:
            with open(self.__path_config, 'rt') as fichier:
                config = json.load(fichier)
        except FileNotFoundError:
            # Aucune configuration presente
            return False

        nom_usager = config['nom_usager']
        url_fiche_serveur = config['url_fiche_serveur']

        self.nom_usager = nom_usager
        self.url_fiche_serveur = parse.urlparse(url_fiche_serveur)

        return True

    def sauvegarder_configuration(self):
        config = {
            'nom_usager': self.nom_usager,
            'url_fiche_serveur': self.url_fiche_serveur.geturl()
        }
        with open(self.__path_config, 'wt') as fichier:
            json.dump(config, fichier)

    def effacer_usager(self):
        self.nom_usager = None
        self.url_fiche_serveur = None
        self.__formatteur = None
        self.__validateur = None
        self.__cle_csr_genere = None
        self._cle_certificat = None

        fichiers = [self.__path_cle, self.__path_cert, self.__path_ca, self.__path_config]
        for fichier in fichiers:
            try:
                os.unlink(fichier)
            except FileNotFoundError:
                pass

        self.deconnecter()

    def authentifier(self, nom_usager=None, url_serveur=None):
        nom_usager = nom_usager or self.nom_usager
        url_serveur = url_serveur or self.url_fiche_serveur

        if nom_usager is None or url_serveur is None:
            raise ValueError('Il faut fournir nom_usager et url_serveur')

        self.__logger.info("Charger usager %s avec url %s" % (nom_usager, url_serveur))
        if self.__pret.is_set():
            raise Exception('Auth en cours ou deja authentifie')

        # Preparer URL de la fiche
        url_parsed = parse.urlparse(url_serveur, scheme="https")
        if url_parsed.hostname is None:
            url_parsed = parse.urlparse(f'https://{url_parsed.path}/fiche.json')
        elif url_parsed.path != '/fiche.json':
            url_parsed = parse.urlparse(f'https://{url_parsed.hostname}/fiche.json')

        self.url_fiche_serveur = url_parsed

        self.nom_usager = nom_usager

        # Verifier si on a deja le certificat pour cet usager
        try:
            cle_certificat = CleCertificat.from_files(self.__path_cle, self.__path_cert)
            if cle_certificat.cle_correspondent():
                common_name = cle_certificat.enveloppe.subject_common_name
                if common_name == nom_usager:
                    if cle_certificat.enveloppe.calculer_expiration()['expire'] is False:

                        # Verifier que l'instance du certificat correspond au systeme (meme IDMG)
                        url_fiche = self.url_fiche_serveur.geturl()
                        reponse = requests.get(url_fiche)
                        reponse_json = reponse.json()
                        contenu = json.loads(reponse_json['contenu'])
                        idmg = cle_certificat.enveloppe.idmg
                        if contenu['idmg'] == idmg:
                            self.__logger.debug("On a un certificat valide pour l'usager %s sur la MilleGrille %s" % (nom_usager, idmg))
                            self._cle_certificat = cle_certificat
                            self.__pret.set()
                            return

        except FileNotFoundError:
            pass  # Certificat n'existe pas

        # Generer un nouveau CSR et emettre vers le serveur
        self.__cle_csr_genere = generer_csr(self.nom_usager)

        self.__pret.set()

    def deconnecter(self):
        if self.__sio:
            self.__sio.disconnect()
            self.__sio = None
        self.auth_frame.set_etat(False)

    def quit(self):
        self.__entretien_event.set()
        if self.__pret.is_set() is False:
            self.__pret.set()
        self.deconnecter()

    def run(self):
        self.__logger.info("Debut thread authentification")
        try:
            while self.__stop_event.is_set() is False:
                self.__pret.wait()
                if self.__stop_event.is_set():
                    return

                urls_collection = self.parse_fiche()
                for url_collection in urls_collection:
                    try:
                        self.connecter(url_collection)
                        break
                    except Exception as e:
                        self.__logger.exception("Echec authentification, essayer prochain serveur")
                        if self.__sio:
                            self.__sio.disconnect()
                        self.__sio = None
                        self.auth_frame.set_etat(False)

                if self.__sio is not None:
                    self.__sio.wait()  # Attendre la fin de la connexion

                # Cleanup pour prochaine authentification
                self.url_fiche_serveur = None
                self.__pret.clear()
        finally:
            self.__logger.info("Fin thread authentification")
            if self.__pret.is_set() is True and self.__stop_event.is_set() is False:
                self.__stop_event.set()
                raise Exception('Authentification thread crash')

    def parse_fiche(self) -> Union[list, parse.ParseResult]:
        url_fiche = self.url_fiche_serveur.geturl()
        reponse = requests.get(url_fiche)
        reponse_json = reponse.json()
        contenu = json.loads(reponse_json['contenu'])

        instances = contenu['instances']
        applcations_v2 = contenu['applicationsV2']

        collections = applcations_v2['collections']
        instances_collection = list()
        for instance_id, app_instance in collections['instances'].items():
            app_path = app_instance['pathname']
            instance = instances[instance_id]
            port_https = instance['ports']['https']
            for domaine_instance in instance['domaines']:
                url_app = parse.urlparse(f'https://{domaine_instance}:{port_https}{app_path}')
                instances_collection.append(url_app)

                if self.url_fiche_serveur.hostname == domaine_instance:
                    return [url_app]

        return instances_collection

    def connecter(self, url: parse.ParseResult):
        self.__url_collection = url

        if self._cle_certificat is None:
            self.socketio_requete_certificat(url)

        self.connecter_socketio()

    def socketio_requete_certificat(self, url: parse.ParseResult):
        connexion_socketio = f'https://{url.hostname}'

        sio = socketio.Client()
        sio.connect(connexion_socketio, socketio_path='/millegrilles/socket.io')
        try:
            # Emettre CSR et attendre activation
            csr_pem = self.__cle_csr_genere.get_pem_csr()
            cle_publique = binascii.hexlify(self.__cle_csr_genere.cle_publique).decode('utf-8')
            code_activation = cle_publique[-8:]
            code_activation_ecran = '-'.join([code_activation[0:4], code_activation[4:]])
            self.__logger.debug("Demande enregistrement usager %s avec code %s" % (self.nom_usager, code_activation_ecran))
            self.auth_frame.set_etat(code_activation=code_activation_ecran)

            commande_ajouter_csr = {'nomUsager': self.nom_usager, 'csr': csr_pem}
            sio.emit('ecouterEvenementsActivationFingerprint', {'fingerprintPk': cle_publique}, callback=self.callback_activation)
            sio.emit('ajouterCsrRecovery', commande_ajouter_csr, callback=self.callback_csr)

            event_certificat = Event()

            @sio.on('*')
            def message(event, data):
                self.__logger.debug('message socket.io : %s\n%s' % (event, data))
                action = event.split('.')[-1]
                if action == 'activationFingerprintPk':
                    self.recevoir_certificat(data)
                    event_certificat.set()

            # self.__sio.wait()  # Attendre la deconnection - indique qu'on a recu le certificat
            if event_certificat.wait(timeout=300) is False:
                raise TimeoutError()

        except Exception as e:
            sio.disconnect()
            self.auth_frame.set_etat(False)
            raise e

    def recevoir_certificat(self, data):
        message = data['message']
        contenu = json.loads(message['contenu'])
        certificat = contenu['certificat']
        ca = certificat[-1]
        cle_pem = self.__cle_csr_genere.get_pem_cle()
        certificat = '\n'.join(certificat[0:2])

        # Sauvegarder le nouvel usager/url serveur
        self.sauvegarder_configuration()

        # Sauvegarder certificats
        with open(self.__path_cert, 'wt') as fichier:
            fichier.write(certificat)
        with open(self.__path_cle, 'wt') as fichier:
            fichier.write(cle_pem)
        with open(self.__path_ca, 'wt') as fichier:
            fichier.write(ca)

        clecertificat = CleCertificat.from_pems(cle_pem, certificat)
        if clecertificat.cle_correspondent() is False:
            raise Exception('erreur cle/certificat ne correspondent pas')

        self._cle_certificat = clecertificat

    def callback_csr(self, *args):
        pass

    def callback_activation(self, *args):
        pass

    def entretien_authentification(self):
        self.__entretien_event.clear()
        while self.__entretien_event.is_set() is False:

            try:
                self.__entretien_event.wait(timeout=30)
            except TimeoutError:
                pass

    def connecter_socketio(self):
        # Reconnecter socketio par https avec client ssl
        url = self.__url_collection
        connexion_socketio = f'https://{url.hostname}:444'

        http_session = requests.Session()
        http_session.verify = self.__path_ca
        http_session.cert = (self.__path_cert, self.__path_cle)

        sio = socketio.Client(http_session=http_session)

        path_app = f'{url.path}/socket.io'
        self.__logger.debug("Connecter socket.io %s path %s" % (connexion_socketio, path_app))
        sio.connect(connexion_socketio, socketio_path=path_app)

        self.__sio = sio

        # Initialiser le formatteur de message pour signer authentification
        self.initialiser_formatteur()

        # Recuperer un challenge d'authentification a signer avec le certificat
        reponse_generer = sio.call('genererChallengeCertificat')
        self.__logger.debug("Reponse generer : %s" % reponse_generer)

        # Effectuer authentification via socket.io
        requete_upgrade = reponse_generer['challengeCertificat']
        requete_upgrade, message_id = self.__formatteur.signer_message(
            Constantes.KIND_COMMANDE, requete_upgrade, 'login', True, 'login')
        self.__logger.debug("Upgrade auth socket.io")
        reponse_upgrade = sio.call('upgrade', requete_upgrade)

        # Verifier reponse
        self.__logger.debug("Connecte, upgrade OK. Data:\n%s" % reponse_upgrade)
        enveloppe = asyncio.run(self.__validateur.verifier(reponse_upgrade))
        if 'collections' not in enveloppe.get_roles or Constantes.SECURITE_PRIVE not in enveloppe.get_exchanges:
            raise Exception(
                "Erreur upgrade socket.io : mauvais role/securite cote serveur. Roles: %s, securite: %s" % (
                    enveloppe.get_roles, enveloppe.get_exchanges))

        contenu = json.loads(reponse_upgrade['contenu'])
        if contenu.get('ok') is not True:
            self.__logger.error("Erreur upgrade socket.io : %s" % reponse_upgrade.get('err'))
            raise Exception('Erreur auth connexion socket.io')

        # Authentification reussie
        self.auth_frame.set_etat(connecte=True)
        self.__logger.debug("Upgrade auth socket.io OK")

    def initialiser_formatteur(self):
        clecert = self._cle_certificat
        enveloppe = clecert.enveloppe
        idmg = enveloppe.idmg

        ca = EnveloppeCertificat.from_file(self.__path_ca)

        signateur = SignateurTransactionSimple(clecert)
        formatteur = FormatteurMessageMilleGrilles(idmg, signateur, ca)
        self.__formatteur = formatteur

        validateur_certificats = ValidateurCertificatCache(ca)
        self.__validateur = ValidateurMessage(validateur_certificats)

    # def authentifier_session_web(self):
    #     # Dans maitre des comptes, authentifier.js (69)
    #     url_collection = self.__url_collection
    #
    #     fingerprint_pk = self._cle_certificat.fingerprint
    #     data_get_usager = {
    #         'nomUsager': self.nom_usager,
    #         'hostname': url_collection.hostname,
    #         'fingerprintPkCourant': fingerprint_pk,
    #         'genererChallenge': True,
    #     }
    #     url_get_usager = f'https://{url_collection.hostname}:{url_collection.port}/auth/get_usager'
    #     reponse_get_usager = requests.post(url_get_usager, json=data_get_usager)
    #     reponse_json = reponse_get_usager.json()
    #     challenges = json.loads(reponse_json['contenu'])
    #
    #     url_auth = f'https://{url_collection.hostname}:{url_collection.port}/auth/authentifier_usager'
    #     data_authentification = {
    #         # certificate_challenge: challengeCertificat, activation: true, dureeSession
    #         'certificate_challenge': challenges['challenge_certificat'],
    #         'activation': True,
    #         'dureeSession': 86_400 * 31,
    #         # 'nomUsager': self.nom_usager,
    #     }
    #     reponse = requests.post(url_auth, json=data_authentification)


def generer_csr(nom_usager: str) -> CleCsrGenere:
    return CleCsrGenere.build(nom_usager)


class AuthFrame(tk.Frame):

    def __init__(self, auth, *args, **kwargs):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        super().__init__(*args, **kwargs)
        self.auth = auth
        self.label_nomusager = tk.Label(master=self, text="Nom usager")
        self.entry_nomusager = tk.Entry(master=self, width=20)
        self.label_url_serveur = tk.Label(master=self, text="URL serveur")
        self.entry_serveur = tk.Entry(master=self, width=60)
        self.button_connecter = tk.Button(master=self, text="Connecter", command=self.btn_connecter_usager)
        self.button_deconnecter = tk.Button(master=self, text="Deconnecter",
                                            command=self.btn_deconnecter_usager)

        self.etat = tk.StringVar(master=self, value='Deconnecte')
        self.__etat_label = tk.Label(master=self, textvariable=self.etat)

    def pack(self):
        self.label_nomusager.pack()
        self.entry_nomusager.pack()
        self.label_url_serveur.pack()
        self.entry_serveur.pack()
        self.button_connecter.pack()
        self.button_deconnecter.pack()
        self.__etat_label.pack()
        super().pack()

    def set_etat(self, connecte=False, code_activation=None):
        if code_activation:
            self.etat.set('Code activation : %s' % code_activation)
            return

        if connecte:
            self.etat.set('Connecte')
        else:
            self.etat.set('Deconnecte')

    def btn_connecter_usager(self):
        nom_usager = self.entry_nomusager.get()
        valeur_url = self.entry_serveur.get()
        self.auth.authentifier(nom_usager, valeur_url)
        self.set_etat(connecte=True)

    def btn_deconnecter_usager(self):
        self.auth.effacer_usager()
        self.auth.deconnecter()
        self.set_etat(connecte=False)
        self.__logger.info("Usager deconnecte, configuration supprimee")

