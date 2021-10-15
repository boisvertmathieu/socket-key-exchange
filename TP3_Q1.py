import argparse
import socket

from glocrypto import *
from glosocket import *


def get_arguments() -> Tuple[bool, bool, int, Optional[str]]:
    """
    Cette fonction doit :
    - ajouter les arguments attendus aux parser,
    - récupérer les arguments passés,
    - retourner un tuple contenant dans cet ordre :
        1. est-ce que le protocole est IPv6 ? (Booléen)
        2. est-ce que le mode est « écoute » ? (Booléen)
        3. le port choisi (entier)
        4. l’adresse du serveur (string si client, None si serveur)
    """
    parser = argparse.ArgumentParser()

    # Argument pour le protocol (ipv4 ou ipv6)
    parser.add_argument(
        "-6",
        dest="protocole",
        nargs="?",
        const="ipv6",
        default="ipv4",
        help="Ajouter cet argument pour utiliser le protocole ipv6",
    )

    parser.add_argument(
        "-l",
        "--listen",
        dest="mode",
        nargs="?",
        const="serveur",
        default="client",
        help="Ajouter cet argument pour démarrer l'application en mode serveur",
    )

    # Argument pour le numéro de port
    parser.add_argument(
        "-p",
        "--port",
        dest="port",
        type=int,
        action="store",
        default=11037,
        help="Choisir un port (par défaut: 11037)",
    )

    # Argument pour l'adresse du serveur
    parser.add_argument(
        "-d",
        "--destination",
        dest="adresse",
        action="store",
        help="Inscrire l'adresse du serveur",
    )

    args = parser.parse_args()
    if args.mode == "serveur":
        if args.adresse is not None:
            parser.error(
                "Aucune adresse ne doit être inscrite si le mode spécifié est 'écoute'"
            )
    else:
        if args.adresse is None:
            parser.error(
                "Une adresse doit être inscrite sur le mode spéficié est 'transmission'"
            )

    return args.protocole == "ipv6", args.mode == "serveur", args.port, args.adresse


def make_server_socket(port: int, est_ipv6: bool) -> socket.socket:
    """
    Cette fonction doit créer le socket du serveur, le lier au port
    et démarrer l’écoute.

    Si le port est invalide ou indisponible, le programme termine.
    """
    socket_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    socket_serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        socket_serveur.bind(("localhost", port))
    except socket.error:
        print(
            "Erreur lors de la connexion du socket à l'adresse {0}:{1}".format(
                "localhost", port
            )
        )
        return None

    socket_serveur.listen(5)
    print("Serveur écoute sur le port : {0}".format(port))

    return socket_serveur


def make_client_socket(destination: str, port: int, est_ipv6: bool) -> socket.socket:
    """
    Cette fonction doit créer le socket du client et le connecter au serveur.

    Si la connexion échoue, le programme termine.
    """
    adresse = (destination, port)

    socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        socket_client.connect(adresse)
    except socket.error:
        print(
            "Erreur lors de la connection du socket du client à l'adresse {0}:{1}".format(
                destination, port
            )
        )
        return None

    print("Client connecté à l'adresse : {0}".format(destination))

    return socket_client


def generate_mod_base(destination: socket.socket) -> Optional[Tuple[int, int]]:
    """
    Cette fonction doit :
    - à l’aide du module glocrypto, générer le modulo et la base,
    - à l’aide du module glosocket, transmettre à la destination
    deux messages contenant respectivement :
        1. le modulo
        2. la base
    - retourner un tuple contenant les deux valeurs dans ce même ordre.
    """
    modulo = trouver_nombre_premier()
    base = entier_aleatoire(modulo)

    send_msg(destination, "%s, %s".format(str(modulo), str(base)))

    return (modulo, base)


def fetch_mod_base(source: socket.socket) -> Tuple[int, int]:
    """
    Cette fonction doit :
    - à l’aide du module glosocket, recevoir depuis la source
    deux messages contenant respectivement :
        1. le modulo
        2. la base
    - retourner un tuple contenant les deux valeurs dans ce même ordre.

    Si l’une des réceptions échoue, le programme termine.
    """

    return recv_msg(source)


def generate_pub_prv_keys(modulo: int, base: int) -> Tuple[int, int]:
    """
    Cette fonction doit :
    - à l’aide du module glocrypto, générer une clé privée,
    - à l’aide du module glocrypto, générer une clé publique,
    - retourner un tuple contenant respectivement :
        1. la clé privée
        2. la clé publique
    """
    cle_privee = entier_aleatoire(modulo)
    cle_publique = exponentiation_modulaire(base, cle_privee, modulo)

    return (cle_privee, cle_publique)


def exchange_keys(destination: socket.socket, cle_pub: int) -> Optional[int]:
    """
    Cette fonction doit respectivement :
    1. à l’aide du module glosocket, envoyer sa clé publique à la destination,
    2. à l’aide du module glosocket, recevoir la clé publique de la destination

    Si l’envoi ou la réception échoue, la fonction retourne None.
    """

    try:
        send_msg(destination, cle_pub)
        return recv_msg(destination)
    except Exception as err:
        print("Erreur lors de l'échange des clés : {0}".format(err))
        return None


def compute_shared_key(modulo: int, cle_prv: int, cle_pub: int) -> int:
    """
    Cette fonction doit, à l’aide du module glocrypto, déduire la clé partagée.
    """

    return exponentiation_modulaire(cle_pub, cle_prv, modulo)


def server(port: int, est_ipv6: bool) -> NoReturn:
    """
    Cette fonction constitue le point d’entrée et la boucle principale du serveur.

    Si la connexion à un client est interrompue, le serveur abandonne ce client
    et en attend un nouveau.
    """
    socket_serveur = make_server_socket(port, est_ipv6)

    (socket_client, adresse_client) = socket_serveur.accept()
    print("SERVEUR - Connection d'un client depuis l'adresse {}".format(adresse_client))

    while True:
        generate_mod_base(socket_client)
        print(recv_msg(socket_client))


def client(destination: str, port: int, est_ipv6: bool) -> None:
    """
    Cette fonction constitue le point d’entrée et la boucle principale du client.

    Si la connexion au serveur est interrompue, le client termine.
    """
    socket_client = make_client_socket(destination, port, est_ipv6)

    (modulo, base) = fetch_mod_base(destination)
    print("CLIENT - Reçu modulo et base : {}, {}".format(modulo, base))

    send_msg(socket_client, "Merci. -client")

    print(recv_msg(socket_client))


def main() -> None:
    est_ipv6, est_serveur, port, destination = get_arguments()
    if est_serveur:
        server(port, est_ipv6)
    else:
        client(destination, port, est_ipv6)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
