import argparse
import socket

from glocrypto import *
from glosocket import *


def get_arguments() -> Tuple[bool, bool, int, Optional[str]]:
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
    modulo = trouver_nombre_premier()
    base = entier_aleatoire(modulo)

    strTuple = str(modulo) + "," + str(base)

    send_msg(destination, strTuple)

    return (modulo, base)


def fetch_mod_base(source: socket.socket) -> Tuple[int, int]:
    return recv_msg(source)


def generate_pub_prv_keys(modulo: int, base: int) -> Tuple[int, int]:
    cle_privee = entier_aleatoire(modulo)
    cle_publique = exponentiation_modulaire(base, cle_privee, modulo)

    return (cle_privee, cle_publique)


def exchange_keys(destination: socket.socket, cle_pub: int) -> Optional[int]:
    try:
        send_msg(destination, str(cle_pub))
        return recv_msg(destination)
    except Exception as err:
        print("Erreur lors de l'échange des clés : {0}".format(err))
        return None


def compute_shared_key(modulo: int, cle_prv: int, cle_pub: int) -> int:
    return exponentiation_modulaire(cle_pub, cle_prv, modulo)


def server(port: int, est_ipv6: bool) -> NoReturn:
    socket_serveur = make_server_socket(port, est_ipv6)

    while True:
        (socket_client, adresse_client) = socket_serveur.accept()
        print(
            "SERVEUR - Connection d'un client depuis l'adresse {}".format(
                adresse_client
            )
        )

        tupl = generate_mod_base(socket_client)
        modulo = int(tupl[0])
        base = int(tupl[1])
        print("SERVEUR - Données envoyé au client : {}".format(tupl))

        (cle_privee, cle_publique) = generate_pub_prv_keys(modulo, base)

        cle_publique_client = exchange_keys(socket_client, cle_publique)
        cle_partagee = compute_shared_key(
            modulo, int(cle_privee), int(cle_publique_client)
        )
        print("SERVEUR - Clé partagé généré : {}".format(cle_partagee))

        socket_client.close()


def client(destination: str, port: int, est_ipv6: bool) -> None:
    socket_client = make_client_socket(destination, port, est_ipv6)

    tupl = tuple(fetch_mod_base(socket_client).split(","))
    modulo = int(tupl[0])
    base = int(tupl[1])
    print("CLIENT - Reçu modulo et base : {}".format(tupl))

    (cle_privee, cle_publique) = generate_pub_prv_keys(modulo, base)

    cle_publique_serveur = int(recv_msg(socket_client))
    send_msg(socket_client, str(cle_publique))

    cle_partagee = compute_shared_key(modulo, cle_privee, cle_publique_serveur)
    print("CLIENT - Clé partagé généré : {}".format(cle_partagee))

    socket_client.close()


def main() -> None:
    est_ipv6, est_serveur, port, destination = get_arguments()
    if est_serveur:
        server(port, est_ipv6)
    else:
        client(destination, port, est_ipv6)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
