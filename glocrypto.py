"""\
Module fournissant les fonctions cryptographiques pour le TP3

Attention : en cryptographie, les nombres doivent être impossibles à deviner, 
ce qui n’est pas le cas ici. N’utilisez pas ce module dans un projet réel !
"""
import random

# Nombre de bits des nombres premiers générés.
# Plus ce nombre est grand, plus le protocole est securitaire, mais plus les operations sont lentes.
# Dans le cadre ce TP on utilisera toujours 128 bits.
_nb_bits = 128


def entier_aleatoire(modulo: int) -> int:
    """ 
    Génère un entier aléatoire entre 0 (inclus) et modulo (exclus)
    """
    return random.randrange(modulo)


def _est_probablement_premier(n: int) -> bool:
    """ 
    Fonction utilitaire pour trouver_nombre_premier.

    Vérifie si n est premier avec le test de Fermat.
    """
    if n in [0, 1]:
        return False
    elif n in [2, 3]:
        return True
    else:
        a = random.randint(2, n-2)
        return pow(a, n-1, n) == 1


def trouver_nombre_premier() -> int:
    """ 
    Trouve un nombre premier sur nb_bits
    """
    n = 0
    while not _est_probablement_premier(n):
        n = random.getrandbits(_nb_bits)
    return n


def exponentiation_modulaire(base: int, exposant: int, modulo: int) -> int:
    """ 
    Calcule (base^exposant) mod modulo
    """
    if modulo == 1:
        return 0
    resultat = 1
    base = base % modulo
    while exposant > 0:
        if exposant % 2 == 1:
            resultat = (resultat * base) % modulo
        exposant = exposant >> 1
        base = (base ** 2) % modulo
    return resultat
