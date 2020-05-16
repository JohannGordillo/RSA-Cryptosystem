#!/usr/bin/env python

"""
============================================================
>> Autor: Johann Gordillo
>> Email: jgordillo@ciencias.unam.mx
>> Fecha: 14/05/2020
============================================================
Implementación sencilla del Criptosistema de clave pública
de Rivest-Shamir-Adleman (RSA).

Nota:
Este programa fue diseñado únicamente con fines educativos
y no se recomienda su uso en seguridad informática.

Copyright (c) 2020 Johann Gordillo
============================================================
"""

from random import randrange, getrandbits
from math import gcd


# Alfabeto español de 26 letras.
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def generate_prime_number(bits=1024):
    """Genera un número primo aleatorio.

    >> Argumentos:
       bits --- int --- Número de bits.
    
    >> Regresa:
       Un número primo con la longitud en bits dada.
    """
    p = 0

    while not is_prime(p, 2):
        # Generamos bits aleatorios.
        p = getrandbits(bits)

        # Hacemos que el bit más significativo sea 1, para
        # asegurarnos de que el número de bits no cambie.
        # ---
        # Hacemos que el bit menos significativo sea 1,
        # para asegurarnos de que el número no sea par.
        p |= (1 << bits - 1) | 1

    return p


def is_prime(n, k):
    """Función que nos dice si un entero dado es un 
    número primo (probable) o no.

    Es una implementación de la prueba de primalidad 
    de Miller-Rabin.

    Se ha elegido esta implementación sobre la
    prueba de primalidad de Fermat, ya que en ésta 
    los números de Carmichael no son un problema.

    Más información en:
    https://en.wikipedia.org/wiki/Miller-Rabin_primality_test

    >> Argumentos:
       n -- int -- Numero a probar.
       k -- int -- Numero de pruebas a realizar.

    >> Regresa:
       True si 'n' es primo. False si no.
    """
    # 2 y 3 son los primeros primos positivos.
    if n == 2 or n == 3:
        return True

    # Verificamos que 'n' no sea par.
    if n <= 1 or n % 2 == 0:
        return False

    # Necesitamos encontrar 'r', 's' tales que:
    # (n - 1) = r * (2 ^ s), con 'r' impar.
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    
    # Realizaremos 'k' pruebas.
    for _ in range(k):
        # Elegimos un entero 'a' aleatorio en [2, n - 2].
        a = randrange(2, n - 1)

        # Calculamos b = (a ^ r) (mód n)
        #b = mod_exp(a, r, n)
        b = pow(a, r, n)

        # Si 'b' es congruente con +1 ó -1 (mód n), es problable primo.
        if b == 1 or b == n - 1:
            continue

        # De otra manera, elevamos b al cuadrado (mód n) mientras
        # el algoritmo no culmine con un caso en el que 'b' no sea primo.
        else:
            i = 1
            while i < s and b != n - 1:
                #b = mod_exp(b, 2, n)
                b = pow(b, 2, n)
                if b == 1:
                    return False
                i += 1
            if b != n - 1:
                return False
    
    # Si no falla ninguna de las pruebas, regresamos True.
    return True


def mod_multiplicative_inverse(n, m):
    """Devuelve el inverso multiplicativo de n modulo m.

    >> Argumentos:
       n --- int --- Un entero cualquiera.
       m --- int --- Un entero cualquiera.
    
    >> Regresa:
       El inverso de n en el anillo Zm.
    """
    n = n % m
    for x in range(1, m): 
        if ((n * x) % m == 1): 
            return x 
    return 1


def generate_keys(p, q):
    """Genera las claves pública y privada del algoritmo.

    >> Argumentos:
       p --- int --- Un número primo
       q --- int --- Un número primo.

    >> Regresa:
       Una tupla con las claves pública y privada.
    """
    n = p * q

    # Función phi de Euler aplicada a n.
    # Como p y q son primos, phi(n) = (p - 1) * (q - 1).
    phi = (p - 1) * (q - 1)

    # Obtenemos un entero 'e' coprimo con phi tal que:
    # 1 < e < phi.
    e = randrange(2, phi)
    while gcd(e, phi) != 1:
        e = randrange(3, phi)

    # Generamos una llave privada 'd' tal que:
    # (e * d) sea congruente con 1 (mód phi).
    d = mod_multiplicative_inverse(e, phi)

    public_key = (e, n)
    private_key = d

    return (public_key, private_key)


def encrypt(public_key, msg):
    """Funcion encrypt.

    >> Argumentos:
        public_key --- tuple[int] --- La clave pública.
        msg --- List[int] --- Una lista de enteros con
        el mensaje a cifrar.

    >> Regresa:
        ciphertext --- List[int] --- Una lista de numeros con el
        mensaje cifrado.
    """
    n, e = public_key 
    ciphertext = [pow(m, e, n) for m in msg]
    return ciphertext


def decrypt(ciphertext, keys):
    """Funcion Decrypt.

    >> Argumentos:
        ciphertext --- List[int] --- Una lista de numeros.
        d --- int --- La llave privada.
        n --- int --- El numero de entrada.

    >> Regresa:
        msg --- List[int] --- Una lista de numeros con el
        mensaje descifrado.
    """
    public_key, private_key = keys
    n, e = public_key 
    msg = [pow(c, private_key, n) % 26 for c in ciphertext]
    return msg


def numbers_to_text(nums):
    """Pasa una lista de numeros a una cadena
    de texto.

    >> Argumentos:
        nums --- Una lista de numeros.

    >> Regresa:
        text --- Una cadena de texto.
    """
    text = ''.join([alphabet[n % 26] for n in nums])
    return text
