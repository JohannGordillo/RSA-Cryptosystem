#!/usr/bin/env python

"""
============================================================
>> Autor: Johann Gordillo
>> Email: jgordillo@ciencias.unam.mx
>> Fecha: 20/05/2020
============================================================
Implementación sencilla del Criptosistema de clave pública
de Rivest-Shamir-Adleman (RSA).

Nota:
Este programa fue diseñado únicamente con fines educativos
y no se recomienda su uso en seguridad informática.

Copyright (c) 2020 Johann Gordillo
============================================================
"""

from random import randrange, randint, getrandbits
from math import gcd


def generate_prime_number(min_length=50, max_length=70):
    """Genera un número primo aleatorio.

    >> Argumentos:
       length -- int -- Número de dígitos.
    
    >> Regresa:
       Un número primo con la cantidad de dígitos
       indicada.
    """
    if max_length < min_length:
        raise ValueError("La longitud máxima de dígitos es menor que la mínima.")
    
    p = 0

    while not is_prime(p, 2):
        # Generamos un entero aleatorio.
        p = randint(pow(10, min_length - 1), pow(10, max_length) - 1)

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
        b = pow(a, r, n)

        # Si 'b' es congruente con +1 ó -1 (mód n), es problable primo.
        if b == 1 or b == n - 1:
            continue

        # De otra manera, elevamos b al cuadrado (mód n) mientras
        # el algoritmo no culmine con un caso en el que 'b' no sea primo.
        else:
            i = 1
            while i < s and b != n - 1:
                b = pow(b, 2, n)
                if b == 1:
                    return False
                i += 1
            if b != n - 1:
                return False
    
    # Si no falla ninguna de las pruebas, regresamos True.
    return True


def extended_gcd(n, m):
    """Implementación del Algoritmo de Euclides Extendido.

    >> Argumentos:
        a --- int --- Un entero cualquiera.
        b --- int --- Un entero cualquiera.

    >> Regresa:
        Una tupla (g, s, t) donde g es el máximo común divisor
        de 'n' y 'm', y se tiene que g = ns + mt.
    """
    if n == 0 :   
        return (m, 0, 1)
             
    g, s1, t1 = extended_gcd(m % n, n)  
     
    s = t1 - (m // n) * s1  
    t = s1  
     
    return (g, s, t) 


def mod_multiplicative_inverse(n, m):
    """Devuelve el inverso multiplicativo de n modulo m.
    Se da por hecho que n es invertible en Zm.

    >> Argumentos:
       n --- int --- Un entero invertible en Zm.
       m --- int --- Un entero cualquiera.
    
    >> Regresa:
       El inverso de n en el anillo Zm.
    """
    # Se tiene que gcd(n, m) = ns + mt
    g, s, _ = extended_gcd(n, m)
    inverse = s % m
    return inverse


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

    public_key = (n, e)
    private_key = d

    return (public_key, private_key)


def encrypt(public_key, msg):
    """Funcion encrypt.

    >> Argumentos:
        public_key --- tuple[int] --- La clave pública.
        msg --- string --- Una cadena con el mensaje.

    >> Regresa:
        ciphertext --- string --- Una cadena con el mensaje
        cifrado.
    """
    n, e = public_key
    ciphertext = [pow(m, e, n) for m in text_to_numbers(msg)]
    return ciphertext


def decrypt(ciphertext, keys):
    """Funcion Decrypt.

    >> Argumentos:
        ciphertext --- string --- Una cadena.
        d --- int --- La llave privada.
        n --- int --- El numero de entrada.

    >> Regresa:
        msg --- string --- Una cadena con el
        mensaje descifrado.
    """
    public_key, private_key = keys
    n, e = public_key 
    msg = [pow(c, private_key, n) for c in ciphertext]
    return numbers_to_text(msg)


def numbers_to_text(nums):
    """Pasa una lista de numeros a una cadena
    de texto.

    >> Argumentos:
        nums --- Una lista de numeros.

    >> Regresa:
        text --- Una cadena de texto.
    """
    text = ''.join([chr(n) for n in nums])
    return text


def text_to_numbers(text):
    """Pasa una lista de caracteres a una lista
    de números enteros.

    >> Argumentos:
        nums --- Una lista de carácteres.

    >> Regresa:
        text --- Una lista de enteros.
    """
    nums = [ord(c) for c in text]
    return nums
