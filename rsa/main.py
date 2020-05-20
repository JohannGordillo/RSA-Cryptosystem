#!/usr/bin/env python

from rsa.gui import FileBrowser
from rsa import rsa 

import platform
import os


# Genera un marco de símbolos "=".
genera_marco = (lambda: print("=" * 80))

# Operación para limpiar la consola.
if platform.system() == "Windows":
    clear_op = "cls"
else:
    clear_op = "clear"
clean_console = (lambda: os.system(clear_op))


def select_file():
    """Permite al usuario seleccionar un archivo
    con ayuda de una interfaz gráfica.

    >> Argumentos:
       Ninguno.

    >> Regresa:
       La ruta del archivo.
    """
    fb = FileBrowser()
    fb.search_path()
    return fb.get_path()


def print_menu():
    """Imprime el menú de selección."""
    clean_console()
    genera_marco()
    print("Menú de Selección".center(80, ' '))
    genera_marco()
    print("1) Cifrar un mensaje.\n")
    print("2) Descifrar un mensaje.\n")
    print("3) Salir.")
    genera_marco()


def main():
    """Funcion principal del programa."""
    while True:
        print_menu()
        op = int(input("\nSeleccione una opcion: "))

        # Cifrado.
        if op == 1:
            # Permitimos al usuario seleccionar el archivo.
            src = select_file()

            # Leemos el archivo.
            with open(src) as f:
                msg = f.read()

            # Generamos dos primos aleatorios distintos de entre 50 y 60 dígitos.
            p = rsa.generate_prime_number(50, 60)
            q = p
            while q == p:
                q = rsa.generate_prime_number(50, 60)

            public_key, private_key = rsa.generate_keys(p, q)

            ciphertext = ' '.join([str(c) for c in rsa.encrypt(public_key, msg)])

            print(f"Su llave pública es: {public_key}\nSu llave privada es: {private_key}")

            with open("salida.txt","w+") as out:
                for c in ciphertext:
                    out.write(c)

            input("\nPresione <ENTER> para continuar... ")
            clean_console()
        
        # Descifrado.
        elif op == 2:
            # Permitimos al usuario seleccionar el archivo.
            src = select_file()

            # Leemos el archivo.
            with open(src) as f:
                text = f.read()

            # Obtenemos la llave pública.
            print(">> Ingrese la llave pública [n, e] (ejemplo: 567 785): ")
            n, e =  map(int, input().split())
            public_key = (n, e)

            # Obtenemos la llave privada.
            print("\n>> Ingrese la llave privada: ")
            private_key = int(input())

            keys = (public_key, private_key)

            ciphertext = [int(c) for c in text.split()] 

            # Obtenemos el mensaje descifrado como una lista de números.
            msg = rsa.decrypt(ciphertext, keys)

            print(f"\nSu texto descifrado es:\n{msg}")

            input("\nPresione <ENTER> para continuar... ")
            clean_console()

        # Salir del programa.
        elif op == 3:
            clean_console()
            print("Hasta luego! Gracias por utilizar el programa :D")
            break
        
        # Opción inválida.
        else:
            print("Opción no válida.")
            input("\nPresione <ENTER> para continuar... ")
            clean_console()
