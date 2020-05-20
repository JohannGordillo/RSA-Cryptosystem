#!/usr/bin/env python

from tkinter import *
from tkinter import filedialog as fd

class FileBrowser(object):
    """
    Clase para representar un manejador de archivos
    con interfaz gráfica.
    """
    def __init__(self, file_path=None):
        """Constructor para la clase."""
        self.__root = Tk()
        self.__file_path = file_path

    def search_path(self):
        """Despliega una ventana del manejador de archivos
        ubicada en la carpeta donde se encuentre el usuario
        para que éste seleccione el archivo .txt con
        el mensaje.

        Da al atributo privado file_path del objeto
        el path del archivo seleccionado por el usuario.
        """
        if self.__file_path == None:
            self.__root.withdraw()
            file_types = (("txt files", "*.txt"),)
            self.__file_path = fd.askopenfilename(\
                               title="Selecciona el archivo", \
                               filetypes=file_types)

    def get_path(self):
        """
        Regresa el path del archivo seleccionado por el usuario.
        """
        return self.__file_path
