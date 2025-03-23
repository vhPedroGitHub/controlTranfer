import os
import shutil

def eliminar_contenido_en_directorio(directorio):
    try:
        for elemento in os.listdir(directorio):
            ruta_elemento = os.path.join(directorio, elemento)
            
            if os.path.isfile(ruta_elemento):
                os.remove(ruta_elemento)
            elif os.path.isdir(ruta_elemento):
                try:
                    os.rmdir(ruta_elemento)  # Elimina carpetas vacías
                except OSError:
                    shutil.rmtree(ruta_elemento)  # Elimina carpetas con contenido
        print(f"Todos los archivos y carpetas en el directorio '{directorio}' han sido eliminados.")
    except Exception as e:
        print(f"Ocurrió un error: {e}")