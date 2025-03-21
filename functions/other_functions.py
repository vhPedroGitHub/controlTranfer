import os

def eliminar_archivos_en_directorio(directorio):
    try:
        for archivo in os.listdir(directorio):
            ruta_archivo = os.path.join(directorio, archivo)
            if os.path.isfile(ruta_archivo):
                os.remove(ruta_archivo)
        print(f"Todos los archivos en el directorio '{directorio}' han sido eliminados.")
    except Exception as e:
        print(f"Ocurrió un error: {e}")