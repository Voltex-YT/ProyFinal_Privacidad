import os
from PIL import Image
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
MAX_DIMENSION = (512, 512)

def extension_valida(nombre_archivo):
    return "." in nombre_archivo and nombre_archivo.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitizar_y_guardar_avatar(file_storage, matricula, upload_dir):
    if not file_storage or not file_storage.filename:
        raise ValueError("No se recibio ningun archivo de imagen")

    if not extension_valida(file_storage.filename):
        raise ValueError("Formato de imagen no permitido (solo PNG, JPG, JPEG, WEBP)")

    matricula_segura = secure_filename(str(matricula).strip())
    if not matricula_segura:
        raise ValueError("Matricula invalida para nombrar el archivo")

    try:
        img_verificacion = Image.open(file_storage.stream)
        img_verificacion.verify()
    except Exception:
        raise ValueError("El archivo cargado no es una imagen valida o esta corrupto")

    file_storage.stream.seek(0)
    with Image.open(file_storage.stream) as img_original:
        img_rgb = img_original.convert("RGB")
        img_rgb.thumbnail(MAX_DIMENSION, Image.Resampling.LANCZOS)

        datos_pixeles = list(img_rgb.getdata())
        img_limpia = Image.new("RGB", img_rgb.size)
        img_limpia.putdata(datos_pixeles)

        os.makedirs(upload_dir, exist_ok=True)
        nombre_final = f"{matricula_segura}.jpg"
        ruta_destino = os.path.join(upload_dir, nombre_final)

        img_limpia.save(ruta_destino, format="JPEG", quality=88, optimize=True)

    return nombre_final
