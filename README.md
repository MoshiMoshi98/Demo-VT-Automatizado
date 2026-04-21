# Demo VT-Automatizado

Verificador automatizado de IOCs (Indicators of Compromise) usando la API de VirusTotal.

## Características

-  Verificación de hashes (MD5, SHA1, SHA256), IPs y dominios
-  Rate limiting automático (4 consultas/min - plan gratuito VT)
-  Cache de resultados en SQLite
-  Dashboard con gráficas interactivas
-  Exportación a Excel con estadísticas y links

## Instalación Local

```bash
pip install -r requirements.txt
export VT_API_KEY="tu-api-key-de-virustotal"
python app.py
```

## Despliegue en PythonAnywhere

1. Crear cuenta en pythonanywhere.com
2. Ir a "Web" > "Add a new web app" > Flask
3. Subir archivos o clonar desde GitHub
4. En "WSGI configuration file" agregar:
```python
   import sys
   path = '/home/TU_USUARIO/Demo-VT-Automatizado'
   if path not in sys.path:
       sys.path.append(path)
   from app import app as application
```
5. En "Virtualenv" instalar dependencias
6. En "Environment variables" agregar `VT_API_KEY`

## Obtener API Key de VirusTotal

1. Crear cuenta en virustotal.com
2. Ir a tu perfil > API Key
3. Copiar la key (plan gratuito: 4 consultas/minuto)

