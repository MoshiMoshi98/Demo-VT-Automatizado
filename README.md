# VT-Automatizado v1.0.0
## Verificador Automatizado de IOCs con VirusTotal | CIR Banxico

Herramienta web para verificacion masiva de Indicadores de Compromiso (IOCs) contra VirusTotal API v3.

## Instalacion

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuracion

Configurar variables de entorno:
```bash
export VT_API_KEY_1='tu_api_key_aqui'
export VT_API_KEY_2='tu_api_key_2_aqui'
export VT_API_KEY_3='tu_api_key_3_aqui'
```

## Uso

```bash
# Desarrollo
python3 app.py

# Produccion
gunicorn -w 2 -b 0.0.0.0:8000 app:app
```

## Capacidad
- 3 API keys x 500/dia = 1,500 consultas/dia
- 12 consultas/minuto
- 46,500 consultas/mes estimadas

## Stack
- Backend: Python 3 + Flask
- API: VirusTotal API v3
- Frontend: Bootstrap 5 + Chart.js
- Export: openpyxl
