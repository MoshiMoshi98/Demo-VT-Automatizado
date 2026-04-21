"""
Demo VT-Automatizado - Verificador de IOCs con VirusTotal
CIR Banxico - Dirección de Ciberseguridad
"""
from flask import Flask, render_template, request, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from collections import Counter
import requests
import os
import re
from io import BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///vt_cache.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# API Key de VirusTotal (configurar en variables de entorno)
VT_API_KEY = os.environ.get('VT_API_KEY', '')

# Rate limiting
request_times = []

# ============ MODELO ============
class VTCache(db.Model):
    __tablename__ = 'vt_cache'
    id = db.Column(db.Integer, primary_key=True)
    ioc_type = db.Column(db.String(20))
    ioc_value = db.Column(db.String(500), unique=True, index=True)
    malicious = db.Column(db.Integer)
    total = db.Column(db.Integer)
    threat_label = db.Column(db.String(200))
    categories = db.Column(db.String(500))
    comment = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')
    scanned_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ============ SERVICIOS VT ============
def detect_ioc_type(value):
    value = value.strip().lower()
    if re.match(r'^[a-f0-9]{64}$', value):
        return 'sha256'
    elif re.match(r'^[a-f0-9]{32}$', value):
        return 'md5'
    elif re.match(r'^[a-f0-9]{40}$', value):
        return 'sha1'
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
        return 'ip'
    elif '.' in value and not value.startswith('http'):
        return 'domain'
    return 'unknown'

def check_rate_limit():
    global request_times
    now = datetime.now()
    cutoff = now - timedelta(minutes=1)
    request_times = [t for t in request_times if t > cutoff]
    if len(request_times) >= 4:
        oldest = min(request_times)
        return (oldest + timedelta(minutes=1) - now).total_seconds()
    return 0

def query_virustotal(ioc_value, ioc_type):
    global request_times
    if not VT_API_KEY:
        return None, "API key no configurada"
    
    headers = {'x-apikey': VT_API_KEY}
    
    try:
        if ioc_type in ['md5', 'sha1', 'sha256']:
            url = f'https://www.virustotal.com/api/v3/files/{ioc_value}'
        elif ioc_type == 'ip':
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}'
        elif ioc_type == 'domain':
            url = f'https://www.virustotal.com/api/v3/domains/{ioc_value}'
        else:
            return None, "Tipo no soportado"
        
        request_times.append(datetime.now())
        resp = requests.get(url, headers=headers, timeout=30)
        
        if resp.status_code == 404:
            return None, "not_found"
        elif resp.status_code != 200:
            return None, f"Error {resp.status_code}"
        
        data = resp.json().get('data', {}).get('attributes', {})
        stats = data.get('last_analysis_stats', {})
        
        result = {
            'malicious': stats.get('malicious', 0),
            'total': sum(stats.values()),
            'threat_label': '',
            'categories': ''
        }
        
        # Extraer threat label
        if ioc_type in ['md5', 'sha1', 'sha256']:
            result['threat_label'] = data.get('popular_threat_classification', {}).get('suggested_threat_label', '')
            cats = data.get('popular_threat_classification', {}).get('popular_threat_category', [])
            result['categories'] = ', '.join([c.get('value', '') for c in cats[:3]])
        
        return result, None
    except Exception as e:
        return None, str(e)

def scan_ioc(ioc_value, comment=''):
    ioc = VTCache.query.filter_by(ioc_value=ioc_value.lower()).first()
    if not ioc:
        ioc = VTCache(ioc_value=ioc_value.lower(), ioc_type=detect_ioc_type(ioc_value), comment=comment, status='pending')
        db.session.add(ioc)
        db.session.commit()
    
    if ioc.status != 'pending':
        return ioc
    
    result, error = query_virustotal(ioc.ioc_value, ioc.ioc_type)
    
    if error == "not_found":
        ioc.status = 'not_found'
    elif error:
        ioc.status = 'error'
    else:
        ioc.malicious = result['malicious']
        ioc.total = result['total']
        ioc.threat_label = result['threat_label']
        ioc.categories = result['categories']
        ioc.status = 'scanned'
        ioc.scanned_at = datetime.utcnow()
    
    db.session.commit()
    return ioc

def get_queue_status():
    pending = VTCache.query.filter_by(status='pending').count()
    scanned = VTCache.query.filter_by(status='scanned').count()
    not_found = VTCache.query.filter_by(status='not_found').count()
    errors = VTCache.query.filter_by(status='error').count()
    return {
        'pending': pending, 'scanned': scanned,
        'not_found': not_found, 'errors': errors,
        'api_configured': bool(VT_API_KEY),
        'wait_seconds': int(check_rate_limit())
    }

# ============ RUTAS ============
@app.route('/')
def index():
    iocs = VTCache.query.order_by(VTCache.malicious.desc().nullslast(), VTCache.created_at.desc()).limit(1000).all()
    
    total = len(iocs)
    malicious_count = sum(1 for i in iocs if i.status == 'scanned' and i.malicious and i.malicious > 10)
    suspicious_count = sum(1 for i in iocs if i.status == 'scanned' and i.malicious and 0 < i.malicious <= 10)
    clean_count = sum(1 for i in iocs if i.status == 'scanned' and (i.malicious == 0 or i.malicious is None))
    not_found = sum(1 for i in iocs if i.status == 'not_found')
    
    threat_counter = Counter()
    for i in iocs:
        if i.threat_label:
            label = i.threat_label.split('/')[0] if '/' in i.threat_label else i.threat_label
            threat_counter[label] += 1
    
    top_threats = threat_counter.most_common(8)
    threat_labels = [t[0] for t in top_threats] if top_threats else ['Sin datos']
    threat_counts = [t[1] for t in top_threats] if top_threats else [0]
    
    stats = get_queue_status()
    
    return render_template('index.html',
        iocs=iocs, stats=stats, total=total,
        malicious_count=malicious_count, suspicious_count=suspicious_count,
        clean_count=clean_count, not_found=not_found,
        threat_labels=threat_labels, threat_counts=threat_counts
    )

@app.route('/add', methods=['POST'])
def add_iocs():
    data = request.get_json() or {}
    iocs_text = data.get('iocs', '')
    lines = [l.strip() for l in iocs_text.split('\n') if l.strip()]
    added = 0
    for line in lines:
        parts = line.split(',', 1)
        value = parts[0].strip()
        comment = parts[1].strip() if len(parts) > 1 else ''
        if not value or len(value) < 4:
            continue
        existing = VTCache.query.filter_by(ioc_value=value.lower()).first()
        if not existing:
            ioc = VTCache(ioc_value=value.lower(), ioc_type=detect_ioc_type(value), comment=comment, status='pending')
            db.session.add(ioc)
            added += 1
    db.session.commit()
    return jsonify({'added': added, 'total': len(lines)})

@app.route('/scan', methods=['POST'])
def scan_next():
    wait = check_rate_limit()
    if wait > 0:
        return jsonify({'status': 'wait', 'seconds': int(wait)})
    pending = VTCache.query.filter_by(status='pending').first()
    if not pending:
        return jsonify({'status': 'done'})
    scan_ioc(pending.ioc_value, pending.comment)
    return jsonify({'status': 'scanned', 'ioc': pending.ioc_value, 'malicious': pending.malicious, 'total': pending.total})

@app.route('/status')
def status():
    return jsonify(get_queue_status())

@app.route('/export/xlsx')
def export_xlsx():
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Border, Side, Alignment
    from openpyxl.chart import PieChart, Reference
    from openpyxl.chart.label import DataLabelList
    
    wb = Workbook()
    hf = Font(bold=True, color='FFFFFF')
    hfill = PatternFill(start_color='182B47', end_color='182B47', fill_type='solid')
    red = PatternFill(start_color='E74C3C', end_color='E74C3C', fill_type='solid')
    yellow = PatternFill(start_color='F39C12', end_color='F39C12', fill_type='solid')
    green = PatternFill(start_color='27AE60', end_color='27AE60', fill_type='solid')
    lred = PatternFill(start_color='FADBD8', end_color='FADBD8', fill_type='solid')
    lyellow = PatternFill(start_color='FCF3CF', end_color='FCF3CF', fill_type='solid')
    lgreen = PatternFill(start_color='D5F5E3', end_color='D5F5E3', fill_type='solid')
    link = Font(color='2980B9', underline='single')
    white = Font(bold=True, color='FFFFFF')
    border = Border(left=Side(style='thin'), right=Side(style='thin'), top=Side(style='thin'), bottom=Side(style='thin'))
    
    all_iocs = VTCache.query.all()
    total = len(all_iocs)
    mal = sum(1 for i in all_iocs if i.status == 'scanned' and i.malicious and i.malicious > 10)
    susp = sum(1 for i in all_iocs if i.status == 'scanned' and i.malicious and 0 < i.malicious <= 10)
    clean = sum(1 for i in all_iocs if i.status == 'scanned' and (i.malicious == 0 or i.malicious is None))
    nf = sum(1 for i in all_iocs if i.status == 'not_found')
    scanned = mal + susp + clean
    
    pct_mal = f'{(mal/total*100):.1f}%' if total > 0 else '0%'
    pct_susp = f'{(susp/total*100):.1f}%' if total > 0 else '0%'
    pct_clean = f'{(clean/total*100):.1f}%' if total > 0 else '0%'
    pct_nf = f'{(nf/total*100):.1f}%' if total > 0 else '0%'
    
    # Resumen
    ws = wb.active
    ws.title = 'Resumen Ejecutivo'
    ws.merge_cells('A1:E1')
    ws['A1'] = 'REPORTE DE ANÁLISIS DE IOCs - VIRUSTOTAL'
    ws['A1'].font = Font(bold=True, size=16, color='182B47')
    ws['A1'].alignment = Alignment(horizontal='center')
    
    ws['A3'] = 'Fecha:'
    ws['B3'] = datetime.now().strftime('%Y-%m-%d %H:%M')
    ws['A4'] = 'Generado por:'
    ws['B4'] = 'Demo VT-Automatizado'
    
    # Stats
    ws['A6'] = 'ESTADÍSTICAS'
    ws['A6'].font = Font(bold=True, size=12)
    
    headers = ['Categoría', 'Cantidad', 'Porcentaje']
    for c, h in enumerate(headers, 1):
        cell = ws.cell(row=7, column=c, value=h)
        cell.font = hf
        cell.fill = hfill
        cell.border = border
    
    stats_rows = [
        ('Total IOCs', total, '100%', None),
        ('Maliciosos (>10)', mal, pct_mal, lred),
        ('Sospechosos (1-10)', susp, pct_susp, lyellow),
        ('Limpios (0)', clean, pct_clean, lgreen),
        ('Sin resultados', nf, pct_nf, None),
    ]
    
    for r, (cat, cant, pct, fill) in enumerate(stats_rows, 8):
        ws.cell(row=r, column=1, value=cat).border = border
        ws.cell(row=r, column=2, value=cant).border = border
        ws.cell(row=r, column=3, value=pct).border = border
        if fill:
            ws.cell(row=r, column=1).fill = fill
    
    # Datos gráfica
    ws['E7'] = 'Tipo'
    ws['F7'] = 'Cantidad'
    ws['E8'] = f'Maliciosos ({pct_mal})'
    ws['F8'] = mal
    ws['E9'] = f'Sospechosos ({pct_susp})'
    ws['F9'] = susp
    ws['E10'] = f'Limpios ({pct_clean})'
    ws['F10'] = clean
    ws['E11'] = f'Sin resultados ({pct_nf})'
    ws['F11'] = nf
    
    pie = PieChart()
    data = Reference(ws, min_col=6, min_row=7, max_row=11)
    cats = Reference(ws, min_col=5, min_row=8, max_row=11)
    pie.add_data(data, titles_from_data=True)
    pie.set_categories(cats)
    pie.title = "Distribución"
    pie.dataLabels = DataLabelList()
    pie.dataLabels.showPercent = True
    ws.add_chart(pie, "A14")
    
    ws.column_dimensions['A'].width = 25
    ws.column_dimensions['B'].width = 12
    ws.column_dimensions['C'].width = 12
    ws.column_dimensions['E'].width = 25
    
    # IOCs
    ws2 = wb.create_sheet('IOCs')
    headers = ['Score', 'IOC', 'Tipo', 'Threat Label', 'Link VT']
    for c, h in enumerate(headers, 1):
        cell = ws2.cell(row=1, column=c, value=h)
        cell.font = hf
        cell.fill = hfill
        cell.border = border
    ws2.freeze_panes = 'A2'
    
    iocs = VTCache.query.order_by(VTCache.malicious.desc().nullslast()).all()
    for r, ioc in enumerate(iocs, 2):
        score = f"{ioc.malicious}/{ioc.total}" if ioc.total else 'N/A'
        ws2.cell(row=r, column=1, value=score).border = border
        ws2.cell(row=r, column=2, value=ioc.ioc_value).border = border
        ws2.cell(row=r, column=3, value=(ioc.ioc_type or '').upper()).border = border
        ws2.cell(row=r, column=4, value=ioc.threat_label or '').border = border
        
        if ioc.ioc_type in ['md5','sha1','sha256']:
            url = f'https://www.virustotal.com/gui/file/{ioc.ioc_value}'
        elif ioc.ioc_type == 'ip':
            url = f'https://www.virustotal.com/gui/ip-address/{ioc.ioc_value}'
        else:
            url = ''
        cell = ws2.cell(row=r, column=5, value=url)
        if url:
            cell.hyperlink = url
            cell.font = link
        cell.border = border
        
        if ioc.malicious and ioc.malicious > 10:
            ws2.cell(row=r, column=1).fill = red
            ws2.cell(row=r, column=1).font = white
        elif ioc.malicious and ioc.malicious > 0:
            ws2.cell(row=r, column=1).fill = yellow
        elif ioc.status == 'scanned':
            ws2.cell(row=r, column=1).fill = green
            ws2.cell(row=r, column=1).font = white
    
    ws2.column_dimensions['A'].width = 10
    ws2.column_dimensions['B'].width = 70
    ws2.column_dimensions['C'].width = 10
    ws2.column_dimensions['D'].width = 30
    ws2.column_dimensions['E'].width = 55
    
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    return Response(output.getvalue(), 
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': f'attachment; filename=IOCs_VT_{datetime.now().strftime("%Y%m%d_%H%M")}.xlsx'})

@app.route('/clear', methods=['POST'])
def clear_all():
    VTCache.query.delete()
    db.session.commit()
    return jsonify({'status': 'ok'})

# Crear tablas
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
