"""
Demo VT-Automatizado v2 - Verificador de IOCs con VirusTotal
Usando vt-py (librería oficial)
CIR Banxico - Dirección de Ciberseguridad
"""
from flask import Flask, render_template, request, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from collections import Counter
import vt
import asyncio
import os
import re
from io import BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///vt_cache.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# API Key de VirusTotal
VT_API_KEY = os.environ.get('VT_API_KEY', 'f2c83df5f4ce4ee2126f44d0082509efb1ff87aee930dffaf0772f08775d6458')

# Rate limiting
request_times = []

# ============ MODELOS ============
class IOC(db.Model):
    """IOC principal"""
    __tablename__ = 'iocs'
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(500), unique=True, index=True)
    ioc_type = db.Column(db.String(20))  # sha256, md5, sha1, ip, domain, url
    comment = db.Column(db.String(500))
    added_by = db.Column(db.String(100), default='sistema')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relación con escaneos
    scans = db.relationship('IOCScan', backref='ioc', lazy='dynamic', order_by='IOCScan.scanned_at.desc()')
    
    @property
    def latest_scan(self):
        return self.scans.first()

class IOCScan(db.Model):
    """Historial de escaneos por IOC"""
    __tablename__ = 'ioc_scans'
    id = db.Column(db.Integer, primary_key=True)
    ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id'), nullable=False)
    
    # Resultados VT
    malicious = db.Column(db.Integer, default=0)
    suspicious = db.Column(db.Integer, default=0)
    harmless = db.Column(db.Integer, default=0)
    undetected = db.Column(db.Integer, default=0)
    total_engines = db.Column(db.Integer, default=0)
    
    # Metadata del archivo (para hashes)
    file_type = db.Column(db.String(100))
    file_size = db.Column(db.Integer)
    file_name = db.Column(db.String(500))
    
    # Clasificación
    threat_label = db.Column(db.String(200))
    threat_category = db.Column(db.String(200))
    popular_threat_name = db.Column(db.String(200))
    
    # Para IPs/Dominios
    country = db.Column(db.String(50))
    as_owner = db.Column(db.String(200))
    reputation = db.Column(db.Integer)
    
    # Fechas importantes
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    last_modification = db.Column(db.DateTime)
    
    # Raw data (JSON completo por si se necesita)
    raw_response = db.Column(db.Text)
    
    # Estado
    status = db.Column(db.String(20), default='pending')  # pending, scanned, not_found, error
    error_message = db.Column(db.String(500))
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def score(self):
        if self.total_engines:
            return f"{self.malicious}/{self.total_engines}"
        return "N/A"
    
    @property
    def severity(self):
        if not self.malicious:
            return 'clean'
        elif self.malicious > 10:
            return 'high'
        elif self.malicious > 0:
            return 'medium'
        return 'clean'

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
    elif value.startswith('http'):
        return 'url'
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

def scan_ioc_vt(ioc):
    """Escanear IOC usando vt-py"""
    global request_times
    
    if not VT_API_KEY:
        return None, "API key no configurada"
    
    # Crear nuevo registro de escaneo
    scan = IOCScan(ioc_id=ioc.id, status='pending')
    db.session.add(scan)
    
    try:
        with vt.Client(VT_API_KEY) as client:
            request_times.append(datetime.now())
            
            if ioc.ioc_type in ['md5', 'sha1', 'sha256']:
                try:
                    file_obj = client.get_object(f"/files/{ioc.value}")
                    
                    stats = file_obj.last_analysis_stats
                    scan.malicious = stats.get('malicious', 0)
                    scan.suspicious = stats.get('suspicious', 0)
                    scan.harmless = stats.get('harmless', 0)
                    scan.undetected = stats.get('undetected', 0)
                    scan.total_engines = sum(stats.values())
                    
                    # Metadata archivo
                    scan.file_type = getattr(file_obj, 'type_description', None)
                    scan.file_size = getattr(file_obj, 'size', None)
                    scan.file_name = getattr(file_obj, 'meaningful_name', None)
                    
                    # Clasificación
                    threat_info = getattr(file_obj, 'popular_threat_classification', {})
                    if threat_info:
                        scan.threat_label = threat_info.get('suggested_threat_label', '')
                        cats = threat_info.get('popular_threat_category', [])
                        if cats:
                            scan.threat_category = ', '.join([c.get('value', '') for c in cats[:3]])
                    
                    # Fechas
                    if hasattr(file_obj, 'first_submission_date'):
                        scan.first_seen = datetime.fromtimestamp(file_obj.first_submission_date)
                    if hasattr(file_obj, 'last_analysis_date'):
                        scan.last_seen = datetime.fromtimestamp(file_obj.last_analysis_date)
                    
                    scan.status = 'scanned'
                    
                except vt.error.APIError as e:
                    if 'NotFoundError' in str(e):
                        scan.status = 'not_found'
                    else:
                        scan.status = 'error'
                        scan.error_message = str(e)
                        
            elif ioc.ioc_type == 'ip':
                try:
                    ip_obj = client.get_object(f"/ip_addresses/{ioc.value}")
                    
                    stats = ip_obj.last_analysis_stats
                    scan.malicious = stats.get('malicious', 0)
                    scan.suspicious = stats.get('suspicious', 0)
                    scan.harmless = stats.get('harmless', 0)
                    scan.undetected = stats.get('undetected', 0)
                    scan.total_engines = sum(stats.values())
                    
                    scan.country = getattr(ip_obj, 'country', None)
                    scan.as_owner = getattr(ip_obj, 'as_owner', None)
                    scan.reputation = getattr(ip_obj, 'reputation', None)
                    
                    scan.status = 'scanned'
                    
                except vt.error.APIError as e:
                    if 'NotFoundError' in str(e):
                        scan.status = 'not_found'
                    else:
                        scan.status = 'error'
                        scan.error_message = str(e)
                        
            elif ioc.ioc_type == 'domain':
                try:
                    domain_obj = client.get_object(f"/domains/{ioc.value}")
                    
                    stats = domain_obj.last_analysis_stats
                    scan.malicious = stats.get('malicious', 0)
                    scan.suspicious = stats.get('suspicious', 0)
                    scan.harmless = stats.get('harmless', 0)
                    scan.undetected = stats.get('undetected', 0)
                    scan.total_engines = sum(stats.values())
                    
                    scan.reputation = getattr(domain_obj, 'reputation', None)
                    
                    scan.status = 'scanned'
                    
                except vt.error.APIError as e:
                    if 'NotFoundError' in str(e):
                        scan.status = 'not_found'
                    else:
                        scan.status = 'error'
                        scan.error_message = str(e)
            else:
                scan.status = 'error'
                scan.error_message = 'Tipo no soportado'
        
        scan.scanned_at = datetime.utcnow()
        db.session.commit()
        return scan, None
        
    except Exception as e:
        scan.status = 'error'
        scan.error_message = str(e)
        db.session.commit()
        return scan, str(e)

def get_stats():
    """Obtener estadísticas globales"""
    iocs = IOC.query.all()
    total = len(iocs)
    
    malicious_count = 0
    suspicious_count = 0
    clean_count = 0
    not_found = 0
    pending = 0
    
    for ioc in iocs:
        scan = ioc.latest_scan
        if not scan:
            pending += 1
        elif scan.status == 'not_found':
            not_found += 1
        elif scan.status == 'scanned':
            if scan.malicious and scan.malicious > 10:
                malicious_count += 1
            elif scan.malicious and scan.malicious > 0:
                suspicious_count += 1
            else:
                clean_count += 1
        else:
            pending += 1
    
    return {
        'total': total,
        'malicious_count': malicious_count,
        'suspicious_count': suspicious_count,
        'clean_count': clean_count,
        'not_found': not_found,
        'pending': pending,
        'api_configured': bool(VT_API_KEY)
    }

# ============ RUTAS ============
@app.route('/')
def index():
    stats = get_stats()
    
    # IOCs con su último escaneo
    iocs = IOC.query.order_by(IOC.created_at.desc()).limit(500).all()
    
    # Ordenar por malicious del último scan
    iocs_with_scans = []
    for ioc in iocs:
        scan = ioc.latest_scan
        iocs_with_scans.append({
            'ioc': ioc,
            'scan': scan,
            'malicious': scan.malicious if scan and scan.malicious else 0
        })
    
    iocs_with_scans.sort(key=lambda x: x['malicious'], reverse=True)
    
    # Top amenazas
    threat_counter = Counter()
    for item in iocs_with_scans:
        if item['scan'] and item['scan'].threat_label:
            label = item['scan'].threat_label.split('/')[0]
            threat_counter[label] += 1
    
    top_threats = threat_counter.most_common(8)
    threat_labels = [t[0] for t in top_threats] if top_threats else ['Sin datos']
    threat_counts = [t[1] for t in top_threats] if top_threats else [0]
    
    return render_template('index.html',
        iocs_with_scans=iocs_with_scans,
        stats=stats,
        threat_labels=threat_labels,
        threat_counts=threat_counts,
        **stats
    )

@app.route('/ioc/<int:ioc_id>')
def ioc_detail(ioc_id):
    """Ver historial de un IOC"""
    ioc = IOC.query.get_or_404(ioc_id)
    scans = ioc.scans.all()
    return render_template('ioc_detail.html', ioc=ioc, scans=scans)

@app.route('/add', methods=['POST'])
def add_iocs():
    data = request.get_json() or {}
    iocs_text = data.get('iocs', '')
    added_by = data.get('added_by', 'sistema')
    
    lines = [l.strip() for l in iocs_text.split('\n') if l.strip()]
    added = 0
    
    for line in lines:
        parts = line.split(',', 1)
        value = parts[0].strip().lower()
        comment = parts[1].strip() if len(parts) > 1 else ''
        
        if not value or len(value) < 4:
            continue
        
        existing = IOC.query.filter_by(value=value).first()
        if not existing:
            ioc = IOC(
                value=value,
                ioc_type=detect_ioc_type(value),
                comment=comment,
                added_by=added_by
            )
            db.session.add(ioc)
            added += 1
    
    db.session.commit()
    return jsonify({'added': added, 'total': len(lines)})

@app.route('/scan', methods=['POST'])
def scan_next():
    wait = check_rate_limit()
    if wait > 0:
        return jsonify({'status': 'wait', 'seconds': int(wait)})
    
    # Buscar IOC sin escanear o para re-escanear
    ioc_id = request.json.get('ioc_id') if request.json else None
    
    if ioc_id:
        # Re-escanear IOC específico
        ioc = IOC.query.get(ioc_id)
    else:
        # Buscar siguiente sin escanear
        ioc = IOC.query.filter(~IOC.scans.any()).first()
    
    if not ioc:
        return jsonify({'status': 'done'})
    
    scan, error = scan_ioc_vt(ioc)
    
    return jsonify({
        'status': 'scanned' if scan else 'error',
        'ioc': ioc.value,
        'ioc_id': ioc.id,
        'malicious': scan.malicious if scan else 0,
        'total': scan.total_engines if scan else 0,
        'threat_label': scan.threat_label if scan else '',
        'error': error
    })

@app.route('/rescan/<int:ioc_id>', methods=['POST'])
def rescan_ioc(ioc_id):
    """Re-escanear un IOC específico"""
    wait = check_rate_limit()
    if wait > 0:
        return jsonify({'status': 'wait', 'seconds': int(wait)})
    
    ioc = IOC.query.get_or_404(ioc_id)
    scan, error = scan_ioc_vt(ioc)
    
    return jsonify({
        'status': 'scanned' if scan else 'error',
        'scan_id': scan.id if scan else None,
        'malicious': scan.malicious if scan else 0,
        'total': scan.total_engines if scan else 0,
        'error': error
    })

@app.route('/status')
def status():
    stats = get_stats()
    stats['wait_seconds'] = int(check_rate_limit())
    return jsonify(stats)

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
    link = Font(color='2980B9', underline='single')
    white = Font(bold=True, color='FFFFFF')
    border = Border(left=Side(style='thin'), right=Side(style='thin'), top=Side(style='thin'), bottom=Side(style='thin'))
    
    stats = get_stats()
    
    # === RESUMEN ===
    ws = wb.active
    ws.title = 'Resumen Ejecutivo'
    ws.merge_cells('A1:F1')
    ws['A1'] = 'REPORTE DE ANÁLISIS DE IOCs - VIRUSTOTAL'
    ws['A1'].font = Font(bold=True, size=16, color='182B47')
    ws['A1'].alignment = Alignment(horizontal='center')
    
    ws['A3'] = 'Fecha:'
    ws['B3'] = datetime.now().strftime('%Y-%m-%d %H:%M')
    ws['A4'] = 'Generado por:'
    ws['B4'] = 'VT-Automatizado v2'
    ws['A5'] = 'Librería:'
    ws['B5'] = 'vt-py (oficial VirusTotal)'
    
    # Stats
    ws['A7'] = 'ESTADÍSTICAS'
    ws['A7'].font = Font(bold=True, size=12)
    
    headers = ['Categoría', 'Cantidad', 'Porcentaje']
    for c, h in enumerate(headers, 1):
        cell = ws.cell(row=8, column=c, value=h)
        cell.font = hf
        cell.fill = hfill
        cell.border = border
    
    total = stats['total'] or 1
    stats_rows = [
        ('Total IOCs', stats['total'], '100%'),
        ('Maliciosos (>10)', stats['malicious_count'], f"{stats['malicious_count']/total*100:.1f}%"),
        ('Sospechosos (1-10)', stats['suspicious_count'], f"{stats['suspicious_count']/total*100:.1f}%"),
        ('Limpios (0)', stats['clean_count'], f"{stats['clean_count']/total*100:.1f}%"),
        ('Sin resultados', stats['not_found'], f"{stats['not_found']/total*100:.1f}%"),
    ]
    
    for r, (cat, cant, pct) in enumerate(stats_rows, 9):
        ws.cell(row=r, column=1, value=cat).border = border
        ws.cell(row=r, column=2, value=cant).border = border
        ws.cell(row=r, column=3, value=pct).border = border
    
    ws.column_dimensions['A'].width = 25
    ws.column_dimensions['B'].width = 12
    ws.column_dimensions['C'].width = 12
    
    # === IOCs DETALLADOS ===
    ws2 = wb.create_sheet('IOCs Detallados')
    headers = ['Score', 'IOC', 'Tipo', 'Threat Label', 'Categoría', 'Archivo', 'Tamaño', 'País/AS', 'Primer Visto', 'Último Scan', 'Link VT']
    for c, h in enumerate(headers, 1):
        cell = ws2.cell(row=1, column=c, value=h)
        cell.font = hf
        cell.fill = hfill
        cell.border = border
    ws2.freeze_panes = 'A2'
    
    iocs = IOC.query.all()
    for r, ioc in enumerate(iocs, 2):
        scan = ioc.latest_scan
        
        score = scan.score if scan else 'N/A'
        ws2.cell(row=r, column=1, value=score).border = border
        ws2.cell(row=r, column=2, value=ioc.value).border = border
        ws2.cell(row=r, column=3, value=ioc.ioc_type.upper()).border = border
        ws2.cell(row=r, column=4, value=scan.threat_label if scan else '').border = border
        ws2.cell(row=r, column=5, value=scan.threat_category if scan else '').border = border
        ws2.cell(row=r, column=6, value=scan.file_name if scan else '').border = border
        ws2.cell(row=r, column=7, value=scan.file_size if scan else '').border = border
        
        location = ''
        if scan:
            if scan.country:
                location = scan.country
            if scan.as_owner:
                location += f' ({scan.as_owner})'
        ws2.cell(row=r, column=8, value=location).border = border
        
        ws2.cell(row=r, column=9, value=scan.first_seen.strftime('%Y-%m-%d') if scan and scan.first_seen else '').border = border
        ws2.cell(row=r, column=10, value=scan.scanned_at.strftime('%Y-%m-%d %H:%M') if scan and scan.scanned_at else '').border = border
        
        if ioc.ioc_type in ['md5','sha1','sha256']:
            url = f'https://www.virustotal.com/gui/file/{ioc.value}'
        elif ioc.ioc_type == 'ip':
            url = f'https://www.virustotal.com/gui/ip-address/{ioc.value}'
        elif ioc.ioc_type == 'domain':
            url = f'https://www.virustotal.com/gui/domain/{ioc.value}'
        else:
            url = ''
        
        cell = ws2.cell(row=r, column=11, value=url)
        if url:
            cell.hyperlink = url
            cell.font = link
        cell.border = border
        
        # Color por severidad
        if scan and scan.malicious:
            if scan.malicious > 10:
                ws2.cell(row=r, column=1).fill = red
                ws2.cell(row=r, column=1).font = white
            elif scan.malicious > 0:
                ws2.cell(row=r, column=1).fill = yellow
            else:
                ws2.cell(row=r, column=1).fill = green
                ws2.cell(row=r, column=1).font = white
    
    # Ajustar anchos
    ws2.column_dimensions['A'].width = 10
    ws2.column_dimensions['B'].width = 65
    ws2.column_dimensions['C'].width = 10
    ws2.column_dimensions['D'].width = 25
    ws2.column_dimensions['E'].width = 20
    ws2.column_dimensions['F'].width = 30
    ws2.column_dimensions['G'].width = 12
    ws2.column_dimensions['H'].width = 25
    ws2.column_dimensions['I'].width = 12
    ws2.column_dimensions['J'].width = 15
    ws2.column_dimensions['K'].width = 55
    
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    return Response(output.getvalue(), 
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': f'attachment; filename=IOCs_VT_{datetime.now().strftime("%Y%m%d_%H%M")}.xlsx'})

@app.route('/clear', methods=['POST'])
def clear_all():
    IOCScan.query.delete()
    IOC.query.delete()
    db.session.commit()
    return jsonify({'status': 'ok'})

# Crear tablas
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
