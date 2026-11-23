import os
import socket
import datetime
from flask import Flask, jsonify, request, render_template_string

app = Flask(__name__)
PROVEEDOR = os.environ.get("CLOUD_PROVIDER", "AWS").upper()

THEMES = {
    "AWS": {
        "nombre": "Amazon Web Services (us-east-2)",
        "sigla": "AWS CLOUD",
        "primario": "#0f172a",
        "acento": "#d97706",
        "acento_suave": "#fef3c7",
        "texto_acento": "#92400e",
        "borde": "#f59e0b",
    },
    "AZURE": {
        "nombre": "Microsoft Azure (East US)",
        "sigla": "AZURE CLOUD",
        "primario": "#0f172a",
        "acento": "#0284c7",
        "acento_suave": "#e0f2fe",
        "texto_acento": "#075985",
        "borde": "#0ea5e9",
    },
}

TEMA = THEMES.get(PROVEEDOR, THEMES["AWS"])

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Portal Nacional de Servicios Digitales | {{ tema.sigla }}</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root{--bg-body:#f8fafc;--surface:#ffffff;--text-main:#0f172a;--text-muted:#64748b;--border-light:#e2e8f0;--primary:{{ tema.primario }};--accent:{{ tema.acento }};--accent-soft:{{ tema.acento_suave }};--accent-text:{{ tema.texto_acento }}}
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Inter',system-ui,sans-serif;background:var(--bg-body);color:var(--text-main);line-height:1.6}
    .gov-banner{background:#020617;color:#cbd5e1;font-size:.78rem;padding:.45rem 2rem;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #1e293b}
    .gov-banner strong{color:#38bdf8}
    header{background:var(--surface);border-bottom:1px solid var(--border-light);padding:1.1rem 2rem;box-shadow:0 1px 3px rgba(0,0,0,.03);position:sticky;top:0;z-index:50}
    .nav-container{max-width:1120px;margin:0 auto;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem}
    .brand{display:flex;align-items:center;gap:.85rem}
    .brand-icon{width:40px;height:40px;background:var(--primary);color:#fff;border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:1.1rem;border-bottom:3px solid var(--accent)}
    .brand-text h1{font-size:1.15rem;font-weight:700;letter-spacing:-.02em;color:var(--primary)}
    .brand-text p{font-size:.8rem;color:var(--text-muted)}
    .cloud-pill{display:inline-flex;align-items:center;gap:.5rem;background:var(--accent-soft);color:var(--accent-text);border:1px solid {{ tema.borde }};padding:.45rem 1rem;border-radius:9999px;font-size:.82rem;font-weight:600}
    .pulse-dot{width:8px;height:8px;background:#16a34a;border-radius:50%;box-shadow:0 0 0 3px rgba(22,163,74,.25)}
    .hero{background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);color:#fff;padding:3rem 2rem;border-bottom:4px solid var(--accent)}
    .hero-container{max-width:1120px;margin:0 auto;display:grid;grid-template-columns:1.4fr 1fr;gap:2.5rem;align-items:center}
    @media(max-width:820px){.hero-container{grid-template-columns:1fr}}
    .hero-tag{display:inline-block;background:rgba(255,255,255,.1);color:#e2e8f0;font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;padding:.3rem .75rem;border-radius:6px;margin-bottom:.9rem}
    .hero h2{font-size:2rem;font-weight:700;letter-spacing:-.03em;line-height:1.2;margin-bottom:.8rem}
    .hero p{color:#cbd5e1;font-size:.95rem;margin-bottom:1.5rem}
    .search-box{display:flex;background:#fff;padding:.35rem;border-radius:10px;box-shadow:0 10px 25px rgba(0,0,0,.2)}
    .search-box input{flex:1;border:none;padding:.65rem 1rem;font-size:.9rem;color:var(--text-main);outline:none;border-radius:8px}
    .search-box button{background:var(--accent);color:#fff;border:none;padding:.65rem 1.35rem;border-radius:8px;font-weight:600;font-size:.88rem;cursor:pointer}
    .telemetry-card{background:rgba(15,23,42,.75);border:1px solid rgba(255,255,255,.12);border-radius:12px;padding:1.4rem}
    .telemetry-header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,.1);padding-bottom:.75rem;margin-bottom:1rem;font-size:.82rem;color:#94a3b8;font-weight:600}
    .telemetry-row{display:flex;justify-content:space-between;font-size:.84rem;margin-bottom:.65rem}
    .telemetry-row span:first-child{color:#94a3b8}
    .telemetry-row span:last-child{font-family:monospace;color:#f8fafc;font-weight:600}
    main{max-width:1120px;margin:2.2rem auto;padding:0 2rem}
    .section-header{display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:1.2rem}
    .section-header h3{font-size:1.15rem;font-weight:700}
    .section-header span{font-size:.82rem;color:var(--text-muted)}
    .services-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1.2rem;margin-bottom:2.5rem}
    .service-card{background:var(--surface);border:1px solid var(--border-light);border-radius:12px;padding:1.35rem}
    .service-card h4{font-size:.98rem;margin-bottom:.4rem;color:var(--primary)}
    .service-card p{font-size:.83rem;color:var(--text-muted);margin-bottom:1rem}
    .service-link{font-size:.82rem;font-weight:600;color:var(--accent);text-decoration:none}
    .table-card{background:var(--surface);border:1px solid var(--border-light);border-radius:12px;overflow:hidden}
    table{width:100%;border-collapse:collapse}
    th{background:#f8fafc;text-align:left;padding:.9rem 1.25rem;font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:var(--text-muted);border-bottom:1px solid var(--border-light)}
    td{padding:1rem 1.25rem;font-size:.88rem;border-bottom:1px solid var(--border-light)}
    .status-badge{display:inline-block;padding:.25rem .65rem;border-radius:999px;font-size:.75rem;font-weight:600}
    .status-ok{background:#dcfce7;color:#166534}
    .status-proc{background:#fef9c3;color:#854d0e}
    footer{max-width:1120px;margin:3rem auto 2rem;padding:1.5rem 2rem 0;border-top:1px solid var(--border-light);display:flex;justify-content:space-between;font-size:.8rem;color:var(--text-muted);flex-wrap:wrap;gap:1rem}
  </style>
</head>
<body>
  <div class="gov-banner"><span>Plataforma Oficial Interoperable | Seguridad Perimetral <strong>Zero-Trust SDN-ONOS</strong></span><span>Política Activa: <strong>GOV-API-001 (TLS 1.3 / HTTPS)</strong></span></div>
  <header><div class="nav-container"><div class="brand"><div class="brand-icon">Gob</div><div class="brand-text"><h1>Portal Ciudadano Unificado</h1><p>Ventanilla Única de Trámites y Certificaciones Digitales</p></div></div>
  <div class="cloud-pill"><span class="pulse-dot"></span>NODO ACTIVO: {{ tema.nombre }}</div></div></header>
  <section class="hero"><div class="hero-container"><div><span class="hero-tag">Infraestructura Multi-Cloud Resiliente</span>
  <h2>Gestione sus trámites y certificados oficiales en línea</h2>
  <p>Consulte el estado de sus expedientes administrativos con validación criptográfica de origen gobernada por controladores definidos por software.</p>
  <div class="search-box"><input type="text" id="buscador" placeholder="Ingrese N.° de Expediente (ej. EXP-2026-0001)..." onkeyup="filtrarTabla()"><button onclick="filtrarTabla()">Consultar Estado</button></div></div>
  <div class="telemetry-card"><div class="telemetry-header"><span>TELEMETRÍA DE CONEXIÓN</span><span style="color:#4ade80">● AUTORIZADO</span></div>
  <div class="telemetry-row"><span>Infraestructura Cloud:</span><span>{{ tema.sigla }}</span></div>
  <div class="telemetry-row"><span>Instancia / Host:</span><span>{{ hostname }}</span></div>
  <div class="telemetry-row"><span>IP Origen Validada:</span><span>{{ client_ip }}</span></div>
  <div class="telemetry-row"><span>Sincronización UTC:</span><span>{{ timestamp }}</span></div></div></div></section>
  <main><div class="section-header"><h3>Servicios Digitales Destacados</h3><span>Disponibilidad garantizada Multi-Región</span></div>
  <div class="services-grid">
  <div class="service-card"><h4>Certificado de Antecedentes</h4><p>Emisión inmediata con firma digital verificable mediante código QR institucional.</p><a href="#expedientes" class="service-link">Iniciar trámite →</a></div>
  <div class="service-card"><h4>Constancia de Identidad Digital</h4><p>Validación biométrica y acreditación ciudadana para entidades públicas y privadas.</p><a href="#expedientes" class="service-link">Verificar documento →</a></div>
  <div class="service-card"><h4>Mesa de Partes Virtual</h4><p>Recepción de solicitudes administrativas 24/7 con trazabilidad de extremo a extremo.</p><a href="#expedientes" class="service-link">Presentar solicitud →</a></div></div>
  <div class="section-header" id="expedientes"><h3>Registro de Expedientes Recientes</h3><span>Actualizado en tiempo real desde {{ tema.sigla }}</span></div>
  <div class="table-card"><table id="tablaExpedientes"><thead><tr><th>Código Expediente</th><th>Descripción del Trámite</th><th>Fecha Registro</th><th>Estado</th><th>Plano de Ejecución</th></tr></thead>
  <tbody><tr><td><strong>EXP-2026-0001</strong></td><td>Certificado Único de Antecedentes Digitales</td><td>15/11/2026</td><td><span class="status-badge status-ok">APROBADO</span></td><td>{{ tema.sigla }}</td></tr>
  <tr><td><strong>EXP-2026-0042</strong></td><td>Acreditación de Domicilio Electrónico Ciudadano</td><td>15/11/2026</td><td><span class="status-badge status-ok">EMITIDO</span></td><td>{{ tema.sigla }}</td></tr>
  <tr><td><strong>EXP-2026-0089</strong></td><td>Renovación de Credencial Profesional</td><td>15/11/2026</td><td><span class="status-badge status-proc">EN VALIDACIÓN</span></td><td>{{ tema.sigla }}</td></tr></tbody></table></div></main>
  <footer><span>© 2026 Arquitectura Multi-Cloud SDN-ONOS | Gobernanza Declarativa de Seguridad</span><span>Endpoint de Salud: <strong>/salud</strong> | Estado: <strong>Operativo (HTTP 200)</strong></span></footer>
  <script>function filtrarTabla(){const f=document.getElementById("buscador").value.toUpperCase();const r=document.getElementById("tablaExpedientes").getElementsByTagName("tr");for(let i=1;i<r.length;i++){const t=r[i].textContent||r[i].innerText;r[i].style.display=t.toUpperCase().indexOf(f)>-1?"":"none"}}</script>
</body>
</html>"""

@app.route("/")
def index():
    return render_template_string(
        HTML_TEMPLATE,
        tema=TEMA,
        hostname=socket.gethostname(),
        client_ip=request.remote_addr,
        timestamp=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

@app.route("/salud")
def salud():
    return jsonify({
        "estado": "ok",
        "entorno": f"Sirviendo desde: {PROVEEDOR}",
        "servicio": "Portal de Consulta de Trámites - Expediente N.° 0001",
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=443, ssl_context=("/cert.pem", "/key.pem"))
