# Motor Declarativo de Políticas de Seguridad SDN (ONOS + Open vSwitch)

Motor en Python que traduce políticas de seguridad declarativas (YAML) en reglas de flujo OpenFlow 1.3 sobre una arquitectura Spine-Leaf controlada por ONOS y Open vSwitch (OVS), incorporando auditoría de telemetría en tiempo real y trazabilidad criptográfica (SHA-256).

## Arquitectura del Laboratorio

* Plano de Control: Controlador SDN ONOS (172.16.10.20, API REST en puerto 8181, OpenFlow 6653).
* Plano de Datos: Topología Spine-Leaf con switches Open vSwitch (br0 en modo OpenFlow13 + RSTP habilitado para prevención de bucles).
* Switch de Aplicación (LEAF-2): of:000032a4da3ea14b (puerto de salida hacia el activo protegido: 3).
* Activos:
  * servicio-https (10.10.10.40:443): Portal HTTPS protegido.
  * entidad-aliada-1 (10.10.10.10): Cliente autorizado.
  * origen-no-autorizado-1 (10.10.10.20): Cliente bloqueado por defecto (DENY).

## Políticas Implementadas (politicas.yaml)

| ID | Protocolo / Puerto | Prioridad ALLOW | Prioridad DENY | Comportamiento |
| :--- | :--- | :---: | :---: | :--- |
| GOV-API-001 | TCP / 443 | 40100 | 40000 | Permite HTTPS solo desde 10.10.10.10 hacia 10.10.10.40; descarta el resto en TCAM. |
| GOV-ICMP-002 | ICMP | 40300 | 40200 | Permite descubrimiento ICMP solo a 10.10.10.10; oculta el servidor ante escaneos no autorizados. |

## Estructura del Proyecto

- inventario.yaml: Topología lógica, credenciales y mapeo de activos
- politicas.yaml: Reglas declarativas de control de acceso
- sdn.py: Adaptador REST hacia ONOS (OpenFlow 1.3)
- motor.py: CLI de despliegue, revocación y auditoría
- test_motor.py: Suite de pruebas unitarias
- requirements.txt: Dependencias Python
- logs/auditoria.jsonl: Historial de eventos con timestamp UTC y hash SHA-256

## Uso

    pip install -r requirements.txt
    python3 motor.py aplicar
    python3 motor.py auditar
    python3 motor.py revocar
    python3 -m unittest -v test_motor.py
