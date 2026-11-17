import argparse
import hashlib
import ipaddress
import json
import os
import sys
import time
from datetime import datetime, timezone
import yaml
from sdn import AdaptadorONOS, ErrorControladorSDN, PROTOCOLOS_IP
from aws_adaptadores import AdaptadorAWSSG, AdaptadorAWSNACL, ErrorDominioAWS
from azure_adaptador import AdaptadorAzureNSG, AdaptadorAzureNSGSimulado

RUTA_LOG = os.path.join("logs", "auditoria.jsonl")


def cargar_yaml(ruta: str) -> dict:
    with open(ruta, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def hash_archivo(ruta: str) -> str:
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        h.update(f.read())
    return h.hexdigest()[:16]


def validar_y_resolver_politicas(inv: dict, pols: dict) -> list[dict]:
    """Valida esquema, CIDR, prohíbe 0.0.0.0/0 y detecta contradicciones antes de tocar dominios."""
    activos = inv.get("activos", {})
    lista_pols = pols.get("politicas", [])
    if not lista_pols:
        raise ValueError("El archivo de políticas está vacío.")

    resueltas = []
    vistos_servicio_proto = set()

    for pol in lista_pols:
        for campo in ("id", "servicio", "protocolo", "origenes_autorizados", "accion_por_defecto"):
            if campo not in pol:
                raise ValueError(f"Política incompleta: falta el campo '{campo}'.")

        pid = pol["id"]
        servicio = pol["servicio"]
        if servicio not in activos:
            raise ValueError(f"[{pid}] Servicio '{servicio}' no registrado en inventario.yaml.")

        proto = str(pol["protocolo"]).lower()
        if proto not in PROTOCOLOS_IP:
            raise ValueError(f"[{pid}] Protocolo '{proto}' no soportado.")

        puerto = pol.get("puerto")
        if proto in ("tcp", "udp"):
            if puerto is None or not (1 <= int(puerto) <= 65535):
                raise ValueError(f"[{pid}] Puerto TCP/UDP inválido: {puerto}.")

        clave_unicidad = (servicio, proto, puerto)
        if clave_unicidad in vistos_servicio_proto:
            raise ValueError(f"[{pid}] Regla contradictoria/duplicada sobre {clave_unicidad}.")
        vistos_servicio_proto.add(clave_unicidad)

        origenes_validados = []
        for origen in pol["origenes_autorizados"]:
            try:
                red = ipaddress.ip_network(str(origen), strict=False)
            except ValueError as exc:
                raise ValueError(f"[{pid}] Origen '{origen}' no tiene formato CIDR válido.") from exc

            if red.prefixlen == 0 or str(red) == "0.0.0.0/0":
                raise ValueError(f"[{pid}] RECHAZADO POR SEGURIDAD: origen peligroso '{origen}' (0.0.0.0/0).")
            origenes_validados.append(str(red))

        if pol["accion_por_defecto"].lower() not in ("denegar", "deny"):
            raise ValueError(f"[{pid}] accion_por_defecto debe ser 'denegar'.")

        resueltas.append({
            "id": pid,
            "descripcion": pol.get("descripcion", ""),
            "servicio": servicio,
            "ip_destino": activos[servicio]["sdn_ip"],
            "protocolo": proto,
            "puerto": int(puerto) if puerto is not None else None,
            "origenes_autorizados": origenes_validados,
            "accion_por_defecto": "denegar",
        })

    return resueltas


def construir_adaptadores(inv: dict, seleccion: str) -> list:
    adaptadores = []
    if seleccion in ("sdn", "todos") and inv.get("sdn", {}).get("habilitado", True):
        adaptadores.append(AdaptadorONOS(inv["sdn"]))
    if seleccion in ("aws", "todos") and inv.get("aws", {}).get("habilitado", False):
        adaptadores.append(AdaptadorAWSSG(inv["aws"]))
        adaptadores.append(AdaptadorAWSNACL(inv["aws"]))
    if seleccion in ("azure", "todos") and inv.get("azure", {}).get("habilitado", False):
        adaptadores.append(AdaptadorAzureNSG(inv["azure"]) if inv["azure"].get("modo") == "real" else AdaptadorAzureNSGSimulado(inv["azure"]))
    if not adaptadores:
        raise ValueError(f"No hay dominios habilitados en inventario.yaml para la selección '{seleccion}'.")
    return adaptadores


def registrar_auditoria(evento: str, hash_pol: str, metricas: dict, detalle: dict | list):
    os.makedirs("logs", exist_ok=True)
    registro = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "evento": evento,
        "hash_politicas": hash_pol,
        "metricas": metricas,
        "detalle": detalle,
    }
    with open(RUTA_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(registro, ensure_ascii=False) + "\n")


def ejecutar_ciclo_multidominio(adaptadores: list, inv: dict, pols: dict, hash_pol: str, auto_aprobar: bool):
    t0 = time.perf_counter()
    politicas_resueltas = validar_y_resolver_politicas(inv, pols)
    t_val = round((time.perf_counter() - t0) * 1000, 2)

    t1 = time.perf_counter()
    planes = [(adp, adp.generar_plan(politicas_resueltas)) for adp in adaptadores]
    t_plan = round((time.perf_counter() - t1) * 1000, 2)

    hay_cambios = False
    for _, plan in planes:
        print(f"=== PLAN DE EJECUCIÓN [{plan['dominio']}] ===")
        print(f"  - Reglas a instalar : {len(plan['instalar'])}")
        print(f"  - Reglas a eliminar : {len(plan['eliminar'])}")
        print(f"  - Reglas sin cambio : {len(plan['mantener'])}")
        if plan["requiere_cambios"]:
            hay_cambios = True

    if not hay_cambios:
        print("[=] Todos los dominios evaluados ya coinciden con la política (Idempotente).")
        t_v = time.perf_counter()
        verifs = [adp.verificar(politicas_resueltas) for adp in adaptadores]
        consistentes = sum(1 for v in verifs if v["consistente"])
        t_total = round(t_val + t_plan + (time.perf_counter() - t_v) * 1000, 2)
        registrar_auditoria(
            "EJECUCION_IDEMPOTENTE",
            hash_pol,
            {
                "t_validacion_ms": t_val,
                "t_plan_ms": t_plan,
                "t_total_ms": t_total,
                "consistencia_entre_dominios": round(consistentes / len(verifs), 2),
            },
            verifs,
        )
        return

    if not auto_aprobar:
        resp = input("¿Autoriza aplicar estos planes en los dominios listados? [s/N]: ").strip().lower()
        if resp != "s":
            print("[!] Operación cancelada por el operador.")
            return

    t2 = time.perf_counter()
    resultados_app = {}
    for adp, plan in planes:
        resultados_app[plan["dominio"]] = adp.aplicar(plan)
    t_app = round((time.perf_counter() - t2) * 1000, 2)

    t3 = time.perf_counter()
    verifs = [adp.verificar(politicas_resueltas) for adp in adaptadores]
    t_ver = round((time.perf_counter() - t3) * 1000, 2)
    t_total = round(t_val + t_plan + (time.perf_counter() - t2) * 1000, 2)

    consistentes = sum(1 for v in verifs if v["consistente"])
    ratio_consistencia = round(consistentes / len(verifs), 2)

    metricas = {
        "dominios_evaluados": len(verifs),
        "dominios_consistentes": consistentes,
        "consistencia_entre_dominios": ratio_consistencia,
        "t_validacion_ms": t_val,
        "t_plan_ms": t_plan,
        "t_aplicacion_ms": t_app,
        "t_verificacion_ms": t_ver,
        "t_propagacion_total_ms": t_total,
    }

    print(f"[+] Aplicación multi-dominio completada en {t_app} ms")
    print(f"[+] Consistencia entre dominios: {consistentes}/{len(verifs)} ({ratio_consistencia * 100:.0f}%)")
    print(f"[*] Tiempo total de propagación: {t_total} ms")
    registrar_auditoria("APLICACION_POLITICAS", hash_pol, metricas, {"aplicacion": resultados_app, "verificacion": verifs})


def cmd_auditar(adaptadores: list):
    for adp in adaptadores:
        print(f"\n--- ESTADO ACTUAL: {adp.nombre} ---")
        estado = adp.consultar_estado()
        if not estado:
            print("  (Sin reglas gestionadas por el motor)")
            continue
        for item in estado:
            limpio = {k: v for k, v in item.items() if k != "firma"}
            print(f"  {limpio}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Motor Declarativo de Políticas SDN Multi-Cloud")
    parser.add_argument("comando", choices=["aplicar", "auditar", "revocar"])
    parser.add_argument("--politicas", default="politicas.yaml", help="Ruta al archivo YAML de políticas")
    parser.add_argument("--dominios", choices=["sdn", "aws", "azure", "todos"], default="todos")
    parser.add_argument("--auto-aprobar", action="store_true", help="Omitir confirmación interactiva")
    args = parser.parse_args()

    try:
        inv = cargar_yaml("inventario.yaml")
        pols = cargar_yaml(args.politicas)
        hash_pol = hash_archivo(args.politicas)
        adaptadores = construir_adaptadores(inv, args.dominios)

        if args.comando == "aplicar":
            ejecutar_ciclo_multidominio(adaptadores, inv, pols, hash_pol, args.auto_aprobar)
        elif args.comando == "auditar":
            cmd_auditar(adaptadores)
        elif args.comando == "revocar":
            for adp in adaptadores:
                if hasattr(adp, "revocar_todo"):
                    st = adp.revocar_todo()
                    print(f"[-] {adp.nombre}: reglas revocadas (HTTP {st}).")
                else:
                    plan_vacio = adp.generar_plan([])
                    adp.aplicar(plan_vacio)
                    print(f"[-] {adp.nombre}: reglas gestionadas limpiadas.")
            registrar_auditoria("REVOCACION", hash_pol, {"dominios": args.dominios}, {})
    except (ErrorControladorSDN, ErrorDominioAWS, ValueError, OSError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)
