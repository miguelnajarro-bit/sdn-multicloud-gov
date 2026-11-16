import json
import os
from sdn import AdaptadorDominio


class AdaptadorAzureNSGSimulado(AdaptadorDominio):
    """Dominio C (Azure NSG - Simulado): modela prioridades numéricas y acciones Allow/Deny."""

    def __init__(self, cfg_azure: dict):
        self.nombre = "Dominio-C-Azure-NSG (Simulado)"
        self.ruta_estado = cfg_azure.get("archivo_estado", os.path.join("logs", "azure_nsg_estado.json"))
        self.prio_inicio = int(cfg_azure.get("prioridad_inicio", 100))

    def _compilar_reglas_deseadas(self, politicas_resueltas: list[dict]) -> list[dict]:
        deseadas = []
        prio = self.prio_inicio
        for pol in politicas_resueltas:
            proto = pol["protocolo"].capitalize()
            puerto = str(pol["puerto"]) if pol["protocolo"].lower() in ("tcp", "udp") else "*"

            # En Azure NSG: menor número de prioridad = mayor precedencia
            for idx, cidr in enumerate(pol["origenes_autorizados"]):
                deseadas.append({
                    "name": f"{pol['id']}-ALLOW-{idx + 1}",
                    "priority": prio,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": proto,
                    "source_address_prefix": cidr,
                    "destination_port_range": puerto,
                })
                prio += 10

            if pol["accion_por_defecto"] == "denegar":
                deseadas.append({
                    "name": f"{pol['id']}-DENY-DEFAULT",
                    "priority": prio,
                    "direction": "Inbound",
                    "access": "Deny",
                    "protocol": proto,
                    "source_address_prefix": "*",
                    "destination_port_range": puerto,
                })
                prio += 10
        return deseadas

    @staticmethod
    def _firma(r: dict) -> tuple:
        return (
            r["priority"],
            r["access"],
            r["protocol"],
            r["source_address_prefix"],
            r["destination_port_range"],
        )

    def consultar_estado(self) -> list[dict]:
        if not os.path.exists(self.ruta_estado):
            return []
        with open(self.ruta_estado, "r", encoding="utf-8") as f:
            reglas = json.load(f)
        for r in reglas:
            r["firma"] = self._firma(r)
        return reglas

    def generar_plan(self, politicas_resueltas: list[dict]) -> dict:
        actuales = self.consultar_estado()
        deseadas = self._compilar_reglas_deseadas(politicas_resueltas)

        firmas_actuales = {r["firma"]: r for r in actuales}
        firmas_deseadas = {self._firma(r): r for r in deseadas}

        instalar = [r for k, r in firmas_deseadas.items() if k not in firmas_actuales]
        eliminar = [r for k, r in firmas_actuales.items() if k not in firmas_deseadas]
        mantener = [r for k, r in firmas_deseadas.items() if k in firmas_actuales]

        return {
            "dominio": self.nombre,
            "requiere_cambios": bool(instalar or eliminar),
            "instalar": instalar,
            "eliminar": eliminar,
            "mantener": mantener,
        }

    def aplicar(self, plan: dict) -> list[dict]:
        if not plan["requiere_cambios"]:
            return [{"estado": "SIN_CAMBIOS_IDEMPOTENTE"}]

        os.makedirs(os.path.dirname(self.ruta_estado) or ".", exist_ok=True)
        finales = []
        for r in plan["mantener"] + plan["instalar"]:
            copia = {k: v for k, v in r.items() if k != "firma"}
            finales.append(copia)
        finales.sort(key=lambda x: x["priority"])

        with open(self.ruta_estado, "w", encoding="utf-8") as f:
            json.dump(finales, f, indent=2, ensure_ascii=False)

        return [{"operacion": "SYNC_NSG_SIMULADO", "total_reglas": len(finales), "status": 200}]

    def verificar(self, politicas_resueltas: list[dict]) -> dict:
        plan_post = self.generar_plan(politicas_resueltas)
        actuales = self.consultar_estado()
        return {
            "dominio": self.nombre,
            "consistente": not plan_post["requiere_cambios"],
            "reglas_activas": len(actuales),
            "detalle_reglas": actuales,
        }
