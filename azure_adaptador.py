import json
import os
from sdn import AdaptadorDominio


class ErrorDominioAzure(Exception):
    """Error controlado en la comunicación con Azure Resource Manager."""


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


class AdaptadorAzureNSG(AdaptadorAzureNSGSimulado):
    """Dominio C (Azure NSG - Real): gestiona reglas inbound vía Azure Resource Manager."""

    def __init__(self, cfg_azure: dict):
        super().__init__(cfg_azure)
        self.nombre = "Dominio-C-Azure-NSG (Real)"
        self.resource_group = cfg_azure.get("resource_group", "rg-multicloud-gov")
        self.nsg_name = cfg_azure.get("nsg_name", "nsg-portal-azure")
        self.puertos_admin = {str(p) for p in cfg_azure.get("puertos_admin_protegidos", [22])}

        sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID") or cfg_azure.get("subscription_id")
        if not sub_id:
            raise ErrorDominioAzure("Falta AZURE_SUBSCRIPTION_ID en variables de entorno.")

        try:
            from azure.identity import EnvironmentCredential
            from azure.mgmt.network import NetworkManagementClient
        except ImportError as exc:
            raise ErrorDominioAzure("SDK de Azure no instalado (azure-identity / azure-mgmt-network).") from exc

        try:
            cred = EnvironmentCredential()
            self.client = NetworkManagementClient(cred, sub_id)
        except Exception as exc:
            raise ErrorDominioAzure(f"Error inicializando credenciales de Azure: {exc}") from exc

    def consultar_estado(self) -> list[dict]:
        try:
            nsg = self.client.network_security_groups.get(self.resource_group, self.nsg_name)
        except Exception as exc:
            raise ErrorDominioAzure(f"No se pudo leer NSG '{self.nsg_name}': {exc}") from exc

        reglas = []
        for r in (nsg.security_rules or []):
            if (r.direction or "").lower() != "inbound":
                continue
            puerto = str(r.destination_port_range or "*")
            # Proteger regla SSH de administración si existe
            if puerto in self.puertos_admin and r.name and not r.name.startswith("GOV-"):
                continue
            item = {
                "name": r.name,
                "priority": int(r.priority),
                "direction": str(getattr(r.direction, "value", r.direction)),
                "access": str(getattr(r.access, "value", r.access)),
                "protocol": str(getattr(r.protocol, "value", r.protocol)),
                "source_address_prefix": r.source_address_prefix or "*",
                "destination_port_range": puerto,
            }
            item["firma"] = self._firma(item)
            reglas.append(item)
        return sorted(reglas, key=lambda x: x["priority"])

    def aplicar(self, plan: dict) -> list[dict]:
        if not plan["requiere_cambios"]:
            return [{"estado": "SIN_CAMBIOS_IDEMPOTENTE"}]

        resultados = []
        try:
            # 1. Eliminar reglas obsoletas o fuera de política
            for r in plan["eliminar"]:
                poller = self.client.security_rules.begin_delete(
                    self.resource_group,
                    self.nsg_name,
                    r["name"],
                )
                poller.result()
                resultados.append({
                    "operacion": "DELETE_NSG_RULE",
                    "regla": r["name"],
                    "priority": r["priority"],
                    "status": 200,
                })

            # 2. Crear o actualizar reglas deseadas
            from azure.mgmt.network.models import SecurityRule

            for r in plan["instalar"]:
                params = SecurityRule(
                    protocol=r["protocol"],
                    source_port_range="*",
                    destination_port_range=r["destination_port_range"],
                    source_address_prefix=r["source_address_prefix"],
                    destination_address_prefix="*",
                    access=r["access"],
                    priority=int(r["priority"]),
                    direction="Inbound",
                    description="Gestionado declarativamente por motor-sdn",
                )
                poller = self.client.security_rules.begin_create_or_update(
                    self.resource_group,
                    self.nsg_name,
                    r["name"],
                    params,
                )
                poller.result()
                resultados.append({
                    "operacion": "UPSERT_NSG_RULE",
                    "regla": r["name"],
                    "priority": r["priority"],
                    "status": 200,
                })
        except Exception as exc:
            raise ErrorDominioAzure(f"Fallo aplicando reglas en Azure NSG '{self.nsg_name}': {exc}") from exc

        return resultados
