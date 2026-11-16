import os
import time
from abc import ABC, abstractmethod
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException

PROTOCOLOS_IP = {"icmp": 1, "tcp": 6, "udp": 17}


class ErrorControladorSDN(Exception):
    """Error controlado en comunicación o estado del dominio SDN."""


class AdaptadorDominio(ABC):
    """Interfaz común exigida para todo dominio (SDN, AWS-SG, AWS-NACL, Azure)."""

    @abstractmethod
    def consultar_estado(self) -> list[dict]:
        pass

    @abstractmethod
    def generar_plan(self, politicas_resueltas: list[dict]) -> dict:
        pass

    @abstractmethod
    def aplicar(self, plan: dict) -> list[dict]:
        pass

    @abstractmethod
    def verificar(self, politicas_resueltas: list[dict]) -> dict:
        pass


class AdaptadorONOS(AdaptadorDominio):
    def __init__(self, cfg_sdn: dict):
        self.nombre = "Dominio-A-SDN (ONOS/OVS)"
        self.url = cfg_sdn["controlador_url"].rstrip("/")
        self.auth = HTTPBasicAuth(
            cfg_sdn["usuario"],
            os.environ.get(cfg_sdn["clave_env"], "rocks"),
        )
        self.device_id = cfg_sdn["device_leaf2"]
        self.puerto_salida = str(cfg_sdn["puerto_salida_https"])
        self.prioridad_base = int(cfg_sdn.get("prioridad_base", 40000))
        self.app_id = cfg_sdn.get("app_id", "gov.motor")

    def _peticion(self, metodo: str, ruta: str, **kwargs) -> requests.Response:
        try:
            resp = requests.request(
                metodo,
                f"{self.url}{ruta}",
                auth=self.auth,
                timeout=5,
                **kwargs,
            )
            resp.raise_for_status()
            return resp
        except RequestException as exc:
            raise ErrorControladorSDN(f"Fallo API ONOS ({metodo} {ruta}): {exc}") from exc

    def _construir_criterios(
        self, ip_dst: str, protocolo: str, puerto: int | None = None, ip_src_cidr: str | None = None
    ) -> list[dict]:
        proto = protocolo.lower()
        criterios = [{"type": "ETH_TYPE", "ethType": "0x0800"}]
        if ip_src_cidr:
            criterios.append({"type": "IPV4_SRC", "ip": ip_src_cidr})
        criterios.append({"type": "IPV4_DST", "ip": f"{ip_dst}/32"})
        criterios.append({"type": "IP_PROTO", "protocol": PROTOCOLOS_IP[proto]})
        if puerto is not None:
            if proto == "tcp":
                criterios.append({"type": "TCP_DST", "tcpPort": int(puerto)})
            elif proto == "udp":
                criterios.append({"type": "UDP_DST", "udpPort": int(puerto)})
        return criterios

    def _compilar_reglas_deseadas(self, politicas_resueltas: list[dict]) -> list[dict]:
        deseadas = []
        for idx_pol, pol in enumerate(politicas_resueltas):
            offset = idx_pol * 200
            prio_deny = self.prioridad_base + offset
            prio_allow = prio_deny + 100
            proto = pol["protocolo"].lower()
            puerto = pol.get("puerto") if proto in ("tcp", "udp") else None

            for idx_src, cidr in enumerate(pol["origenes_autorizados"]):
                deseadas.append({
                    "id_politica": pol["id"],
                    "accion": "ALLOW",
                    "priority": prio_allow + idx_src,
                    "criterios": self._construir_criterios(pol["ip_destino"], proto, puerto, cidr),
                    "puerto_salida": self.puerto_salida,
                })

            if pol["accion_por_defecto"] == "denegar":
                deseadas.append({
                    "id_politica": pol["id"],
                    "accion": "DENY",
                    "priority": prio_deny,
                    "criterios": self._construir_criterios(pol["ip_destino"], proto, puerto, None),
                    "puerto_salida": None,
                })
        return deseadas

    @staticmethod
    def _firma_criterios(criterios: list[dict]) -> tuple:
        items = []
        for c in criterios:
            val = c.get("ip") or c.get("tcpPort") or c.get("udpPort") or c.get("protocol") or c.get("ethType")
            s_val = str(val).lower()
            if s_val.startswith("0x"):
                s_val = hex(int(s_val, 16))
            items.append((c["type"], s_val))
        return tuple(sorted(items))

    def consultar_estado(self) -> list[dict]:
        resp = self._peticion("GET", f"/flows/{self.device_id}")
        flujos = [f for f in resp.json().get("flows", []) if f.get("appId") == self.app_id]
        estado = []
        for f in flujos:
            insts = f.get("treatment", {}).get("instructions", [])
            tiene_output = any(i.get("type") == "OUTPUT" for i in insts)
            accion = "ALLOW" if tiene_output else "DENY"
            estado.append({
                "flow_id": f["id"],
                "priority": f["priority"],
                "state": f["state"],
                "accion": accion,
                "packets": f.get("packets", 0),
                "bytes": f.get("bytes", 0),
                "criterios": f["selector"]["criteria"],
                "firma": (f["priority"], accion, self._firma_criterios(f["selector"]["criteria"])),
            })
        return estado

    def generar_plan(self, politicas_resueltas: list[dict]) -> dict:
        actuales = self.consultar_estado()
        deseadas = self._compilar_reglas_deseadas(politicas_resueltas)

        firmas_actuales = {r["firma"]: r for r in actuales}
        firmas_deseadas = {
            (r["priority"], r["accion"], self._firma_criterios(r["criterios"])): r for r in deseadas
        }

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

        resultados = []
        for regla_del in plan["eliminar"]:
            self._peticion("DELETE", f"/flows/{self.device_id}/{regla_del['flow_id']}")
            resultados.append({"operacion": "ELIMINAR", "priority": regla_del["priority"], "status": 204})

        for regla_add in plan["instalar"]:
            treatment = (
                {"instructions": [{"type": "OUTPUT", "port": regla_add["puerto_salida"]}]}
                if regla_add["accion"] == "ALLOW"
                else {"instructions": []}
            )
            payload = {
                "priority": regla_add["priority"],
                "timeout": 0,
                "isPermanent": True,
                "deviceId": self.device_id,
                "treatment": treatment,
                "selector": {"criteria": regla_add["criterios"]},
            }
            r = self._peticion("POST", f"/flows/{self.device_id}?appId={self.app_id}", json=payload)
            resultados.append({
                "operacion": "INSTALAR",
                "politica": regla_add["id_politica"],
                "accion": regla_add["accion"],
                "priority": regla_add["priority"],
                "status": r.status_code,
            })
        return resultados

    def verificar(self, politicas_resueltas: list[dict], max_espera_s: float = 2.0) -> dict:
        limite = time.perf_counter() + max_espera_s
        actuales = self.consultar_estado()
        while time.perf_counter() < limite:
            if actuales and all(f["state"] == "ADDED" for f in actuales):
                break
            time.sleep(0.1)
            actuales = self.consultar_estado()

        plan_post = self.generar_plan(politicas_resueltas)
        todos_added = bool(actuales) and all(f["state"] == "ADDED" for f in actuales)
        consistente = (not plan_post["requiere_cambios"]) and todos_added
        return {
            "dominio": self.nombre,
            "consistente": consistente,
            "reglas_activas": len(actuales),
            "detalle_flujos": actuales,
        }

    def revocar_todo(self) -> int:
        resp = self._peticion("DELETE", f"/flows/application/{self.app_id}")
        return resp.status_code
