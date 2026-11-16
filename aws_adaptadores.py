import boto3
from botocore.exceptions import BotoCoreError, ClientError
from sdn import AdaptadorDominio, PROTOCOLOS_IP


class ErrorDominioAWS(Exception):
    """Error controlado en comunicación o permisos del dominio AWS."""


class AdaptadorAWSSG(AdaptadorDominio):
    """Adaptador stateful para AWS Security Group (solo reglas de permiso)."""

    def __init__(self, cfg_aws: dict):
        self.nombre = "Dominio-B1-AWS-SG (Stateful)"
        self.region = cfg_aws["region"]
        self.sg_id = cfg_aws["security_group_id"]
        self.puertos_protegidos = set(cfg_aws.get("puertos_admin_protegidos", [22]))
        self.ec2 = boto3.client("ec2", region_name=self.region)

    def _compilar_reglas_deseadas(self, politicas_resueltas: list[dict]) -> list[dict]:
        deseadas = []
        for pol in politicas_resueltas:
            proto = pol["protocolo"].lower()
            if proto == "icmp":
                from_p, to_p = -1, -1
            else:
                from_p = to_p = int(pol["puerto"])

            for cidr in pol["origenes_autorizados"]:
                deseadas.append({
                    "id_politica": pol["id"],
                    "proto": proto,
                    "from_port": from_p,
                    "to_port": to_p,
                    "cidr": cidr,
                })
        return deseadas

    def consultar_estado(self) -> list[dict]:
        try:
            resp = self.ec2.describe_security_group_rules(
                Filters=[{"Name": "group-id", "Values": [self.sg_id]}]
            )
        except (BotoCoreError, ClientError) as exc:
            raise ErrorDominioAWS(f"Fallo consultando SG {self.sg_id}: {exc}") from exc

        actuales = []
        for r in resp.get("SecurityGroupRules", []):
            if r.get("IsEgress", False):
                continue
            proto = str(r.get("IpProtocol", "")).lower()
            from_p = int(r.get("FromPort", -1))
            to_p = int(r.get("ToPort", -1))
            cidr = r.get("CidrIpv4")
            if not cidr:
                continue
            # Guardia de gestión: ignorar reglas administrativas (ej. SSH puerto 22)
            if proto == "tcp" and from_p in self.puertos_protegidos:
                continue
            actuales.append({
                "rule_id": r["SecurityGroupRuleId"],
                "proto": proto,
                "from_port": from_p,
                "to_port": to_p,
                "cidr": cidr,
                "firma": (proto, from_p, to_p, cidr),
            })
        return actuales

    def generar_plan(self, politicas_resueltas: list[dict]) -> dict:
        actuales = self.consultar_estado()
        deseadas = self._compilar_reglas_deseadas(politicas_resueltas)

        firmas_actuales = {r["firma"]: r for r in actuales}
        firmas_deseadas = {
            (r["proto"], r["from_port"], r["to_port"], r["cidr"]): r for r in deseadas
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
        try:
            if plan["eliminar"]:
                ids_borrar = [r["rule_id"] for r in plan["eliminar"]]
                self.ec2.revoke_security_group_ingress(
                    GroupId=self.sg_id,
                    SecurityGroupRuleIds=ids_borrar,
                )
                for r in plan["eliminar"]:
                    resultados.append({"operacion": "ELIMINAR", "cidr": r["cidr"], "proto": r["proto"], "status": 200})

            if plan["instalar"]:
                permisos = []
                for r in plan["instalar"]:
                    permisos.append({
                        "IpProtocol": r["proto"],
                        "FromPort": r["from_port"],
                        "ToPort": r["to_port"],
                        "IpRanges": [{"CidrIp": r["cidr"], "Description": f"gov.motor:{r['id_politica']}"}],
                    })
                self.ec2.authorize_security_group_ingress(
                    GroupId=self.sg_id,
                    IpPermissions=permisos,
                )
                for r in plan["instalar"]:
                    resultados.append({
                        "operacion": "INSTALAR",
                        "politica": r["id_politica"],
                        "cidr": r["cidr"],
                        "proto": r["proto"],
                        "status": 200,
                    })
        except (BotoCoreError, ClientError) as exc:
            raise ErrorDominioAWS(f"Fallo aplicando cambios en SG {self.sg_id}: {exc}") from exc

        return resultados

    def verificar(self, politicas_resueltas: list[dict]) -> dict:
        plan_post = self.generar_plan(politicas_resueltas)
        actuales = self.consultar_estado()
        return {
            "dominio": self.nombre,
            "consistente": not plan_post["requiere_cambios"],
            "reglas_activas": len(actuales),
            "detalle_reglas": actuales,
        }


class AdaptadorAWSNACL(AdaptadorDominio):
    """Adaptador stateless para AWS Network ACL (reglas numeradas Allow/Deny + retorno efímero)."""

    def __init__(self, cfg_aws: dict):
        self.nombre = "Dominio-B2-AWS-NACL (Stateless)"
        self.region = cfg_aws["region"]
        self.nacl_id = cfg_aws["network_acl_id"]
        self.rango_min = int(cfg_aws.get("nacl_rango_inicio", 100))
        self.rango_max = int(cfg_aws.get("nacl_rango_fin", 299))
        self.ec2 = boto3.client("ec2", region_name=self.region)

    def _compilar_reglas_deseadas(self, politicas_resueltas: list[dict]) -> list[dict]:
        deseadas = []
        regla_num = self.rango_min

        for pol in politicas_resueltas:
            proto_str = pol["protocolo"].lower()
            proto_num = str(PROTOCOLOS_IP[proto_str])
            puerto = int(pol["puerto"]) if proto_str in ("tcp", "udp") else None

            # 1. Reglas ALLOW de entrada para orígenes autorizados (números menores = mayor precedencia)
            for cidr in pol["origenes_autorizados"]:
                deseadas.append({
                    "id_politica": pol["id"],
                    "rule_number": regla_num,
                    "egress": False,
                    "action": "allow",
                    "protocol": proto_num,
                    "cidr": cidr,
                    "from_port": puerto,
                    "to_port": puerto,
                })
                regla_num += 1

            # 2. Regla DENY explícita de entrada para el resto (número mayor)
            if pol["accion_por_defecto"] == "denegar":
                deseadas.append({
                    "id_politica": pol["id"],
                    "rule_number": regla_num,
                    "egress": False,
                    "action": "deny",
                    "protocol": proto_num,
                    "cidr": "0.0.0.0/0",
                    "from_port": puerto,
                    "to_port": puerto,
                })
                regla_num += 1

        # 3. Retorno stateless explícito en Egress (puertos efímeros TCP 1024-65535)
        deseadas.append({
            "id_politica": "RETORNO-EFIMERO",
            "rule_number": regla_num,
            "egress": True,
            "action": "allow",
            "protocol": "6",
            "cidr": "0.0.0.0/0",
            "from_port": 1024,
            "to_port": 65535,
        })
        return deseadas

    @staticmethod
    def _firma(r: dict) -> tuple:
        return (
            r["rule_number"],
            r["egress"],
            r["action"],
            str(r["protocol"]),
            r["cidr"],
            r.get("from_port"),
            r.get("to_port"),
        )

    def consultar_estado(self) -> list[dict]:
        try:
            resp = self.ec2.describe_network_acls(NetworkAclIds=[self.nacl_id])
        except (BotoCoreError, ClientError) as exc:
            raise ErrorDominioAWS(f"Fallo consultando NACL {self.nacl_id}: {exc}") from exc

        entradas = resp["NetworkAcls"][0].get("Entries", [])
        actuales = []
        for e in entradas:
            num = int(e["RuleNumber"])
            # Guardia de gestión: solo gestiona el rango [100..299], jamás toca reglas admin (<100) ni default (32767)
            if not (self.rango_min <= num <= self.rango_max):
                continue
            pr = e.get("PortRange", {})
            item = {
                "rule_number": num,
                "egress": bool(e["Egress"]),
                "action": e["RuleAction"].lower(),
                "protocol": str(e["Protocol"]),
                "cidr": e["CidrBlock"],
                "from_port": pr.get("From"),
                "to_port": pr.get("To"),
            }
            item["firma"] = self._firma(item)
            actuales.append(item)
        return actuales

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

        resultados = []
        try:
            for r in plan["eliminar"]:
                self.ec2.delete_network_acl_entry(
                    NetworkAclId=self.nacl_id,
                    RuleNumber=r["rule_number"],
                    Egress=r["egress"],
                )
                resultados.append({"operacion": "ELIMINAR", "rule_number": r["rule_number"], "egress": r["egress"]})

            for r in plan["instalar"]:
                params = {
                    "NetworkAclId": self.nacl_id,
                    "RuleNumber": r["rule_number"],
                    "Protocol": r["protocol"],
                    "RuleAction": r["action"],
                    "Egress": r["egress"],
                    "CidrBlock": r["cidr"],
                }
                if r.get("from_port") is not None and r.get("to_port") is not None:
                    params["PortRange"] = {"From": int(r["from_port"]), "To": int(r["to_port"])}
                if r["protocol"] == "1":
                    params["IcmpTypeCode"] = {"Type": -1, "Code": -1}

                self.ec2.create_network_acl_entry(**params)
                resultados.append({
                    "operacion": "INSTALAR",
                    "politica": r["id_politica"],
                    "rule_number": r["rule_number"],
                    "action": r["action"],
                    "egress": r["egress"],
                })
        except (BotoCoreError, ClientError) as exc:
            raise ErrorDominioAWS(f"Fallo aplicando cambios en NACL {self.nacl_id}: {exc}") from exc

        return resultados

    def verificar(self, politicas_resueltas: list[dict]) -> dict:
        plan_post = self.generar_plan(politicas_resueltas)
        actuales = self.consultar_estado()
        return {
            "dominio": self.nombre,
            "consistente": not plan_post["requiere_cambios"],
            "reglas_activas": len(actuales),
            "detalle_reglas": actuales,
        }
