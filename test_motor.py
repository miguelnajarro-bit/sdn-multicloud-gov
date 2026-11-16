import unittest
from unittest.mock import patch, MagicMock
from sdn import AdaptadorONOS
from motor import validar_y_resolver_politicas


class TestMotorSDN(unittest.TestCase):
    def setUp(self):
        self.cfg_sdn = {
            "controlador_url": "http://172.16.10.20:8181/onos/v1",
            "usuario": "onos",
            "clave_env": "ONOS_CLAVE",
            "device_leaf2": "of:000032a4da3ea14b",
            "puerto_salida_https": "3",
            "prioridad_base": 40000,
            "app_id": "gov.motor",
        }
        self.inv = {"activos": {"servicio-https": {"sdn_ip": "10.10.10.40"}}}
        self.adp = AdaptadorONOS(self.cfg_sdn)

    def test_rechaza_origen_peligroso_0_0_0_0(self):
        pols = {
            "politicas": [{
                "id": "BAD-01",
                "servicio": "servicio-https",
                "protocolo": "tcp",
                "puerto": 443,
                "origenes_autorizados": ["0.0.0.0/0"],
                "accion_por_defecto": "denegar",
            }]
        }
        with self.assertRaises(ValueError) as ctx:
            validar_y_resolver_politicas(self.inv, pols)
        self.assertIn("0.0.0.0/0", str(ctx.exception))

    def test_rechaza_servicio_inexistente(self):
        pols = {
            "politicas": [{
                "id": "BAD-02",
                "servicio": "portal-fantasma",
                "protocolo": "tcp",
                "puerto": 443,
                "origenes_autorizados": ["10.10.10.10/32"],
                "accion_por_defecto": "denegar",
            }]
        }
        with self.assertRaises(ValueError):
            validar_y_resolver_politicas(self.inv, pols)

    def test_normalizacion_hex_onos_e_idempotencia(self):
        pols = {
            "politicas": [{
                "id": "GOV-API-001",
                "servicio": "servicio-https",
                "protocolo": "tcp",
                "puerto": 443,
                "origenes_autorizados": ["10.10.10.10/32"],
                "accion_por_defecto": "denegar",
            }]
        }
        resueltas = validar_y_resolver_politicas(self.inv, pols)
        # Simula respuesta de ONOS con 0x800 en lugar de 0x0800
        estado_simulado = [
            {
                "flow_id": "1",
                "priority": 40100,
                "state": "ADDED",
                "accion": "ALLOW",
                "firma": (40100, "ALLOW", (('ETH_TYPE', '0x800'), ('IPV4_DST', '10.10.10.40/32'), ('IPV4_SRC', '10.10.10.10/32'), ('IP_PROTO', '6'), ('TCP_DST', '443'))),
            },
            {
                "flow_id": "2",
                "priority": 40000,
                "state": "ADDED",
                "accion": "DENY",
                "firma": (40000, "DENY", (('ETH_TYPE', '0x800'), ('IPV4_DST', '10.10.10.40/32'), ('IP_PROTO', '6'), ('TCP_DST', '443'))),
            },
        ]
        with patch.object(self.adp, "consultar_estado", return_value=estado_simulado):
            plan = self.adp.generar_plan(resueltas)
            self.assertFalse(plan["requiere_cambios"])
            self.assertEqual(len(plan["mantener"]), 2)

    def test_compilacion_bandas_prioridad(self):
        pols = {
            "politicas": [
                {
                    "id": "P1",
                    "servicio": "servicio-https",
                    "protocolo": "tcp",
                    "puerto": 443,
                    "origenes_autorizados": ["10.10.10.10/32"],
                    "accion_por_defecto": "denegar",
                },
                {
                    "id": "P2",
                    "servicio": "servicio-https",
                    "protocolo": "icmp",
                    "origenes_autorizados": ["10.10.10.10/32"],
                    "accion_por_defecto": "denegar",
                },
            ]
        }
        reglas = self.adp._compilar_reglas_deseadas(validar_y_resolver_politicas(self.inv, pols))
        prios = [r["priority"] for r in reglas]
        self.assertEqual(prios, [40100, 40000, 40300, 40200])


if __name__ == "__main__":
    unittest.main()
