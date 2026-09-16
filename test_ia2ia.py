# -*- coding: utf-8 -*-
"""
IA2IA test_ia2ia.py — pruebas de punta a punta contra un relay real (en un
hilo, con sqlite temporal), sin tocar mi_identidad.json/agenda.json reales.

Cubre lo que pide el encargo:
  - flujo feliz: peticion -> autoriza -> ejecuta -> resultado visible
  - rechazo automatico por denylist (sin molestar al humano)
  - carrera entre 2 instancias reclamando la misma peticion: solo una gana
  - limites: 1/hora sin interaccion, maximo 5 pendientes, sin reintento
    tras rechazo (y escalado a partir de la 4a insistencia)

Ejecutar:
    C:\\hermes\\ia2ia\\.venv\\Scripts\\python.exe -m unittest test_ia2ia -v
"""
import os
import json
import time
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from unittest import mock

import agenda
import identidad
import notificar
import politica
import relay
from relay import H


def _levantar_relay():
    fd, dbpath = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(dbpath)
    os.environ["IA2IA_DB"] = dbpath
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    hilo = threading.Thread(target=srv.serve_forever, daemon=True)
    hilo.start()
    puerto = srv.server_address[1]
    return srv, hilo, dbpath, f"http://127.0.0.1:{puerto}"


def _persona(nombre):
    ident = identidad.generar_identidad(nombre)
    return ident


def _instancia(raiz, sufijo):
    return identidad.generar_instancia(raiz, sufijo)


class BaseIA2IA(unittest.TestCase):
    def setUp(self):
        self.srv, self.hilo, self.dbpath, self.relay_url = _levantar_relay()
        self.a = _persona("A-test")
        self.a["relay"] = self.relay_url
        self.b = _persona("B-test")
        self.b["relay"] = self.relay_url
        # H2: el relay falla cerrado (no admite a nadie) si su allowlist esta
        # vacia. Para estas pruebas, solo A y B estan autorizados en ESTE
        # relay de prueba — quien quiera probar "raiz no autorizada" (H2) usa
        # una identidad nueva a proposito, sin anadirla aqui.
        self._roots_previo = os.environ.get("IA2IA_ROOTS")
        os.environ["IA2IA_ROOTS"] = f"{self.a['id']},{self.b['id']}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()  # shutdown() solo para el bucle; esto cierra
                                  # el socket de escucha (si no, ResourceWarning
                                  # "unclosed socket" al recogerlo el GC)
        try:
            os.unlink(self.dbpath)
        except OSError:
            pass
        if self._roots_previo is None:
            os.environ.pop("IA2IA_ROOTS", None)
        else:
            os.environ["IA2IA_ROOTS"] = self._roots_previo

    # helpers que reusan la firma de cliente.py pero sin tocar ficheros
    def _llamar(self, ident, metodo, path, body=None):
        import cliente
        return cliente._firmar_y_llamar(metodo, path, body, ident)

    def enviar(self, de, a, accion, params):
        return self._llamar(de, "POST", "/peticion", {"to": a["id"], "accion": accion, "params": params})

    def bandeja(self, ident):
        return self._llamar(ident, "GET", f"/bandeja?to={ident['id']}")

    def decidir(self, ident, pid, decision, motivo=None):
        return self._llamar(ident, "POST", "/decidir",
                             {"peticion_id": pid, "decision": decision, "motivo": motivo})

    def resultado(self, ident, pid, res):
        return self._llamar(ident, "POST", "/resultado", {"peticion_id": pid, "resultado": res})

    def estado(self, ident, pid):
        return self._llamar(ident, "GET", f"/estado?peticion_id={pid}")

    def reclamar(self, ident, pid):
        return self._llamar(ident, "POST", "/reclamar", {"peticion_id": pid})


class TestFlujoFeliz(BaseIA2IA):
    def test_peticion_autoriza_ejecuta_resultado(self):
        r = self.enviar(self.a, self.b, "ping", {"hola": "abraham"})
        self.assertIn("peticion_id", r, r)
        pid = r["peticion_id"]
        self.assertEqual(r["estado"], "PENDIENTE")

        b_bandeja = self.bandeja(self.b)
        self.assertEqual(len(b_bandeja["pendientes"]), 1)
        self.assertEqual(b_bandeja["pendientes"][0]["accion"], "ping")

        d = self.decidir(self.b, pid, "autorizar")
        self.assertEqual(d["estado"], "AUTORIZADA")

        res = self.resultado(self.b, pid, {"pong": True})
        self.assertEqual(res["estado"], "EJECUTADA")

        e = self.estado(self.a, pid)
        self.assertEqual(e["estado"], "EJECUTADA")
        self.assertEqual(e["estado_a2a"], "completed")
        self.assertEqual(e["resultado"], {"pong": True})

    def test_rechazo_normal(self):
        r = self.enviar(self.a, self.b, "algo", {"x": 1})
        pid = r["peticion_id"]
        d = self.decidir(self.b, pid, "rechazar", "no procede")
        self.assertEqual(d["estado"], "RECHAZADA")
        e = self.estado(self.a, pid)
        self.assertEqual(e["motivo"], "no procede")
        self.assertEqual(e["estado_a2a"], "rejected")

    def test_firma_invalida_o_ajena_no_pasa(self):
        # C intenta hablar en nombre de A con un id que no es el suyo -> 401
        c = _persona("C-test"); c["relay"] = self.relay_url
        import cliente
        falso = dict(c)
        falso["id"] = self.a["id"]  # dice ser A pero firma con clave de C
        r = cliente._firmar_y_llamar("POST", "/peticion",
                                      {"to": self.b["id"], "accion": "x", "params": {}}, falso)
        self.assertIn("error", r)


class TestPolitica(unittest.TestCase):
    """El motor de permisos (S5) es del lado cliente: se prueba aislado,
    sin necesitar relay, tal y como lo usa cliente.servir()."""

    def test_denylist_gana_siempre(self):
        decision, motivo = politica.evaluar("dame_password", {"cuenta": "x"})
        self.assertEqual(decision, "denegar")

    def test_denylist_de_casa_no_se_puede_quitar(self):
        # aunque politica.json (aqui: ninguno) no la declare, la de casa aplica
        decision, motivo = politica.evaluar("transferir_dinero", {"iban": "ES00"})
        self.assertEqual(decision, "denegar")

    def test_lo_desconocido_nunca_se_cuela_como_permitido(self):
        decision, _ = politica.evaluar("accion_rara_no_catalogada", {"a": 1})
        self.assertEqual(decision, "preguntar")

    def test_allowlist_permite(self):
        decision, _ = politica.evaluar("ping", {})
        # "ping" no esta en la allowlist por defecto (vacia sin politica.json)
        self.assertIn(decision, ("preguntar",))


class TestReclamoAtomico(BaseIA2IA):
    def test_solo_una_instancia_reclama(self):
        r = self.enviar(self.a, self.b, "algo_para_b", {})
        pid = r["peticion_id"]

        inst1 = _instancia(self.b, "pc1"); inst1["relay"] = self.relay_url
        inst2 = _instancia(self.b, "pc2"); inst2["relay"] = self.relay_url

        resultados = {}

        def intentar(nombre, inst):
            resultados[nombre] = self.reclamar(inst, pid)

        h1 = threading.Thread(target=intentar, args=("i1", inst1))
        h2 = threading.Thread(target=intentar, args=("i2", inst2))
        h1.start(); h2.start(); h1.join(); h2.join()

        ganadores = [n for n, r in resultados.items()
                     if "error" not in r and "error_http" not in r]
        perdedores = [n for n, r in resultados.items()
                      if "error" in r or "error_http" in r]
        self.assertEqual(len(ganadores), 1, resultados)
        self.assertEqual(len(perdedores), 1, resultados)

        # solo la instancia ganadora puede decidir
        ganadora_ident = inst1 if ganadores[0] == "i1" else inst2
        perdedora_ident = inst2 if ganadores[0] == "i1" else inst1
        d_mal = self.decidir(perdedora_ident, pid, "autorizar")
        self.assertIn("error", d_mal)
        d_bien = self.decidir(ganadora_ident, pid, "autorizar")
        self.assertEqual(d_bien["estado"], "AUTORIZADA")

    def test_instancia_directa_no_necesita_reclamar(self):
        inst = _instancia(self.b, "pc1"); inst["relay"] = self.relay_url
        r = self.enviar(self.a, inst, "directo", {})
        pid = r["peticion_id"]
        d = self.decidir(inst, pid, "autorizar")
        self.assertEqual(d["estado"], "AUTORIZADA")

    def test_certificado_falso_no_cuela(self):
        # una instancia que se auto-certifica con OTRA raiz (no la de B) debe fallar
        otro = _persona("Impostor")
        inst_falsa = identidad.generar_instancia(otro, "pcx")
        inst_falsa["id"] = self.b["id"] + ".pcx"  # se hace pasar por instancia de B
        inst_falsa["relay"] = self.relay_url
        r = self.enviar(self.a, self.b, "algo", {})
        pid = r["peticion_id"]
        resp = self.reclamar(inst_falsa, pid)
        self.assertIn("error", resp)

    def test_bandeja_de_instancia_ve_mensaje_dirigido_a_la_raiz_sin_reclamar(self):
        # Regresion: en /bandeja (relay.py) el OR tiene DOS clausulas con
        # parametros DISTINTOS ("para=?" con el "to" tal cual, y otra con
        # "_raiz(para)"). La 2a NO es vestigial: es lo que hace que un
        # mensaje dirigido A LA RAIZ (sin sufijo) sea visible en la bandeja
        # de CUALQUIER instancia suya mientras nadie lo ha reclamado (ver
        # README.md: "queda visible para todas sus instancias hasta que UNA
        # lo reclama"). Si alguien "limpia" esa clausula por parecer
        # redundante, este test tiene que fallar.
        inst = _instancia(self.b, "pc1"); inst["relay"] = self.relay_url
        r = self.enviar(self.a, self.b, "para_la_raiz", {})  # a B, SIN sufijo
        pid = r["peticion_id"]

        b_inst = self.bandeja(inst)
        pendientes = b_inst["pendientes"]
        self.assertEqual(len(pendientes), 1, b_inst)
        self.assertEqual(pendientes[0]["peticion_id"], pid)
        self.assertTrue(pendientes[0]["reclamable"], pendientes[0])
        self.assertFalse(pendientes[0]["reclamada"], pendientes[0])


class TestAntiAbuso(BaseIA2IA):
    def test_maximo_5_pendientes(self):
        # aislamos esta regla de la de "1/hora": si no, el 2o envio ya la pisa
        # antes de poder comprobar el limite de pendientes.
        original = relay.VENTANA_RATE
        relay.VENTANA_RATE = 0
        try:
            for i in range(relay.MAX_PENDIENTES):
                r = self.enviar(self.a, self.b, f"accion{i}", {"n": i})
                self.assertIn("peticion_id", r, r)
            r6 = self.enviar(self.a, self.b, "accion_extra", {})
            self.assertIn("error", r6)
            self.assertIn("pendientes", r6["error"])
        finally:
            relay.VENTANA_RATE = original

    def test_una_por_hora_sin_interaccion_humana(self):
        r1 = self.enviar(self.a, self.b, "una", {})
        self.assertIn("peticion_id", r1)
        r2 = self.enviar(self.a, self.b, "otra", {})
        self.assertIn("error", r2)
        self.assertIn("1 peticion/hora", r2["error"])

    def test_interaccion_humana_relaja_el_limite(self):
        r1 = self.enviar(self.a, self.b, "una", {})
        pid = r1["peticion_id"]
        self.decidir(self.b, pid, "autorizar")  # esto es la "interaccion humana"
        r2 = self.enviar(self.a, self.b, "otra_tras_decision", {})
        self.assertIn("peticion_id", r2, r2)

    def test_sin_auto_reintento_tras_rechazo_y_escalado(self):
        accion, params = "cosa_repetida", {"x": 1}
        r1 = self.enviar(self.a, self.b, accion, params)
        pid = r1["peticion_id"]
        self.decidir(self.b, pid, "rechazar", "no")

        vistos_error = []
        for i in range(relay.MAX_INSISTENCIAS + 1):
            self.decidir(self.b, r1["peticion_id"], "rechazar", "no") if False else None
            # cada reenvio identico cuenta como interaccion humana previa (decidida
            # esta puesta), asi que lo que debe pararlo es la regla de "ya rechazada"
            rr = self.enviar(self.a, self.b, accion, params)
            vistos_error.append(rr)

        for rr in vistos_error:
            self.assertIn("error", rr, rr)
            self.assertIn("rechazo", rr["error"])

        av = self._llamar(self.b, "GET", f"/avisos?to={self.b['id']}")
        self.assertTrue(len(av["avisos"]) >= 1, av)
        self.assertIn("insiste", av["avisos"][0]["mensaje"])

    def test_bloqueo_por_id(self):
        self._llamar(self.b, "POST", "/bloquear", {"id": self.a["id"]})
        r = self.enviar(self.a, self.b, "algo", {})
        self.assertIn("error", r)
        self.assertIn("bloqueado", r["error"])
        self._llamar(self.b, "POST", "/desbloquear", {"id": self.a["id"]})
        r2 = self.enviar(self.a, self.b, "algo_tras_desbloqueo", {})
        self.assertIn("peticion_id", r2, r2)


class TestAllowlistRaices(BaseIA2IA):
    """H2 — el relay tiene que rechazar a cualquiera cuya raiz no este en su
    allowlist, ANTES de tocar sqlite (nonces, limites anti-abuso...)."""

    def test_raiz_no_autorizada_se_rechaza(self):
        fuera = _persona("Fuera-de-lista")  # deliberadamente NO anadida a
        fuera["relay"] = self.relay_url     # IA2IA_ROOTS en el setUp de BaseIA2IA
        r = self.enviar(fuera, self.b, "algo", {})
        self.assertIn("error", r, r)
        self.assertIn("no autorizada", r["error"])
        # no llego a insertarse: la bandeja de B sigue vacia
        b_bandeja = self.bandeja(self.b)
        self.assertEqual(b_bandeja["pendientes"], [])

    def test_instancia_de_raiz_no_autorizada_tambien_se_rechaza(self):
        fuera = _persona("Fuera-de-lista-2")
        inst_fuera = _instancia(fuera, "pc1")
        inst_fuera["relay"] = self.relay_url
        r = self._llamar(inst_fuera, "GET", f"/bandeja?to={inst_fuera['id']}")
        self.assertIn("error", r, r)
        self.assertIn("no autorizada", r["error"])

    def test_raiz_autorizada_sigue_funcionando(self):
        # que la allowlist no rompa el caso normal (A y B si estan permitidos)
        r = self.enviar(self.a, self.b, "sigue_vivo", {})
        self.assertIn("peticion_id", r, r)


class TestLimitesTransporte(BaseIA2IA):
    """H3 — el relay corta un cuerpo demasiado grande por Content-Length,
    sin llegar a leerlo entero del socket."""

    def test_cuerpo_demasiado_grande_se_rechaza_con_413(self):
        relleno = "A" * (relay.MAX_BODY_BYTES + 1024)
        cuerpo = json.dumps({"to": self.b["id"], "accion": "x",
                              "params": {"relleno": relleno}}).encode("utf-8")
        self.assertGreater(len(cuerpo), relay.MAX_BODY_BYTES)
        req = urllib.request.Request(
            self.relay_url + "/peticion", method="POST", data=cuerpo,
            headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=10)
            self.fail("se esperaba HTTPError 413 por cuerpo demasiado grande")
        except urllib.error.HTTPError as e:
            try:
                self.assertEqual(e.code, 413)
            finally:
                e.close()  # si no, ResourceWarning "unclosed" al recogerlo el GC

    def test_cuerpo_normal_no_se_ve_afectado(self):
        r = self.enviar(self.a, self.b, "normal", {"x": 1})
        self.assertIn("peticion_id", r, r)


class TestAgendaIdentidad(unittest.TestCase):
    """Agenda: 'un nombre = un contacto', como el movil. Bug reportado por
    tests: anadir() deduplicaba solo por id, no por nombre, y resolver()
    devolvia en silencio la primera coincidencia por nombre - riesgo real
    de "hablar con quien no tocaba" sin enterarse."""

    def setUp(self):
        fd, self.ruta = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(self.ruta)  # anadir() la crea; que no exista es el caso normal

    def tearDown(self):
        try:
            os.unlink(self.ruta)
        except OSError:
            pass

    def test_nombre_duplicado_con_clave_distinta_se_rechaza(self):
        _, pub_a = identidad.generar_par()
        _, pub_b = identidad.generar_par()
        agenda.anadir("X", pub_a, ruta=self.ruta)
        with self.assertRaises(agenda.NombreDuplicadoError):
            agenda.anadir("X", pub_b, ruta=self.ruta)
        # no debe haber creado una segunda entrada en silencio
        self.assertEqual(len(agenda.cargar(self.ruta)), 1)

    def test_reemplazar_sustituye_la_clave_del_nombre(self):
        _, pub_a = identidad.generar_par()
        _, pub_b = identidad.generar_par()
        id_a = agenda.anadir("X", pub_a, ruta=self.ruta)
        id_b = agenda.anadir("X", pub_b, ruta=self.ruta, reemplazar=True)
        self.assertNotEqual(id_a, id_b)
        contactos = agenda.cargar(self.ruta)
        self.assertEqual(len(contactos), 1)
        self.assertIn(id_b, contactos)
        self.assertNotIn(id_a, contactos)
        self.assertEqual(agenda.resolver("X", ruta=self.ruta)["id"], id_b)

    def test_mismo_nombre_misma_clave_es_idempotente(self):
        _, pub_a = identidad.generar_par()
        id1 = agenda.anadir("X", pub_a, ruta=self.ruta)
        id2 = agenda.anadir("X", pub_a, ruta=self.ruta)  # no debe lanzar
        self.assertEqual(id1, id2)
        self.assertEqual(len(agenda.cargar(self.ruta)), 1)

    def test_resolver_con_nombres_duplicados_heredados_lanza_ambiguedad(self):
        # defensa en profundidad: un agenda.json de ANTES de este fix pudo
        # quedar con el mismo nombre dos veces; resolver() tiene que
        # defenderse igual, no solo anadir()
        _, pub_a = identidad.generar_par()
        _, pub_b = identidad.generar_par()
        id_a = identidad.huella(pub_a)
        id_b = identidad.huella(pub_b)
        with open(self.ruta, "w", encoding="utf-8") as f:
            json.dump({"contactos": [
                {"id": id_a, "nombre": "X", "clave_publica": pub_a},
                {"id": id_b, "nombre": "X", "clave_publica": pub_b},
            ]}, f)
        with self.assertRaises(agenda.NombreAmbiguoError):
            agenda.resolver("X", ruta=self.ruta)
        # resolver por id exacto sigue funcionando (no rompe el caso sano)
        self.assertEqual(agenda.resolver(id_a, ruta=self.ruta)["id"], id_a)


class TestNotificarKillSwitch(unittest.TestCase):
    """IA2IA_NOTIFICAR_DESACTIVAR: incidente real 2026-09-16 - despejar
    TELEGRAM_BOT_TOKEN/TELEGRAM_*CHAT_ID del entorno NO basta como
    aislamiento, porque notificar._valor() cae a leer los .env reales del
    disco y manda el aviso de todas formas. El kill-switch tiene que cortar
    ANTES de _credenciales()/_valor(), sin abrir ningun .env ni tocar la
    red."""

    def setUp(self):
        self._previo = os.environ.get("IA2IA_NOTIFICAR_DESACTIVAR")

    def tearDown(self):
        if self._previo is None:
            os.environ.pop("IA2IA_NOTIFICAR_DESACTIVAR", None)
        else:
            os.environ["IA2IA_NOTIFICAR_DESACTIVAR"] = self._previo

    def test_kill_switch_no_abre_env_ni_hace_red(self):
        os.environ["IA2IA_NOTIFICAR_DESACTIVAR"] = "1"
        with mock.patch("notificar.urllib.request.urlopen") as m_urlopen, \
             mock.patch("notificar._credenciales") as m_cred, \
             mock.patch("notificar.dotenv_values") as m_dotenv:
            resultado = notificar.avisar_telegram("mensaje de prueba")
        self.assertFalse(resultado)
        m_urlopen.assert_not_called()
        m_cred.assert_not_called()   # ni siquiera se leen las credenciales...
        m_dotenv.assert_not_called()  # ...luego tampoco se abre ningun .env

    def test_kill_switch_no_bloquea_el_log_local(self):
        # avisar_peticion() sigue haciendo su log por consola (el gate humano
        # por CLI no depende de Telegram); solo se suprime el envio real.
        os.environ["IA2IA_NOTIFICAR_DESACTIVAR"] = "1"
        with mock.patch("notificar.urllib.request.urlopen") as m_urlopen, \
             mock.patch("notificar._print_seguro") as m_print:
            notificar.avisar_peticion({"peticion_id": "p1", "de": "X",
                                        "accion": "ping", "params": {}})
        m_print.assert_called_once()
        m_urlopen.assert_not_called()

    def test_sin_kill_switch_sigue_intentando_credenciales(self):
        # que el interruptor este ausente no cambia el comportamiento previo
        # (sin credenciales, avisar_telegram devuelve False igualmente, pero
        # SI llega a mirar _credenciales)
        os.environ.pop("IA2IA_NOTIFICAR_DESACTIVAR", None)
        with mock.patch("notificar._credenciales", return_value=(None, None)) as m_cred:
            resultado = notificar.avisar_telegram("mensaje de prueba")
        self.assertFalse(resultado)
        m_cred.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
