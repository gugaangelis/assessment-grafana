#!/usr/bin/env python3
"""
grafana_assessment.py - Assessment SOMENTE LEITURA de um ambiente Grafana (9.x a 12.x) alinhado a boas práticas de
observabilidade/SRE, em 5 pilares:
  Confiabilidade da plataforma · Cobertura de observabilidade · Qualidade de alertas · Resposta e operação · Segurança e governança

Levanta o que existe (instância, versão, banco/HA, plugins, organizações, pastas, dashboards, painéis, fontes de dados, regras
de alerta, contact points, políticas de notificação, silêncios, usuários, times, service accounts, tokens, compartilhamentos),
aponta lacunas por pilar com recomendação e gera relatório para stakeholders.

Gera: relatorio.html (stakeholders) · dados.json (bruto; checks/scores/scores_pilar/score_global)
      achados.csv (backlog por pilar) · inventario_dashboards.csv (dashboard x pasta/painéis/queries/descontinuados/refresh/fontes)
      fontes_dados.csv (fonte x tipo/sinal/health/uso) · regras_alerta.csv (regra x estado/saúde/labels/runbook/intervalo)
      cobertura_pastas.csv (pasta x dashboards/tags/descontinuados/quebrados) · top_regras.csv (mais disparos na janela, MTTR)
      higiene_otimizacao.csv (dashboards, fontes, regras, contact points, usuários e tokens a tratar; consultas/min DE/PARA)
      relatorio_executivo.pdf (liderança) · relatorio_tecnico.pdf (engenharia, A4 paisagem)
      apresentacao_stakeholders.pptx (16:9, gráficos nativos editáveis e notas do apresentador)

Requisitos : Python 3.8+. A COLETA usa só a biblioteca padrão (roda em jump server sem internet/pip).
             PDF/PPTX (opcionais): `pip install --user reportlab python-pptx`; sem eles, essas saídas são puladas.
             Alternativa: coletar no jump server com --formats none e gerar PDF/PPTX na sua máquina com --render-only.
Autenticação:
  Token de API (padrão)  : token de service account (glsa_...) ou API key legada, em GRAFANA_TOKEN, --token ou prompt
                           oculto (pedido quando nenhuma credencial é informada). Enviado como "Authorization: Bearer".
  Usuário/senha (opcional): --user/GRAFANA_USER e senha em GRAFANA_PASSWORD ou prompt (HTTP Basic).
Permissão mínima (token):
  Service account com role Admin na organização avaliada -> fontes de dados, alerting, usuários da org, times,
  service accounts, permissões. O token vale para UMA organização (a da service account): o assessment avalia só ela.
  Service accounts não podem ser "Grafana Admin" (server admin): /api/admin/settings, /api/admin/stats, usuários globais
  e lista de organizações respondem 403 e esses controles ficam N/A/"parcial" (esperado; o relatório indica).
  Para cobrir também a configuração do servidor e todas as orgs, use usuário/senha com Grafana Admin = Sim + Admin nas orgs.
  O Grafana OSS não tem role de administrador somente leitura: a garantia de read-only é do próprio script (abaixo).
  Grafana Enterprise/Cloud: pode-se usar uma role RBAC customizada só com ações *:read.
  Com role Editor/Viewer o assessment roda, mas coletores restritos aparecem como "parcial" e os controles ficam N/A.

Garantia de read-only: o cliente HTTP só implementa GET em caminhos /api/...; proxy de datasource, /api/ds/* e recursos de
plugins são bloqueados antes de sair da máquina. Token/Basic não criam sessão (nada a encerrar). Único efeito: o health
check das fontes de dados executa a consulta de teste de cada fonte (desligue com --skip-ds-health).

Uso:
  export GRAFANA_URL='https://grafana.interno/' ; export GRAFANA_TOKEN='glsa_...'   (ou omita e cole no prompt oculto)
  python3 grafana_assessment.py --test                                    (valida conexão e permissões e sai)
  python3 grafana_assessment.py --customer "Assaí Atacadista" --env-name "Produção" --days 30
  python3 grafana_assessment.py --insecure --no-proxy --formats none      (certificado interno, sem proxy, sem PDF/PPTX)
  python3 grafana_assessment.py --orgs "Main Org.,NOC*" --threads 4
  python3 grafana_assessment.py --render-only ./grafana-assessment-20261126-1600/dados.json
"""
from __future__ import annotations

import argparse
import base64
import calendar
import csv
import fnmatch
import getpass
import html
import json
import os
import re
import ssl
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

# --------------------------------------------------------------------------- #
# Catálogos
# --------------------------------------------------------------------------- #

# Ciclo de vida (grafana.com/docs/grafana/latest/upgrade-guide/when-to-upgrade): o major vigente recebe correções;
# do major anterior só a última minor recebe correções de segurança por tempo limitado. Revisar a cada novo major.
CURRENT_MAJOR = 12
LAST_MINOR = {7: 5, 8: 5, 9: 5, 10: 4, 11: 6}  # última minor de cada major encerrado

# Painéis Angular/descontinuados (Angular desabilitado por padrão no 11 e removido no 12).
DEPRECATED_PANELS = {"graph", "singlestat", "table-old", "grafana-singlestat-panel", "grafana-piechart-panel", "grafana-worldmap-panel",
                     "natel-discrete-panel", "natel-plotly-panel", "vonage-status-panel", "briangann-datatable-panel", "briangann-gauge-panel",
                     "flant-statusmap-panel", "agenty-flowcharting-panel", "jdbranham-diagram-panel", "snuids-trafficlights-panel",
                     "yesoreyeram-boomtable-panel", "mtanda-histogram-panel", "petrslavotinek-carpetplot-panel",
                     "neocat-cal-heatmap-panel", "savantly-heatmap-panel", "digrich-bubblechart-panel", "corpglory-progresslist-panel"}
BUILTIN_DS = {"-- grafana --", "grafana", "-- mixed --", "-- dashboard --", "__expr__", "-100", "datasource", "dashboard", "mixed"}
SIGNALS = [("Traces", re.compile(r"tempo|jaeger|zipkin|x-?ray|lightstep|honeycomb|trace", re.I)),
           ("Perfis", re.compile(r"pyroscope|phlare|parca|profil", re.I)),
           ("Logs", re.compile(r"loki|elastic|opensearch|splunk|graylog|quickwit|victorialogs|logs|seq|humio|falcon-logscale", re.I)),
           ("Métricas", re.compile(r"prometheus|mimir|cortex|thanos|victoriametrics|graphite|influx|opentsdb|cloudwatch|azure-monitor|stackdriver|"
                                   r"googlecloud-monitoring|zabbix|datadog|newrelic|dynatrace|appdynamics|prtg|sensu|timescale|instana|checkmk|nagios|snmp", re.I)),
           ("SQL / negócio", re.compile(r"mysql|postgres|mssql|oracle|clickhouse|bigquery|snowflake|redshift|athena|databricks|sqlite|sql|mongodb|redis|"
                                        r"google-sheets|sheets|csv|json|infinity|api", re.I)),
           ("Teste", re.compile(r"testdata", re.I))]
CORE_SIGNALS = ("Métricas", "Logs", "Traces")
ONCALL_RE = re.compile(r"pagerduty|opsgenie|oncall|victorops|splunk|servicenow|jira|teams|slack|telegram|glpi|topdesk|zammad|otrs|znuny|signl4|"
                       r"squadcast|ilert|webex|discord|google ?chat|googlechat|line|kafka|sns|wecom|dingding|threema|pushover|sensugo|mqtt|"
                       r"zendesk|freshservice|itop|redmine|moogsoft|bigpanda|xmatters|everbridge|zabbix|rocket|mattermost|itsm", re.I)
SEV_KEYS = ("severity", "severidade", "priority", "prioridade", "criticality", "criticidade", "sev", "level", "nivel", "nível")
CRIT_RE = re.compile(r"^(critical|crit|critica|crítica|disaster|desastre|high|alta|p1|p2|sev1|sev2|1|2|emergency|major)$", re.I)
CFG_KEYS = {"server.protocol", "server.root_url", "server.router_logging", "server.enable_gzip", "database.type", "remote_cache.type",
            "security.admin_user", "security.cookie_secure", "security.cookie_samesite", "security.allow_embedding", "security.strict_transport_security",
            "security.content_security_policy", "security.disable_gravatar", "security.disable_brute_force_login_protection", "security.angular_support_enabled",
            "security.disable_initial_admin_creation", "users.allow_sign_up", "users.allow_org_create", "users.viewers_can_edit", "users.editors_can_admin",
            "auth.disable_login_form", "auth.login_maximum_inactive_lifetime_duration", "auth.login_maximum_lifetime_duration",
            "auth.anonymous.enabled", "auth.anonymous.org_role", "auth.basic.enabled", "auth.basic.password_policy", "auth.proxy.enabled",
            "snapshots.enabled", "snapshots.external_enabled", "dashboards.versions_to_keep", "dashboards.min_refresh_interval",
            "annotations.dashboard.max_age", "annotations.api.max_age", "annotations.alerting.max_age", "unified_alerting.state_history.enabled",
            "unified_alerting.enabled", "unified_alerting.ha_peers", "unified_alerting.ha_redis_address", "unified_alerting.min_interval",
            "unified_alerting.screenshots.capture", "alerting.enabled", "plugins.allow_loading_unsigned_plugins", "log.level", "log.mode",
            "analytics.reporting_enabled", "analytics.check_for_updates", "analytics.check_for_plugin_updates", "smtp.enabled", "auditing.enabled",
            "rendering.server_url", "public_dashboards.enabled", "feature_toggles.enable", "panels.disable_sanitize_html", "dataproxy.logging"}
DUR_PART = re.compile(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w|y)")
UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "y": 31536000}
ISO_RE = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.\d+)?\s*(Z|[+-]\d\d:?\d\d)?")

P_PLAT, P_COV, P_ALR, P_OPS, P_SEC = ("Confiabilidade da plataforma", "Cobertura de observabilidade", "Qualidade de alertas",
                                      "Resposta e operação", "Segurança e governança")
PILLARS = (P_PLAT, P_COV, P_ALR, P_OPS, P_SEC)
D_VER, D_HA, D_CAP, D_HK = "Versões & ciclo de vida", "Alta disponibilidade", "Desempenho & carga", "Retenção & housekeeping"
D_DS, D_SIG, D_DASH, D_ADOPT = "Fontes de dados", "Sinais & correlação", "Dashboards & padronização", "Adoção & uso"
D_RULE, D_NOISE, D_STATE = "Regras de alerta", "Ruído & flapping", "Alertas em aberto"
D_NOTIF, D_INT, D_MAINT, D_RUN = "Notificações & roteamento", "Integrações (ITSM/on-call)", "Silêncios & manutenção", "Runbooks & contexto"
D_IAM, D_EXP, D_AUD = "Identidade & acesso", "Exposição & criptografia", "Permissões & auditoria"
DOMAIN_PILLAR = {D_VER: P_PLAT, D_HA: P_PLAT, D_CAP: P_PLAT, D_HK: P_PLAT, D_DS: P_COV, D_SIG: P_COV, D_DASH: P_COV, D_ADOPT: P_COV,
                 D_RULE: P_ALR, D_NOISE: P_ALR, D_STATE: P_ALR, D_NOTIF: P_OPS, D_INT: P_OPS, D_MAINT: P_OPS, D_RUN: P_OPS,
                 D_IAM: P_SEC, D_EXP: P_SEC, D_AUD: P_SEC}
SEV_ORDER = {"Alta": 0, "Média": 1, "Baixa": 2}
SEV_W = {"Alta": 3, "Média": 2, "Baixa": 1}

_lock = threading.Lock()


def log(msg: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] {msg}", file=sys.stderr)


def pct(a: int | float, b: int | float) -> int:
    return round(100 * a / b) if b else 0


def clip(s: Any, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def num(v: Any, dec: int = 0) -> str:
    if v is None:
        return "N/D"
    return f"{v:,.{dec}f}".replace(",", "X").replace(".", ",").replace("X", ".")


def i0(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def truthy(v: Any) -> bool | None:
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "1", "yes", "on")


def dur_s(v: Any) -> float | None:
    """'30s','5m','1h30m','90d', 60 -> segundos; vazio/variável -> None."""
    if v is None or v is False or v == "":
        return None
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    s = str(v).strip().lower()
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return float(s)
    parts = DUR_PART.findall(s)
    if not parts or DUR_PART.sub("", s).strip():
        return None
    return sum(float(n) * UNITS[u] for n, u in parts)


def iso_ts(v: Any) -> float | None:
    """ISO-8601 (com Z/offset/nanossegundos) ou epoch (s/ms) -> epoch em segundos; datas 'zero' -> None."""
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v / 1000 if v > 1e11 else float(v)
    m = ISO_RE.match(str(v).strip())
    if not m:
        return None
    y, mo, dd, hh, mi, se = (int(x) for x in m.groups()[:6])
    if y < 1971:
        return None
    tz, off = m.group(7), 0
    if tz and tz != "Z":
        t = tz[1:].replace(":", "")
        off = (1 if tz[0] == "+" else -1) * (int(t[:2]) * 3600 + int(t[2:]) * 60)
    return calendar.timegm((y, mo, dd, hh, mi, se, 0, 0, 0)) - off


def days_ago(ts: float | None, now: float | None = None) -> float | None:
    return None if ts is None else round(((now or time.time()) - ts) / 86400, 1)


def norm_err(e: Any) -> str:
    return clip(re.sub(r"\d+", "#", re.sub(r"\s+", " ", str(e or "sem mensagem"))).strip(), 110)


def pmap(fn: Callable, items: list, threads: int) -> list:
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        return list(ex.map(fn, items))


def median(v: list) -> float | None:
    return round(statistics.median(v), 1) if v else None


def p90(v: list) -> float | None:
    s = sorted(v)
    return round(s[max(0, int(len(s) * 0.9) - 1)], 1) if len(s) >= 10 else None


def signal_of(ds_type: str) -> str:
    t = ds_type or ""
    return next((name for name, rx in SIGNALS if rx.search(t)), "Outros")


# --------------------------------------------------------------------------- #
# Cliente HTTP (read-only, somente GET, somente biblioteca padrão)
# --------------------------------------------------------------------------- #

DENY_RE = re.compile(r"^/api/(ds/|datasources/(proxy|uid/[^/]+/resources|[^/]+/resources)|plugins/[^/]+/resources|plugin-proxy/)", re.I)


AUTH_LBL = {"token_api": "Token de API (service account)", "service_account_token": "Token de API (service account)", "usuario_senha": "Usuário/senha"}


class GfError(Exception):
    def __init__(self, path: str, status: int, message: str = ""):
        super().__init__(f"{path}: HTTP {status} {message}".strip())
        self.path, self.status, self.message = path, status, message


class Grafana:
    """Cliente mínimo da HTTP API do Grafana. Só executa GET em /api/... (exceto proxies/recursos de plugin)."""

    def __init__(self, url: str, token: str | None = None, user: str | None = None, password: str | None = None,
                 insecure: bool = False, ca: str | None = None, timeout: int = 60, no_proxy: bool = False):
        u = url.strip().rstrip("/")
        self.base = re.sub(r"/api$", "", u)
        ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        if insecure:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        handlers: list[Any] = [urllib.request.HTTPSHandler(context=ctx)]
        if no_proxy:
            handlers.append(urllib.request.ProxyHandler({}))
        self._op = urllib.request.build_opener(*handlers)
        self.timeout, self.stats = timeout, Counter()
        token = (token or "").strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        if token:
            self._auth, self.auth_mode = "Bearer " + token, "token_api"
        elif user:
            self._auth = "Basic " + base64.b64encode(f"{user}:{password or ''}".encode("utf-8")).decode("ascii")
            self.auth_mode = "usuario_senha"
        else:
            raise ValueError("informe --token/GRAFANA_TOKEN ou --user/GRAFANA_USER")
        self.token_mode = self.auth_mode == "token_api"
        try:
            self.health = self._get("/api/health", auth=False) or {}
        except GfError:  # health anônimo bloqueado por proxy/SSO: segue sem ele
            self.health = {}

    def _get(self, path: str, params: dict | None = None, org: Any = None, auth: bool = True, retry: bool = True) -> Any:
        q = ("?" + urllib.parse.urlencode(params, doseq=True)) if params else ""
        hdr = {"Accept": "application/json", "User-Agent": "grafana-assessment/1.0"}
        if auth:
            hdr["Authorization"] = self._auth
        if org and not self.token_mode:  # token já é da org da service account; trocar de org com token dá 401
            hdr["X-Grafana-Org-Id"] = str(org)
        raw = ""
        tries = 4 if retry else 1
        for attempt in range(tries):
            try:
                req = urllib.request.Request(self.base + path + q, headers=hdr, method="GET")
                with self._op.open(req, timeout=self.timeout) as r:
                    raw = r.read().decode("utf-8", "replace")
                break
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and attempt < tries - 1:
                    time.sleep(2 ** attempt)
                    continue
                body = ""
                try:
                    body = e.read().decode("utf-8", "replace")
                except Exception:  # noqa: BLE001
                    pass
                msg: Any = body
                try:
                    j = json.loads(body)
                    msg = (j.get("message") or j.get("error") or body) if isinstance(j, dict) else body
                except ValueError:
                    pass
                raise GfError(path, e.code, clip(re.sub(r"\s+", " ", str(msg or e.reason)), 160)) from None
            except OSError:
                if attempt < tries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise
        if not raw.strip():
            return None
        try:
            return json.loads(raw)
        except ValueError:
            raise GfError(path, 200, "resposta não-JSON (a URL aponta para o Grafana? há SSO/proxy na frente?)") from None

    def get(self, path: str, org: Any = None, retry: bool = True, **params: Any) -> Any:
        if not path.startswith("/api/") or DENY_RE.match(path):
            raise PermissionError(f"caminho '{path}' bloqueado: assessment somente leitura")
        with _lock:
            self.stats["calls"] += 1
        params = {k: v for k, v in params.items() if v is not None}
        return self._get(path, params or None, org, retry=retry)


class Errors:
    """Contabiliza negações/erros por coletor sem derrubar o assessment."""

    def __init__(self):
        self.e: dict[str, Counter] = defaultdict(Counter)
        self.na: dict[str, str] = {}
        self.ok: set[str] = set()

    def run(self, key: str, fn: Callable, default: Any = None, na404: bool = True) -> Any:
        try:
            r = fn()
            with _lock:
                self.ok.add(key)
            return r
        except PermissionError:
            raise
        except GfError as exc:
            with _lock:
                if exc.status == 404 and na404:
                    self.na.setdefault(key, "n/a (endpoint inexistente nesta versão/edição ou recurso desabilitado)")
                else:
                    self.e[key][f"HTTP {exc.status} {clip(exc.message, 70)}"] += 1
        except Exception as exc:  # noqa: BLE001
            with _lock:
                self.e[key][f"erro {type(exc).__name__}: {clip(exc, 60)}"] += 1
        return default

    def status(self, key: str) -> str:
        c = self.e.get(key)
        if c:
            return "parcial: " + ", ".join(f"{k} x{v}" for k, v in c.most_common(2))
        if key in self.ok:
            return "ok"
        return self.na.get(key, "não executado (sem objetos a consultar)")

    def failed(self, key: str) -> bool:
        """True quando o coletor não trouxe dado nenhum (negado/erro em todas as chamadas)."""
        return key not in self.ok


def support_status(ver: tuple, latest: tuple | None = None) -> dict:
    cur = max(CURRENT_MAJOR, latest[0] if latest else 0)
    major, minor = ver
    if major >= cur:
        st = "completo"
    elif major == cur - 1:
        lm = LAST_MINOR.get(major)
        st = "limitado" if lm is None or minor >= lm else "EOL"
    else:
        st = "EOL"
    return {"status": st, "major_vigente": cur, "ultima_minor_major_anterior": LAST_MINOR.get(cur - 1)}


def parse_ver(s: Any) -> tuple[int, int]:
    n = [int(x) for x in re.findall(r"\d+", str(s or ""))[:2]] + [0, 0]
    return n[0], n[1]


# --------------------------------------------------------------------------- #
# Coletores
# --------------------------------------------------------------------------- #


def paged(fn: Callable[[int], Any], size: int, key: str | None = None, max_pages: int = 500) -> list:
    out: list = []
    for page in range(1, max_pages + 1):
        r = fn(page)
        rows = ((r or {}).get(key) if key else r) or []
        out += rows
        if len(rows) < size:
            break
    return out


def collect_instance(G: Grafana, E: Errors) -> dict:
    o: dict[str, Any] = {}
    me = E.run("identidade", lambda: G.get("/api/user"), {}) or {}
    o["me"] = {"login": me.get("login"), "server_admin": bool(me.get("isGrafanaAdmin")), "org_id": me.get("orgId")}
    fs = E.run("frontend_settings", lambda: G.get("/api/frontend/settings"), {}) or {}
    bi = fs.get("buildInfo") or {}
    vs = bi.get("version") or G.health.get("version") or "0.0.0"
    latest = parse_ver(bi.get("latestVersion")) if bi.get("latestVersion") else None
    o.update({"versao": vs, "ver": list(parse_ver(vs)), "edicao": bi.get("edition") or ("Enterprise" if (fs.get("licenseInfo") or {}).get("hasLicense") else "Open Source"),
              "commit": bi.get("commit") or G.health.get("commit"), "latest": bi.get("latestVersion") or None,
              "has_update": bi.get("hasUpdate") if bi.get("latestVersion") else None, "db_status": G.health.get("database")})
    o["suporte"] = support_status(tuple(o["ver"]), latest)
    oauth = fs.get("oauth") or {}
    o["frontend"] = {"anonymous": fs.get("anonymousEnabled"), "disable_login_form": fs.get("disableLoginForm"), "ldap": fs.get("ldapEnabled"),
                     "saml": fs.get("samlEnabled"), "auth_proxy": fs.get("authProxyEnabled"), "jwt": bool(fs.get("jwtHeaderName")),
                     "oauth": sorted(oauth) if isinstance(oauth, dict) else [], "unified_alerting": fs.get("unifiedAlertingEnabled"),
                     "legacy_alerting": fs.get("alertingEnabled"), "min_refresh": fs.get("minRefreshInterval"), "renderer": fs.get("rendererAvailable"),
                     "public_dashboards": fs.get("publicDashboardsEnabled"), "angular_support": fs.get("angularSupportEnabled"),
                     "allow_org_create": fs.get("allowOrgCreate"), "snapshots": fs.get("snapshotEnabled"),
                     "feature_toggles": sorted(k for k, v in (fs.get("featureToggles") or {}).items() if v)}
    o["angular_panels"] = sorted(k for k, v in (fs.get("panels") or {}).items()
                                 if isinstance(v, dict) and (v.get("angularDetected") or (v.get("angular") or {}).get("detected")))
    adm = E.run("admin_settings", lambda: G.get("/api/admin/settings"), None)
    o["cfg"] = None if adm is None else {f"{s}.{k}": v for s, kv in adm.items() if isinstance(kv, dict) for k, v in kv.items()
                                          if f"{s}.{k}" in CFG_KEYS or (s.startswith("auth.") and k == "enabled")}
    o["stats"] = E.run("admin_stats", lambda: G.get("/api/admin/stats"), None)
    o["sso"] = E.run("sso_settings", lambda: G.get("/api/v1/sso-settings"), None)
    plugins = E.run("plugins", lambda: G.get("/api/plugins", embedded=0), []) or []
    o["plugins"] = [{"id": p.get("id"), "nome": p.get("name"), "tipo": p.get("type"), "versao": (p.get("info") or {}).get("version"),
                     "assinatura": p.get("signature"), "assinatura_tipo": p.get("signatureType"), "core": p.get("signature") == "internal",
                     "angular": bool(p.get("angularDetected") or (p.get("angular") or {}).get("detected")), "habilitado": p.get("enabled"),
                     "atualizacao": p.get("hasUpdate"), "ultima_versao": p.get("latestVersion")} for p in plugins]
    return o


def collect_users(G: Grafana, E: Errors) -> list[dict] | None:
    rows = E.run("usuarios", lambda: paged(lambda p: G.get("/api/users/search", perpage=1000, page=p), 1000, "users"), None)
    if rows is None:
        return None
    return [{"id": u.get("id"), "login": u.get("login"), "server_admin": bool(u.get("isAdmin")), "desabilitado": bool(u.get("isDisabled")),
             "visto_dias": days_ago(iso_ts(u.get("lastSeenAt"))), "auth": sorted(u.get("authLabels") or [])} for u in rows]


def collect_orgs(G: Grafana, E: Errors, patterns: list[str]) -> tuple[list[dict], list[dict] | None]:
    mine = None
    if G.token_mode:  # token = uma org (a da service account/API key)
        cur = E.run("organizacoes", lambda: G.get("/api/org"), {}) or {}
        role = next((o.get("role") for o in E.run("organizacoes", lambda: G.get("/api/user/orgs"), None) or []
                     if o.get("orgId") == cur.get("id")), None)
        mine = [{"orgId": cur.get("id", 1), "name": cur.get("name", "Main Org."), "role": role}]
    else:
        mine = E.run("organizacoes", lambda: G.get("/api/user/orgs"), None)
    if not mine:
        cur = E.run("organizacoes", lambda: G.get("/api/org"), {}) or {}
        mine = [{"orgId": cur.get("id", 1), "name": cur.get("name", "Main Org."), "role": None}]
    allo = E.run("organizacoes", lambda: G.get("/api/orgs", perpage=1000), None)
    sel = [{"id": o.get("orgId"), "nome": o.get("name"), "papel": o.get("role")} for o in mine]
    pats = [p.strip().lower() for p in patterns if p.strip()]
    if pats:
        sel = [o for o in sel if any(fnmatch.fnmatch(str(o["nome"]).lower(), p) or str(o["id"]) == p for p in pats)]
        if not sel:
            raise SystemExit(f"--orgs não encontrou organizações (das que o usuário é membro) para: {', '.join(patterns)}"
                             + (f". Com token, só a org do token ({mine[0].get('name')}) é avaliável: gere um token em cada org." if G.token_mode else ""))
    return sel, None if allo is None else [{"id": o.get("id"), "nome": o.get("name")} for o in allo]


def ds_ref(ref: Any) -> tuple[str, Any]:
    """Classifica a referência a datasource de um painel/target."""
    if ref is None or ref == "":
        return "default", None
    if isinstance(ref, dict):
        uid, typ = ref.get("uid"), ref.get("type")
        if uid in (None, "") and not typ:
            return "default", None
        if str(typ or "").lower() in ("datasource", "grafana", "__expr__") or str(uid or "").lower() in BUILTIN_DS:
            return "builtin", uid
        if uid in (None, ""):
            return "type", typ
        return ("var", uid) if "$" in str(uid) else ("uid", str(uid))
    s = str(ref)
    if "$" in s:
        return "var", s
    return ("builtin", s) if s.lower() in BUILTIN_DS else ("name", s)


def walk_panels(panels: list) -> Any:
    for p in panels or []:
        if not isinstance(p, dict):
            continue
        yield p
        if p.get("type") == "row" and p.get("panels"):
            yield from walk_panels(p.get("panels"))


def analyze_dashboard(org: str, item: dict, raw: dict | None, dsx: dict, angular: set) -> dict:
    rec: dict[str, Any] = {"org": org, "uid": item.get("uid"), "titulo": item.get("title"), "pasta": item.get("folderTitle") or "General",
                           "pasta_uid": item.get("folderUid") or "", "lido": raw is not None}
    if raw is None:
        return rec
    dsh, meta = raw.get("dashboard") or {}, raw.get("meta") or {}
    top = dsh.get("panels") or []
    if not top and dsh.get("rows"):
        top = [p for r in dsh["rows"] or [] for p in (r.get("panels") or [])]
    panels = [p for p in walk_panels(top) if p.get("type") != "row"]
    refs: list = []
    dep: Counter = Counter()
    queries = legacy = libp = 0
    for p in panels:
        t = str(p.get("type") or "")
        if t in DEPRECATED_PANELS or t in angular:
            dep[t] += 1
        legacy += bool(p.get("alert"))
        libp += bool(p.get("libraryPanel"))
        tg = [x for x in p.get("targets") or [] if isinstance(x, dict)]
        queries += sum(1 for x in tg if not x.get("hide"))
        pref = p.get("datasource")
        tds = [x.get("datasource") for x in tg if x.get("datasource") is not None]
        if tds:
            refs += tds
            if pref is not None:
                refs.append(pref)
        elif tg or pref is not None:
            refs.append(pref)
    variables = [v for v in (dsh.get("templating") or {}).get("list") or [] if isinstance(v, dict)]
    refs += [v.get("datasource") for v in variables if v.get("type") == "query"]
    used, broken = set(), set()
    for r in refs if dsx["lidas"] else []:  # sem ler as fontes não dá para afirmar que a referência está quebrada
        k, v = ds_ref(r)
        if k == "default":
            (used.add(dsx["default"]) if dsx["default"] else broken.add("(fonte padrão inexistente)"))
        elif k in ("uid", "name"):
            uid = v if v in dsx["uid"] else dsx["name"].get(v)
            (used.add(uid) if uid else broken.add(str(v)))
    rs = dur_s(dsh.get("refresh")) if dsh.get("refresh") else None
    rec.update({"titulo": item.get("title") or dsh.get("title"), "tags": len(item.get("tags") or dsh.get("tags") or []), "paineis": len(panels),
                "queries": queries, "descontinuados": sum(dep.values()), "tipos_descontinuados": sorted(dep), "alertas_legados": legacy,
                "library_panels": libp, "refresh": str(dsh.get("refresh") or ""), "refresh_s": rs, "variaveis": len(variables),
                "ds_usados": sorted(used), "ds_quebrados": sorted(broken), "provisionado": bool(meta.get("provisioned")),
                "versao": i0(dsh.get("version") or meta.get("version")), "schema": i0(dsh.get("schemaVersion")),
                "atualizado_dias": days_ago(iso_ts(meta.get("updated"))), "descricao": bool(dsh.get("description")),
                "acl_propria": bool(meta.get("hasAcl")), "periodo": str((dsh.get("time") or {}).get("from") or "")})
    return rec


def _health(G: Grafana, oid: Any, ds: dict) -> tuple[str | None, str]:
    try:
        r = G.get(f"/api/datasources/uid/{urllib.parse.quote(str(ds.get('uid')), safe='')}/health", org=oid, retry=False) or {}
        st = str(r.get("status") or "OK").upper()
        return ("OK" if st == "OK" else "ERROR" if st == "ERROR" else st), clip(r.get("message") or "", 140)
    except GfError as e:
        if e.status in (404, 405, 501):
            return None, "health check não suportado pelo plugin"
        if e.status in (401, 403):
            return None, "sem permissão para o health check"
        return "ERROR", clip(e.message or f"HTTP {e.status}", 140)
    except PermissionError:
        raise
    except Exception as e:  # noqa: BLE001
        return "ERROR", clip(f"{type(e).__name__}: {e}", 140)


def collect_org(G: Grafana, E: Errors, org: dict, a: Any, angular: set) -> dict:
    oid, oname, th = org["id"], org["nome"], max(1, a.threads)

    def g(path: str, **kw: Any) -> Any:
        return G.get(path, org=oid, **kw)

    R: dict[str, Any] = {"org": oname, "org_id": oid, "papel": org.get("papel")}
    log(f"[{oname}] fontes de dados...")
    ds = E.run("fontes_dados", lambda: g("/api/datasources"), None)
    R["ds_lidas"] = ds is not None
    ds = ds or []
    health = pmap(lambda x: _health(G, oid, x), ds, th) if ds and not a.skip_ds_health else [(None, "não verificado (--skip-ds-health)")] * len(ds)
    R["datasources"] = [{"org": oname, "uid": x.get("uid"), "nome": x.get("name"), "tipo": x.get("type"), "tipo_nome": x.get("typeName") or x.get("type"),
                         "sinal": signal_of(f"{x.get('type')} {x.get('typeName') or ''}"), "padrao": bool(x.get("isDefault")), "acesso": x.get("access"),
                         "url": x.get("url") or "", "tls_skip": bool((x.get("jsonData") or {}).get("tlsSkipVerify")), "readonly": bool(x.get("readOnly")),
                         "basic_auth": bool(x.get("basicAuth")),
                         "correlacao": any((x.get("jsonData") or {}).get(k) for k in ("tracesToLogs", "tracesToLogsV2", "tracesToMetrics", "tracesToProfiles",
                                                                                     "derivedFields", "exemplarTraceIdDestinations")),
                         "health": h[0], "health_msg": h[1], "usos_dash": 0, "usos_regras": 0} for x, h in zip(ds, health)]
    dsx = {"uid": {d["uid"]: d for d in R["datasources"]}, "name": {d["nome"]: d["uid"] for d in R["datasources"]},
           "default": next((d["uid"] for d in R["datasources"] if d["padrao"]), None), "lidas": R["ds_lidas"]}

    log(f"[{oname}] pastas e dashboards...")
    R["folders"] = [{"uid": f.get("uid"), "titulo": f.get("title"), "pai": f.get("folderUid") or ""}
                    for f in E.run("pastas", lambda: paged(lambda p: g("/api/search", type="dash-folder", limit=5000, page=p), 5000), []) or []]
    dl = E.run("dashboards", lambda: paged(lambda p: g("/api/search", type="dash-db", limit=5000, page=p), 5000), []) or []
    R["dash_total"] = len(dl)
    if a.max_dashboards and len(dl) > a.max_dashboards:
        dl = dl[: a.max_dashboards]

    def fetch(item: dict) -> dict:
        raw = E.run("dashboards", lambda: g("/api/dashboards/uid/" + urllib.parse.quote(str(item.get("uid")), safe="")), None, na404=False)
        return analyze_dashboard(oname, item, raw, dsx, angular)

    R["dashboards"] = pmap(fetch, dl, th)
    log(f"[{oname}] {len(R['dashboards'])} dashboards analisados · alerting...")
    R["ruler"] = E.run("regras_alerta", lambda: g("/api/ruler/grafana/api/v1/rules"), None)
    R["prom"] = E.run("estado_alertas", lambda: g("/api/prometheus/grafana/api/v1/rules"), None)
    R["contact_points"] = E.run("contact_points", lambda: g("/api/v1/provisioning/contact-points"), None)
    R["policies"] = E.run("politicas", lambda: g("/api/v1/provisioning/policies"), None)
    R["mute_timings"] = E.run("mute_timings", lambda: g("/api/v1/provisioning/mute-timings"), None)
    R["templates"] = E.run("templates_notificacao", lambda: g("/api/v1/provisioning/templates"), None)
    R["silences"] = E.run("silencios", lambda: g("/api/alertmanager/grafana/api/v2/silences"), None)
    R["am_alerts"] = E.run("alertas_ativos", lambda: g("/api/alertmanager/grafana/api/v2/alerts"), None)
    R["receivers"] = E.run("entrega_notificacoes", lambda: g("/api/alertmanager/grafana/config/api/v1/receivers"), None)
    R["am_choice"] = E.run("alertmanager_externo", lambda: g("/api/v1/ngalert/admin_config"), None)

    log(f"[{oname}] histórico de estados de alerta ({a.days} dias)...")
    now = int(time.time())
    wins = [(s, min(s + 86400, now)) for s in range(now - a.days * 86400, now, 86400)]

    def hist(w: tuple) -> list:
        return E.run("historico_alertas", lambda: g("/api/annotations", type="alert", limit=a.max_events_per_day,
                                                     **{"from": w[0] * 1000, "to": w[1] * 1000 - 1}), []) or []

    parts = pmap(hist, wins, th)
    R["history"] = [{"id": i0(x.get("alertId")), "nome": x.get("alertName"), "texto": clip(x.get("text") or "", 300), "estado": x.get("newState"),
                     "t": i0(x.get("time")) / 1000} for p in parts for x in p]
    R["history_truncado"] = any(len(p) >= a.max_events_per_day for p in parts)

    log(f"[{oname}] usuários, times, service accounts, compartilhamentos, permissões...")
    ou = E.run("usuarios_org", lambda: g("/api/org/users"), None)
    R["org_users"] = None if ou is None else [{"login": u.get("login"), "papel": u.get("role"), "visto_dias": days_ago(iso_ts(u.get("lastSeenAt"))),
                                               "desabilitado": bool(u.get("isDisabled")), "auth": sorted(u.get("authLabels") or [])} for u in ou]
    tm = E.run("times", lambda: g("/api/teams/search", perpage=1000), None)
    R["teams"] = None if tm is None else [{"id": t.get("id"), "nome": t.get("name"), "membros": i0(t.get("memberCount"))} for t in tm.get("teams") or []]
    sa = E.run("service_accounts", lambda: paged(lambda p: g("/api/serviceaccounts/search", perpage=1000, page=p), 1000, "serviceAccounts"), None)

    def toks(s: dict) -> list:
        if not i0(s.get("tokens")):
            return []
        return E.run("service_accounts", lambda: g(f"/api/serviceaccounts/{s.get('id')}/tokens"), []) or []

    R["service_accounts"] = None if sa is None else [
        {"nome": s.get("name"), "papel": s.get("role"), "desabilitado": bool(s.get("isDisabled")),
         "tokens": [{"nome": t.get("name"), "expira": t.get("expiration"), "expirado": bool(t.get("hasExpired")), "revogado": bool(t.get("isRevoked")),
                     "uso_dias": days_ago(iso_ts(t.get("lastUsedAt"))), "criado_dias": days_ago(iso_ts(t.get("created")))} for t in tk]}
        for s, tk in zip(sa, pmap(toks, sa, th))]
    keys = E.run("api_keys", lambda: g("/api/auth/keys"), None)
    R["api_keys"] = None if keys is None else [{"nome": k.get("name"), "papel": k.get("role"), "expira": k.get("expiration")} for k in keys]
    pub = E.run("dashboards_publicos", lambda: g("/api/dashboards/public-dashboards", perpage=1000), None)
    pub = (pub.get("publicDashboards") if isinstance(pub, dict) else pub) if pub is not None else None
    R["public_dashboards"] = None if pub is None else [{"titulo": p.get("title"), "dashboard": p.get("dashboardUid"),
                                                        "ativo": p.get("isEnabled", True), "share": p.get("share")} for p in pub]
    sn = E.run("snapshots", lambda: g("/api/dashboard/snapshots", limit=1000), None)
    R["snapshots"] = None if sn is None else [{"nome": s.get("name"), "externo": bool(s.get("external")), "expira": iso_ts(s.get("expires"))} for s in sn]
    lib = E.run("library_panels", lambda: paged(lambda p: (g("/api/library-elements", perPage=500, page=p, kind=1) or {}).get("result") or {}, 500, "elements"), None)
    R["library_panels"] = None if lib is None else [{"nome": x.get("name"), "pasta": (x.get("meta") or {}).get("folderName") or "General",
                                                     "conexoes": i0((x.get("meta") or {}).get("connectedDashboards"))} for x in lib]
    cr = E.run("correlacoes", lambda: g("/api/datasources/correlations", limit=1000), None)
    R["correlacoes"] = None if cr is None else len(cr.get("correlations") or []) if isinstance(cr, dict) else len(cr)

    def perm(f: dict) -> tuple:
        return f["uid"], E.run("permissoes_pastas", lambda: g(f"/api/folders/{urllib.parse.quote(str(f['uid']), safe='')}/permissions"), None)

    R["folder_perms"] = {uid: None if p is None else [{"papel": x.get("role") or "", "time": i0(x.get("teamId")), "usuario": i0(x.get("userId")),
                                                       "permissao": i0(x.get("permission")), "herdada": bool(x.get("inherited"))} for x in p]
                         for uid, p in pmap(perm, R["folders"], th)}
    return R


# --------------------------------------------------------------------------- #
# Consolidação
# --------------------------------------------------------------------------- #


def parse_rules(R: dict) -> list[dict]:
    """Junta definição (ruler) e estado em tempo de execução (API Prometheus) das regras de alerta da org."""
    org = R["org"]
    runtime: dict = {}
    for gr in ((R.get("prom") or {}).get("data") or {}).get("groups") or []:
        for r in gr.get("rules") or []:
            if r.get("type", "alerting") == "alerting":
                runtime[(gr.get("file"), gr.get("name"), r.get("name"))] = (r, gr)
    out: list[dict] = []
    seen: set = set()

    def rec(title, folder, group, iv, for_s, labels, ann, rt, extra):
        alerts = (rt or {}).get("alerts") or []
        firing = [x for x in alerts if str(x.get("state") or "").lower().startswith(("alerting", "firing"))]
        ages = [a for a in (days_ago(iso_ts(x.get("activeAt"))) for x in firing) if a is not None]
        labels, ann = labels or {}, ann or {}
        sev = next((str(v) for k, v in labels.items() if str(k).lower() in SEV_KEYS), None)
        base = {"org": org, "titulo": title, "pasta": folder, "grupo": group, "intervalo_s": iv, "for_s": for_s or 0, "severidade": sev,
                "labels": len(labels), "runbook": bool(ann.get("runbook_url")), "resumo": bool(ann.get("summary") or ann.get("description")),
                "dashboard": bool(ann.get("__dashboardUid__")), "estado": (rt or {}).get("state"), "saude": (rt or {}).get("health"),
                "erro": clip((rt or {}).get("lastError") or "", 160), "instancias": len(alerts), "disparando": len(firing),
                "idades": ages, "uid": None, "id": None, "pausada": False, "datasources": [], "queries": 1, "nodata_state": None,
                "exec_err_state": None, "receiver": None}
        base.update(extra)
        return base

    for folder, groups in (R.get("ruler") or {}).items():
        for gr in groups or []:
            iv = dur_s(gr.get("interval"))
            for r in gr.get("rules") or []:
                ga = r.get("grafana_alert") or {}
                if ga.get("record"):
                    continue
                title = ga.get("title") or r.get("alert") or "(sem título)"
                key = (folder, gr.get("name"), title)
                rt, rg = runtime.get(key, (None, None))
                seen.add(key)
                dsq = [str(x.get("datasourceUid")) for x in ga.get("data") or [] if str(x.get("datasourceUid") or "") not in ("", "__expr__", "-100")]
                ns = ga.get("notification_settings") or {}
                out.append(rec(title, folder, gr.get("name"), iv or (rg or {}).get("interval"), dur_s(r.get("for")), r.get("labels"),
                               r.get("annotations"), rt,
                               {"uid": ga.get("uid"), "id": ga.get("id"), "pausada": bool(ga.get("is_paused")), "datasources": sorted(set(dsq)),
                                "queries": max(1, len(dsq)), "nodata_state": ga.get("no_data_state"), "exec_err_state": ga.get("exec_err_state"),
                                "receiver": ns.get("receiver")}))
    for key, (rt, rg) in runtime.items():
        if key not in seen:
            out.append(rec(key[2], key[0], key[1], dur_s(rg.get("interval")), dur_s(rt.get("duration")), rt.get("labels"), rt.get("annotations"), rt, {}))
    return out


def parse_notif(R: dict, rules: list[dict]) -> dict:
    cps, pol, now = R.get("contact_points"), R.get("policies") or {}, time.time()
    by_name: dict[str, list] = defaultdict(list)
    for c in cps or []:
        by_name[c.get("name")].append(c)
    used, repeats, mt_used, routes = set(), [], set(), [0]

    def walk(r: dict, rep_in: float, depth: int) -> None:
        if r.get("receiver"):
            used.add(r["receiver"])
        rep = dur_s(r.get("repeat_interval")) or rep_in
        repeats.append(rep)
        mt_used.update(r.get("mute_time_intervals") or [])
        mt_used.update(r.get("active_time_intervals") or [])
        routes[0] += depth > 0
        for c in r.get("routes") or []:
            walk(c, rep, depth + 1)

    if pol:
        walk(pol, 14400, 0)
    used.update(r["receiver"] for r in rules if r.get("receiver"))
    dflt = pol.get("receiver")

    def example(c: dict) -> bool:
        return c.get("type") == "email" and "example@email.com" in str((c.get("settings") or {}).get("addresses") or "")

    integ = [c for lst in by_name.values() for c in lst]
    mts = R.get("mute_timings")
    rcv, fails, tried = R.get("receivers"), [], 0
    for r in rcv or []:
        for i in r.get("integrations") or []:
            tried += not str(i.get("lastNotifyAttempt") or "0001").startswith("0001")
            if i.get("lastNotifyAttemptError"):
                fails.append({"org": R["org"], "receiver": r.get("name"), "tipo": i.get("name") or i.get("type"), "erro": clip(i["lastNotifyAttemptError"], 140)})
    sil = R.get("silences")
    act = [s for s in sil or [] if (s.get("status") or {}).get("state") == "active"]
    long_ = [{"org": R["org"], "comentario": clip(s.get("comment") or "", 90),
              "matchers": clip(", ".join(f"{m.get('name')}{'=' if m.get('isEqual', True) else '!='}{m.get('value')}" for m in s.get("matchers") or []), 120),
              "dias_restantes": round(((iso_ts(s.get("endsAt")) or now) - now) / 86400)} for s in act if ((iso_ts(s.get("endsAt")) or now) - now) > 30 * 86400]
    ama = R.get("am_alerts")
    return {"coletado": cps is not None, "contact_points": len(by_name), "integracoes": len(integ),
            "por_tipo": dict(Counter(str(c.get("type")) for c in integ)), "padrao": dflt,
            "padrao_exemplo": bool(dflt) and bool(by_name.get(dflt)) and all(example(c) for c in by_name[dflt]),
            "exemplo_em_uso": sorted(n for n, lst in by_name.items() if n in used and any(example(c) for c in lst)),
            "politicas": bool(pol), "rotas": routes[0], "repeat_min_s": min(repeats) if repeats else None,
            "repeat_curto": sum(1 for x in repeats if x and x < 3600), "cp_sem_uso": sorted(n for n in by_name if n not in used),
            "resolve_off": sum(1 for c in integ if c.get("disableResolveMessage")), "email": any(c.get("type") == "email" for c in integ),
            "oncall": sorted({f"{n} ({c.get('type')})" for n, lst in by_name.items() for c in lst
                              if c.get("type") != "email" and ONCALL_RE.search(f"{c.get('type')} {n}")}),
            "webhooks": sorted({n for n, lst in by_name.items() for c in lst if c.get("type") == "webhook"}),
            "mute_timings": None if mts is None else len(mts), "mt_sem_uso": sorted(m.get("name") for m in mts or [] if m.get("name") not in mt_used),
            "templates": None if R.get("templates") is None else len(R["templates"]),
            "entregas": None if rcv is None else len(rcv), "entregas_tentadas": tried, "falhas": fails,
            "silencios_ativos": None if sil is None else len(act), "silencios_longos": long_,
            "alertas_am": None if ama is None else len(ama), "suprimidos": sum(1 for x in ama or [] if (x.get("status") or {}).get("state") == "suppressed"),
            "am_choice": (R.get("am_choice") or {}).get("alertmanagersChoice")}


def summarize_history(d: dict, results: list[dict]) -> None:
    days = d["meta"]["days"]
    evs = []
    for R in results:
        names = {r["id"]: r["titulo"] for r in R["_rules"] if r.get("id")}
        by_inst: dict[tuple, list] = defaultdict(list)
        for x in R["history"]:
            txt = x.get("texto") or ""
            nm = names.get(x["id"]) or x.get("nome") or clip(re.split(r" \{| - ", txt)[0] or f"regra {x['id']}", 90)
            by_inst[(x["id"] or nm, txt.split(" - ")[0])].append((x["t"], str(x.get("estado") or "").lower(), nm))
        for lst in by_inst.values():
            lst.sort(key=lambda z: z[0])
            nxt, ends = None, [None] * len(lst)
            for i in range(len(lst) - 1, -1, -1):
                ends[i] = nxt
                if lst[i][1].startswith("normal"):
                    nxt = lst[i][0]
            for i, (t, st, nm) in enumerate(lst):
                if st.startswith("alerting"):
                    evs.append({"t": f"{R['org']}|{nm}", "n": nm, "org": R["org"], "c": t, "dur": (ends[i] - t) if ends[i] else None})
    by_t: dict[str, list] = defaultdict(list)
    for e in evs:
        by_t[e["t"]].append(e)
    durs = [e["dur"] / 60 for e in evs if e["dur"] is not None]
    top, flap = [], []
    for lst in by_t.values():
        dd = [e["dur"] / 60 for e in lst if e["dur"] is not None]
        row = {"regra": lst[0]["n"], "org": lst[0]["org"], "disparos": len(lst), "mttr_mediana_min": median(dd)}
        top.append(row)
        if len(lst) >= 10 and dd and statistics.median(dd) < 10:
            flap.append(row)
    top.sort(key=lambda r: -r["disparos"])
    flap.sort(key=lambda r: -r["disparos"])
    per_day = Counter(datetime.fromtimestamp(e["c"]).strftime("%Y-%m-%d") for e in evs)
    d["events"] = {"total": len(evs), "por_dia": round(len(evs) / days, 1) if days else 0, "truncado": any(R["history_truncado"] for R in results),
                   "transicoes": sum(len(R["history"]) for R in results), "regras_distintas": len(by_t), "resolvidos": len(durs),
                   "curta_duracao": sum(1 for x in durs if x < 5), "mttr_mediana_min": median(durs), "mttr_p90_min": p90(durs),
                   "top_regras": top[:50], "flapping": flap[:50], "flapping_total": len(flap), "serie_diaria": dict(sorted(per_day.items()))}


def consolidate(d: dict, inst: dict, users: list[dict] | None, results: list[dict], expected: list[str]) -> None:
    now, multi = time.time(), len(results) > 1
    pfx = (lambda o, s: f"{o} / {s}") if multi else (lambda o, s: s)
    cfg = inst.get("cfg")
    fe = inst["frontend"]

    def C(k: str) -> Any:
        return None if cfg is None else cfg.get(k)

    def CB(k: str) -> bool | None:
        return None if cfg is None else truthy(cfg.get(k))

    # Regras e notificação por org
    for R in results:
        R["_rules"] = parse_rules(R)
        R["_notif"] = parse_notif(R, R["_rules"])
    rules = [r for R in results for r in R["_rules"]]
    dash = [x for R in results for x in R["dashboards"]]
    lidos = [x for x in dash if x["lido"]]
    dss = [x for R in results for x in R["datasources"]]
    dkey = {(x["org"], x["uid"]): x for x in dss}
    for x in lidos:
        for u in x["ds_usados"]:
            if (x["org"], u) in dkey:
                dkey[(x["org"], u)]["usos_dash"] += 1
    for r in rules:
        for u in r["datasources"]:
            if (r["org"], u) in dkey:
                dkey[(r["org"], u)]["usos_regras"] += 1
    d["dashboards"], d["datasources"] = dash, dss

    # Dashboards
    libs = [x for R in results for x in (R.get("library_panels") or [])]
    lib_ok = any(R.get("library_panels") is not None for R in results)
    dep_types = Counter(t for x in lidos for t in x["tipos_descontinuados"])
    d["dash_resumo"] = {
        "total": sum(R["dash_total"] for R in results), "analisados": len(dash), "lidos": len(lidos),
        "nao_lidos": len(dash) - len(lidos), "pastas": sum(len(R["folders"]) for R in results),
        "paineis": sum(x["paineis"] for x in lidos), "queries": sum(x["queries"] for x in lidos),
        "com_descontinuado": sum(1 for x in lidos if x["descontinuados"]), "paineis_descontinuados": sum(x["descontinuados"] for x in lidos),
        "tipos_descontinuados": dict(dep_types.most_common()), "alertas_legados": sum(x["alertas_legados"] for x in lidos),
        "na_general": sum(1 for x in lidos if x["pasta"] == "General"), "com_tag": sum(1 for x in lidos if x["tags"]),
        "com_variaveis": sum(1 for x in lidos if x["variaveis"]), "vazios": sum(1 for x in lidos if not x["paineis"]),
        "provisionados": sum(1 for x in lidos if x["provisionado"]), "quebrados": sum(1 for x in lidos if x["ds_quebrados"]),
        "refresh_agressivo": sum(1 for x in lidos if x["refresh_s"] and x["refresh_s"] < 60),
        "pesados": sum(1 for x in lidos if x["paineis"] > 50 or x["queries"] > 100),
        "parados_1a": sum(1 for x in lidos if (x["atualizado_dias"] or 0) > 365), "com_descricao": sum(1 for x in lidos if x["descricao"]),
        "acl_propria": sum(1 for x in lidos if x["acl_propria"]), "library_total": len(libs) if lib_ok else None,
        "library_sem_uso": sum(1 for x in libs if not x["conexoes"]),
        "mais_pesados": [{"titulo": x["titulo"], "pasta": pfx(x["org"], x["pasta"]), "paineis": x["paineis"], "queries": x["queries"], "refresh": x["refresh"]}
                         for x in sorted(lidos, key=lambda x: -(x["queries"] + x["paineis"]))[:15]],
    }
    agg: dict[str, Counter] = {}
    for x in lidos:
        a = agg.setdefault(pfx(x["org"], x["pasta"]), Counter())
        a["dashboards"] += 1
        a["com_tag"] += bool(x["tags"])
        a["sem_descontinuado"] += not x["descontinuados"]
        a["sem_quebrado"] += not x["ds_quebrados"]
        a["mantidos"] += (x["atualizado_dias"] or 0) <= 365
        a["provisionados"] += x["provisionado"]
        a["refresh_ok"] += not (x["refresh_s"] and x["refresh_s"] < 60)
        a["paineis"] += x["paineis"]
    d["coverage"] = {k: dict(v) for k, v in sorted(agg.items(), key=lambda kv: -kv[1]["dashboards"])}

    # Fontes de dados
    hc = [x for x in dss if x["health"] in ("OK", "ERROR")]
    by_sig = Counter(x["sinal"] for x in dss)
    d["ds_resumo"] = {
        "total": len(dss), "verificadas": len(hc), "falhas": sum(1 for x in hc if x["health"] == "ERROR"),
        "falhas_lista": [f"{x['nome']} ({x['tipo']})" for x in hc if x["health"] == "ERROR"],
        "por_sinal": dict(by_sig.most_common()), "saudaveis_por_sinal": dict(Counter(x["sinal"] for x in dss if x["health"] != "ERROR")),
        "por_tipo": dict(Counter(x["tipo_nome"] for x in dss).most_common()),
        "orgs_sem_padrao": [R["org"] for R in results if R["datasources"] and not any(x["padrao"] for x in R["datasources"])],
        "sem_uso": sum(1 for x in dss if not x["usos_dash"] and not x["usos_regras"]), "com_correlacao": sum(1 for x in dss if x["correlacao"]),
        "correlacoes": None if all(R.get("correlacoes") is None for R in results) else sum(R.get("correlacoes") or 0 for R in results),
        "tls_skip": [x["nome"] for x in dss if x["tls_skip"]], "direct": [x["nome"] for x in dss if x["acesso"] == "direct"],
        "com_url": sum(1 for x in dss if re.match(r"^https?://", x["url"] or "")),
        "http": sum(1 for x in dss if re.match(r"^http://", x["url"] or "") and not re.match(r"^http://(localhost|127\.|\[::1\])", x["url"])),
        "provisionadas": sum(1 for x in dss if x["readonly"]), "lidas": all(R["ds_lidas"] for R in results),
    }

    # Regras de alerta e alertas ativos
    ruler_ok = any(R.get("ruler") is not None or R.get("prom") is not None for R in results)
    crit_rules = [r for r in rules if r["severidade"] is not None]
    d["rules_resumo"] = {
        "coletado": ruler_ok, "total": len(rules), "grupos": len({(r["org"], r["pasta"], r["grupo"]) for r in rules}),
        "erro": sum(1 for r in rules if r["saude"] == "error"), "nodata": sum(1 for r in rules if r["saude"] == "nodata"),
        "disparando": sum(1 for r in rules if r["estado"] == "firing"), "pendentes": sum(1 for r in rules if r["estado"] == "pending"),
        "pausadas": sum(1 for r in rules if r["pausada"]), "com_severidade": len(crit_rules),
        "severidades": dict(Counter(str(r["severidade"]).lower() for r in crit_rules).most_common(8)),
        "sem_for": sum(1 for r in rules if not r["for_s"]), "agressivas": sum(1 for r in rules if r["intervalo_s"] and r["intervalo_s"] < 60),
        "com_runbook": sum(1 for r in rules if r["runbook"]), "com_resumo": sum(1 for r in rules if r["resumo"]),
        "com_dashboard": sum(1 for r in rules if r["dashboard"]),
        "erros": Counter(norm_err(r["erro"]) for r in rules if r["saude"] == "error").most_common(10),
        "intervalos": dict(Counter(f"{int(r['intervalo_s'])}s" for r in rules if r["intervalo_s"]).most_common(8)),
    }
    inst_ages = [(a, r) for r in rules for a in r["idades"]]
    has_sev = bool(crit_rules)
    d["active"] = {
        "disparando": len(inst_ages), "regras_disparando": sum(1 for r in rules if r["disparando"]),
        "mais_7d": sum(1 for a, _ in inst_ages if a > 7), "mais_30d": sum(1 for a, _ in inst_ages if a > 30),
        "criticos": sum(1 for a, r in inst_ages if r["severidade"] and CRIT_RE.match(str(r["severidade"]))) if has_sev else None,
        "criticos_24h": sum(1 for a, r in inst_ages if a > 1 and r["severidade"] and CRIT_RE.match(str(r["severidade"]))) if has_sev else None,
        "tempestade": [f"{r['titulo']} ({r['disparando']})" for r in rules if r["disparando"] > 50],
        "mais_antigos": [{"regra": r["titulo"], "pasta": pfx(r["org"], r["pasta"]), "sev": r["severidade"] or "-", "instancias": r["disparando"],
                          "dias": round(max(r["idades"]))} for r in sorted((r for r in rules if r["idades"]), key=lambda r: -max(r["idades"]))[:30]],
    }
    d["rules"] = [{k: v for k, v in r.items() if k != "idades"} for r in rules]
    d["_libs"] = [(R["org"], R.get("library_panels") or []) for R in results]
    summarize_history(d, results)

    # Notificação (agregado de todas as orgs)
    N = [R["_notif"] for R in results]
    col = [n for n in N if n["coletado"]]
    d["alerting"] = {
        "coletado": bool(col), "contact_points": sum(n["contact_points"] for n in col), "integracoes": sum(n["integracoes"] for n in col),
        "por_tipo": dict(sum((Counter(n["por_tipo"]) for n in col), Counter()).most_common()),
        "padrao": ", ".join(sorted({str(n["padrao"]) for n in col if n["padrao"]})) or "-",
        "padrao_exemplo": [R["org"] for R, n in zip(results, N) if n["padrao_exemplo"]],
        "exemplo_em_uso": sorted({x for n in col for x in n["exemplo_em_uso"]}),
        "rotas": sum(n["rotas"] for n in col), "politicas": sum(1 for n in col if n["politicas"]),
        "repeat_min_s": min((n["repeat_min_s"] for n in col if n["repeat_min_s"]), default=None), "repeat_curto": sum(n["repeat_curto"] for n in col),
        "cp_sem_uso": [pfx(R["org"], c) for R, n in zip(results, N) for c in n["cp_sem_uso"]],
        "resolve_off": sum(n["resolve_off"] for n in col), "email": any(n["email"] for n in col),
        "oncall": sorted({x for n in col for x in n["oncall"]}), "webhooks": sorted({x for n in col for x in n["webhooks"]}),
        "mute_timings": None if all(n["mute_timings"] is None for n in N) else sum(n["mute_timings"] or 0 for n in N),
        "mt_sem_uso": sorted({x for n in N for x in n["mt_sem_uso"]}),
        "templates": None if all(n["templates"] is None for n in N) else sum(n["templates"] or 0 for n in N),
        "entregas": None if all(n["entregas"] is None for n in N) else sum(n["entregas"] or 0 for n in N),
        "entregas_tentadas": sum(n["entregas_tentadas"] for n in N), "falhas": [f for n in N for f in n["falhas"]],
        "silencios_ativos": None if all(n["silencios_ativos"] is None for n in N) else sum(n["silencios_ativos"] or 0 for n in N),
        "silencios_longos": [s for n in N for s in n["silencios_longos"]],
        "alertas_am": None if all(n["alertas_am"] is None for n in N) else sum(n["alertas_am"] or 0 for n in N),
        "suprimidos": sum(n["suprimidos"] for n in N), "am_choice": ", ".join(sorted({str(n["am_choice"]) for n in N if n["am_choice"]})) or None,
    }
    hit_src = ([x["nome"] for x in dss] + [x["tipo"] for x in dss] + d["alerting"]["oncall"] + d["alerting"]["webhooks"]
               + [p["id"] for p in inst["plugins"] if not p["core"]])
    d["alerting"]["esperadas"] = {t: sorted({h for h in hit_src if t in str(h).lower()}) for t in expected}

    # Configuração do servidor
    min_ref = C("dashboards.min_refresh_interval") or fe.get("min_refresh")
    ann = {k: C(k) for k in ("annotations.dashboard.max_age", "annotations.api.max_age", "annotations.alerting.max_age")}
    d["config"] = {
        "disponivel": cfg is not None, "db_tipo": C("database.type"), "remote_cache": C("remote_cache.type"),
        "ha_peers": C("unified_alerting.ha_peers") or "", "ha_redis": C("unified_alerting.ha_redis_address") or "",
        "unified_alerting": fe.get("unified_alerting") if fe.get("unified_alerting") is not None else CB("unified_alerting.enabled"),
        "min_refresh": min_ref, "min_refresh_s": dur_s(min_ref), "log_level": (C("log.level") or "").lower() or None,
        "ann_max_age": ann, "ann_retencao": None if cfg is None else any(str(v or "").strip() not in ("", "0", "0s") for v in ann.values()),
        "versions_to_keep": i0(C("dashboards.versions_to_keep")) if C("dashboards.versions_to_keep") not in (None, "") else None,
        "smtp": CB("smtp.enabled"), "renderer": bool(fe.get("renderer")) if fe.get("renderer") is not None else (bool(C("rendering.server_url")) if cfg else None),
        "screenshots": CB("unified_alerting.screenshots.capture"), "state_history": CB("unified_alerting.state_history.enabled"),
        "root_url": C("server.root_url"), "protocol": C("server.protocol"),
    }

    # Segurança
    sso: set[str] | None = None if cfg is None and not fe else set()
    if sso is not None:
        for k, v in (cfg or {}).items():
            if k.startswith("auth.") and k.endswith(".enabled") and k not in ("auth.anonymous.enabled", "auth.basic.enabled") and truthy(v):
                sso.add(k[5:-8])
        sso.update(p for p in fe.get("oauth") or [])
        sso.update(n for n, f in (("ldap", fe.get("ldap")), ("saml", fe.get("saml")), ("proxy", fe.get("auth_proxy")), ("jwt", fe.get("jwt"))) if f)
        sso.update(str(s.get("provider")) for s in inst.get("sso") or [] if isinstance(s, dict) and (s.get("settings") or {}).get("enabled"))
    if users is None:
        merged: dict[str, dict] = {}
        for R in results:
            for u in R.get("org_users") or []:
                merged.setdefault(u["login"], {"login": u["login"], "server_admin": None, "desabilitado": u["desabilitado"], "visto_dias": u["visto_dias"], "auth": u["auth"]})
        ulist = list(merged.values()) if any(R.get("org_users") is not None for R in results) else None
    else:
        ulist = users
    act = [u for u in ulist or [] if not u["desabilitado"]]
    admin_login = str(C("security.admin_user") or "admin").lower()
    adm = next((u for u in ulist or [] if str(u["login"]).lower() == admin_login), None)
    sas = [s for R in results for s in (R.get("service_accounts") or [])]
    sa_ok = any(R.get("service_accounts") is not None for R in results)
    toks = [(s, t) for s in sas for t in s["tokens"] if not t["expirado"] and not t["revogado"]]
    keys = [k for R in results for k in (R.get("api_keys") or []) if not iso_ts(k.get("expira")) or iso_ts(k.get("expira")) > now]
    keys_ok = any(R.get("api_keys") is not None for R in results)
    pubs = [p for R in results for p in (R.get("public_dashboards") or []) if p["ativo"]]
    pub_ok = any(R.get("public_dashboards") is not None for R in results)
    snaps = [s for R in results for s in (R.get("snapshots") or [])]
    snap_ok = any(R.get("snapshots") is not None for R in results)
    perms = [(R["org"], uid, p) for R in results for uid, p in (R.get("folder_perms") or {}).items() if p is not None]
    ftitle = {(R["org"], f["uid"]): f["titulo"] for R in results for f in R["folders"]}
    teams = [t for R in results for t in (R.get("teams") or [])]
    teams_ok = any(R.get("teams") is not None for R in results)
    org_admins = [sum(1 for u in R["org_users"] if u["papel"] == "Admin" and not u["desabilitado"]) for R in results if R.get("org_users") is not None]
    ext = [p for p in inst["plugins"] if not p["core"]]
    unsigned_cfg = C("plugins.allow_loading_unsigned_plugins")
    https = str(d["meta"]["url"]).lower().startswith("https://") or str(C("server.protocol") or "").lower() in ("https", "h2") \
        or str(C("server.root_url") or "").lower().startswith("https://")
    d["security"] = {
        "usuarios": None if ulist is None else len(ulist), "usuarios_ativos": len(act),
        "ativos_30d": sum(1 for u in act if u["visto_dias"] is not None and u["visto_dias"] <= 30),
        "inativos_90d": sum(1 for u in act if u["visto_dias"] is None or u["visto_dias"] > 90),
        "inativos_lista": sorted(u["login"] for u in act if u["visto_dias"] is None or u["visto_dias"] > 90),
        "server_admins": None if users is None else sum(1 for u in act if u["server_admin"]),
        "locais": sum(1 for u in act if not u["auth"]) if ulist is not None else None,
        "org_admins_max": max(org_admins) if org_admins else None, "org_admins_total": sum(org_admins) if org_admins else None,
        "admin_user": admin_login, "admin_padrao_ativo": None if ulist is None else bool(adm and not adm["desabilitado"]),
        "anonimo": CB("auth.anonymous.enabled") if cfg is not None else fe.get("anonymous"), "anonimo_papel": C("auth.anonymous.org_role"),
        "sso": None if sso is None else sorted(sso), "cadastro_livre": CB("users.allow_sign_up"),
        "criar_org": CB("users.allow_org_create") if cfg is not None else fe.get("allow_org_create"),
        "viewers_edit": CB("users.viewers_can_edit"), "login_form_off": CB("auth.disable_login_form") if cfg is not None else fe.get("disable_login_form"),
        "basic_auth": CB("auth.basic.enabled"), "senha_politica": CB("auth.basic.password_policy"),
        "brute_force_off": CB("security.disable_brute_force_login_protection"),
        "sa_total": len(sas) if sa_ok else None, "sa_admin": sum(1 for s in sas if s["papel"] == "Admin" and not s["desabilitado"]),
        "tokens_ativos": len(toks) if sa_ok else None, "tokens_sem_expiracao": sum(1 for _, t in toks if not t["expira"]),
        "tokens_sem_uso_90d": sum(1 for _, t in toks if (t["uso_dias"] is None and (t["criado_dias"] or 0) > 90) or (t["uso_dias"] or 0) > 90),
        "tokens_sem_expiracao_lista": [f"{s['nome']} / {t['nome']}" for s, t in toks if not t["expira"]],
        "api_keys": len(keys) if keys_ok else None, "api_keys_lista": [k["nome"] for k in keys],
        "https": https, "cookie_secure": CB("security.cookie_secure"), "hsts": CB("security.strict_transport_security"),
        "embedding": CB("security.allow_embedding"), "csp": CB("security.content_security_policy"),
        "gravatar_off": CB("security.disable_gravatar"), "reporting": CB("analytics.reporting_enabled"),
        "publicos": len(pubs) if pub_ok else None, "publicos_lista": [p["titulo"] or p["dashboard"] for p in pubs],
        "snapshots": len(snaps) if snap_ok else None, "snap_externos": sum(1 for s in snaps if s["externo"]),
        "snap_sem_expiracao": sum(1 for s in snaps if not s["expira"] or s["expira"] > now + 365 * 86400),
        "snap_externo_habilitado": CB("snapshots.external_enabled"),
        "plugins_externos": len(ext), "plugins_angular": sorted(p["id"] for p in ext if p["angular"]),
        "plugins_nao_assinados": sorted(p["id"] for p in ext if str(p["assinatura"]).lower() in ("unsigned", "invalid", "modified")),
        "plugins_desatualizados": None if all(p["atualizacao"] is None for p in ext) else sorted(p["id"] for p in ext if p["atualizacao"]),
        "unsigned_permitidos": str(unsigned_cfg or "").strip(),
        "pastas_perm_lidas": len(perms), "pastas_viewer_edita": sorted(ftitle.get((o, u), u) for o, u, p in perms
                                                                        if any(x["papel"] == "Viewer" and x["permissao"] >= 2 for x in p)),
        "perm_por_time": sum(1 for _, _, p in perms if any(x["time"] for x in p)), "times": len(teams) if teams_ok else None,
        "dash_acl_propria": d["dash_resumo"]["acl_propria"], "auditoria": CB("auditing.enabled"), "router_logging": CB("server.router_logging"),
        "edicao": inst.get("edicao"),
    }
    d["platform"]["plugins_resumo"] = {"externos": len(ext), "angular": d["security"]["plugins_angular"],
                                       "nao_assinados": d["security"]["plugins_nao_assinados"], "desatualizados": d["security"]["plugins_desatualizados"]}


# Premissa de carga de consultas (consultas/min) por categoria de higiene: (fração removida, ação).
QPM_RULES: dict[str, tuple[float | None, str]] = {
    "Regra de alerta com erro": (1.00, "Corrigir consulta/fonte ou excluir a regra (avalia sem gerar alerta útil)"),
    "Intervalo de avaliação agressivo (< 1 min)": (None, "Padronizar avaliação ≥ 1 min nos grupos (exceto regras críticas justificadas)"),
    "Dashboard com refresh agressivo (< 1 min)": (None, "Refresh ≥ 1 min (ou desligado) e min_refresh_interval no servidor"),
    "Fonte de dados com falha": (0.0, "Corrigir URL/credencial/rede ou remover a fonte"),
    "Regra em NoData": (0.0, "Revisar a consulta e o tratamento de NoData (série inexistente)"),
    "Regra pausada": (0.0, "Reativar ou excluir regras pausadas"),
    "Dashboard com fonte inexistente": (0.0, "Reapontar painéis para fonte existente ou excluir o dashboard"),
    "Dashboard com painel descontinuado (Angular)": (0.0, "Migrar graph/singlestat/table-old e plugins Angular para painéis React"),
    "Dashboard vazio": (0.0, "Excluir dashboards sem painéis"),
    "Dashboard na pasta General": (0.0, "Mover para a pasta do time/serviço com permissões adequadas"),
    "Dashboard sem alteração > 1 ano": (0.0, "Validar com o dono; arquivar ou excluir se sem uso"),
    "Fonte de dados sem uso": (0.0, "Confirmar com o dono e remover fontes sem dashboards/regras"),
    "Contact point sem uso": (0.0, "Remover contact points não referenciados por políticas/regras"),
    "Library panel sem uso": (0.0, "Excluir library panels sem dashboards conectados"),
    "Silêncio de longa duração (> 30 dias)": (0.0, "Trocar por mute timing ou ajustar/desabilitar a regra"),
    "Usuário inativo > 90 dias": (0.0, "Desabilitar/remover (ou sincronizar via SSO/SCIM)"),
    "Token sem expiração": (0.0, "Recriar o token com expiração e guardar em cofre"),
    "API key legada": (0.0, "Migrar para service account com token com expiração"),
}


def build_hygiene(d: dict) -> None:
    opp: list[dict] = []
    multi = len(d["platform"]["orgs_avaliadas"]) > 1

    def grp(o: str, s: str) -> str:
        return f"{o} / {s}" if multi else s

    def add(cat, tipo, nome, grupo, det, de=None, para=None):
        opp.append({"categoria": cat, "tipo": tipo, "nome": nome, "grupo": grupo, "detalhe": det,
                    "qpm_de": None if de is None else round(de, 3), "qpm_para": None if para is None else round(para, 3)})

    qr = qd = 0.0
    for r in d["rules"]:
        iv, q = r["intervalo_s"] or 60, r["queries"] or 1
        load = q * 60 / iv
        qr += load
        g = grp(r["org"], f"{r['pasta']} / {r['grupo']}")
        if r["saude"] == "error":
            add("Regra de alerta com erro", "Regra", r["titulo"], g, r["erro"] or "erro de avaliação", load, 0.0)
        elif r["saude"] == "nodata":
            add("Regra em NoData", "Regra", r["titulo"], g, "sem dados na última avaliação")
        if r["intervalo_s"] and r["intervalo_s"] < 60 and r["saude"] != "error":
            add("Intervalo de avaliação agressivo (< 1 min)", "Regra", r["titulo"], g, f"avaliada a cada {int(iv)}s · {q} consulta(s)", load, float(q))
        if r["pausada"]:
            add("Regra pausada", "Regra", r["titulo"], g, "regra pausada")
    for x in d["dashboards"]:
        if not x["lido"]:
            continue
        g = grp(x["org"], x["pasta"])
        if x["refresh_s"] and x["queries"]:
            qd += x["queries"] * 60 / x["refresh_s"]
            if x["refresh_s"] < 60:
                add("Dashboard com refresh agressivo (< 1 min)", "Dashboard", x["titulo"], g, f"refresh {x['refresh']} · {x['queries']} consultas",
                    x["queries"] * 60 / x["refresh_s"], float(x["queries"]))
        if x["descontinuados"]:
            add("Dashboard com painel descontinuado (Angular)", "Dashboard", x["titulo"], g, f"{x['descontinuados']} painéis: {', '.join(x['tipos_descontinuados'])}")
        if x["ds_quebrados"]:
            add("Dashboard com fonte inexistente", "Dashboard", x["titulo"], g, "fonte(s): " + clip(", ".join(x["ds_quebrados"]), 120))
        if not x["paineis"]:
            add("Dashboard vazio", "Dashboard", x["titulo"], g, "sem painéis")
        if x["pasta"] == "General":
            add("Dashboard na pasta General", "Dashboard", x["titulo"], g, "fora de pasta de time/serviço")
        if (x["atualizado_dias"] or 0) > 365:
            add("Dashboard sem alteração > 1 ano", "Dashboard", x["titulo"], g, f"última alteração há {round(x['atualizado_dias'])} dias")
    for s in d["datasources"]:
        if s["health"] == "ERROR":
            add("Fonte de dados com falha", "Fonte de dados", s["nome"], grp(s["org"], s["tipo_nome"]), s["health_msg"] or "health check com erro")
        if not s["usos_dash"] and not s["usos_regras"]:
            add("Fonte de dados sem uso", "Fonte de dados", s["nome"], grp(s["org"], s["tipo_nome"]), "sem dashboards nem regras referenciando")
    for c in d["alerting"]["cp_sem_uso"]:
        add("Contact point sem uso", "Contact point", c, "—", "não referenciado pela árvore de políticas nem por regras")
    for o, libs in d.get("_libs", []):
        for lp in libs:
            if not lp["conexoes"]:
                add("Library panel sem uso", "Library panel", lp["nome"], grp(o, lp["pasta"]), "sem dashboards conectados")
    for s in d["alerting"]["silencios_longos"]:
        add("Silêncio de longa duração (> 30 dias)", "Silêncio", s["matchers"] or "(sem matchers)", s["org"], f"expira em {s['dias_restantes']} dias · {s['comentario']}")
    for u in d["security"]["inativos_lista"]:
        add("Usuário inativo > 90 dias", "Usuário", u, "—", "sem acesso há mais de 90 dias (ou nunca acessou)")
    for t in d["security"]["tokens_sem_expiracao_lista"]:
        add("Token sem expiração", "Token", t, "—", "service account token sem data de expiração")
    for k in d["security"]["api_keys_lista"]:
        add("API key legada", "API key", k, "—", "API key (descontinuada) ainda ativa")
    order = list(QPM_RULES)
    opp.sort(key=lambda o: (order.index(o["categoria"]), -(o["qpm_de"] or 0)))
    base = qr + qd
    rows: dict[str, dict] = {}
    for o in opp:
        if o["qpm_de"] is None:
            continue
        r = rows.setdefault(o["categoria"], {"categoria": o["categoria"], "acao": QPM_RULES[o["categoria"]][1], "objetos": 0, "de": 0.0, "para": 0.0})
        r["objetos"] += 1
        r["de"] += o["qpm_de"]
        r["para"] += o["qpm_para"]
    dp = [{**r, "de": round(r["de"], 1), "para": round(r["para"], 1), "reducao": round(r["de"] - r["para"], 1),
           "pct_carga": round(100 * (r["de"] - r["para"]) / base, 1) if base else None} for r in rows.values()]
    d["hygiene"] = {"oportunidades": opp, "resumo": dict(Counter(o["categoria"] for o in opp)), "de_para": sorted(dp, key=lambda r: -r["reducao"]) or None,
                    "qpm_base": round(base, 1), "qpm_regras": round(qr, 1), "qpm_dashboards": round(qd, 1)}


# --------------------------------------------------------------------------- #
# Motor de avaliação
# --------------------------------------------------------------------------- #


@dataclass
class Check:
    domain: str
    severity: str
    title: str
    passed: bool | None
    evidence: str
    impact: str
    recommendation: str
    pillar: str = ""


def _ls(items: list, n: int = 5) -> str:
    items = [str(x) for x in items if x]
    return (": " + ", ".join(items[:n]) + (f" (+{len(items) - n})" if len(items) > n else "")) if items else ""


def evaluate(d: dict) -> list[Check]:
    out: list[Check] = []
    PL, CF, DR, DS, RR = d["platform"], d["config"], d["dash_resumo"], d["ds_resumo"], d["rules_resumo"]
    AC, AL, EV, SE = d["active"], d["alerting"], d["events"], d["security"]
    ver, days = tuple(PL["ver"]), d["meta"]["days"]
    n, nd, nr = DR["lidos"], DS["total"], RR["total"]

    def add(dom, sev, title, cond, ev, impact, reco):
        out.append(Check(dom, sev, title, cond, ev, impact, reco, DOMAIN_PILLAR[dom]))

    # ---------------- Confiabilidade da plataforma ---------------- #
    sp = PL["suporte"]
    add(D_VER, "Alta", "Versão do Grafana com suporte do fabricante", sp["status"] != "EOL",
        f"Grafana {PL['versao']} ({PL['edicao']}) · suporte {sp['status']} (major vigente considerado: {sp['major_vigente']}).",
        "Versão sem suporte não recebe correções de segurança (CVE) nem de bugs críticos.",
        f"Planejar upgrade para a última minor do Grafana {sp['major_vigente']} com ensaio em homologação, backup do banco e validação de plugins.")
    if sp["status"] != "EOL":
        add(D_VER, "Baixa", "Versão no major vigente", sp["status"] == "completo", f"Grafana {PL['versao']} · suporte {sp['status']}.",
            "O major anterior recebe só correções de segurança, por tempo limitado.", "Agendar upgrade para o major vigente antes do fim do suporte.")
    if PL.get("has_update") is not None:
        add(D_VER, "Baixa", "Sem atualização pendente (patch/minor)", not PL["has_update"], f"Instalada {PL['versao']} · disponível {PL.get('latest') or '-'}.",
            "Patches trazem correções de segurança já publicadas (e exploráveis).", "Aplicar a última versão patch da linha em uso.")
    pa = SE["plugins_angular"]
    if SE["plugins_externos"]:
        add(D_VER, "Alta" if ver >= (11, 0) else "Média", "Plugins sem dependência de Angular", not pa,
            f"{len(pa)} de {SE['plugins_externos']} plugins externos dependem de Angular{_ls(pa)}.",
            "Angular fica desabilitado no Grafana 11 e foi removido no 12: esses plugins param de funcionar no upgrade.",
            "Substituir por plugins React equivalentes (ou nativos) antes do upgrade; remover os sem uso.")
        if SE["plugins_desatualizados"] is not None:
            add(D_VER, "Baixa", "Plugins atualizados", not SE["plugins_desatualizados"],
                f"{len(SE['plugins_desatualizados'])} plugins com versão mais nova disponível{_ls(SE['plugins_desatualizados'])}.",
                "Plugins desatualizados acumulam falhas de segurança e incompatibilidades.", "Atualizar plugins via grafana cli/provisioning a cada ciclo de upgrade.")
    db = (CF["db_tipo"] or "").lower()
    if db:
        add(D_HA, "Alta", "Banco de dados externo (PostgreSQL/MySQL), não SQLite", db not in ("sqlite3", "sqlite"), f"Banco de configuração: {db}.",
            "SQLite não permite múltiplas instâncias e uma falha de disco perde dashboards, usuários e regras de alerta.",
            "Migrar para PostgreSQL/MySQL com backup e réplica; então escalar para 2+ instâncias atrás de load balancer.")
        if db not in ("sqlite3", "sqlite"):
            add(D_HA, "Média", "Alerting em cluster (HA)", bool(CF["ha_peers"] or CF["ha_redis"]),
                f"ha_peers: {CF['ha_peers'] or 'vazio'} · ha_redis_address: {CF['ha_redis'] or 'vazio'}.",
                "Com uma instância, sua falha para todos os alertas; com várias sem cluster, as notificações duplicam.",
                "Rodar 2+ réplicas e configurar [unified_alerting] ha_peers (ou ha_redis_address).")
            if CF["remote_cache"] is not None:
                add(D_HA, "Baixa", "Cache remoto (Redis/Memcached)", str(CF["remote_cache"]).lower() in ("redis", "memcached"), f"remote_cache: {CF['remote_cache'] or 'database'}.",
                    "Sessões e cache no banco aumentam a carga nele quando há várias instâncias.", "Configurar [remote_cache] type = redis.")
    if PL.get("db_status"):
        add(D_HA, "Alta", "Banco de dados da instância saudável", str(PL["db_status"]).lower() == "ok", f"/api/health: database = {PL['db_status']}.",
            "Banco com falha derruba login, dashboards e avaliação de alertas.", "Investigar conectividade, espaço e locks do banco de configuração.")
    if n:
        add(D_CAP, "Média", "Dashboards sem auto-refresh agressivo (< 1 min)", pct(DR["refresh_agressivo"], n) <= 5,
            f"{DR['refresh_agressivo']} de {n} dashboards com refresh < 1 min ({pct(DR['refresh_agressivo'], n)}%).",
            "Cada tela aberta repete todas as consultas a cada poucos segundos e sobrecarrega as fontes de dados.",
            "Padronizar refresh ≥ 1 min (ou desligado) e restringir via min_refresh_interval.")
        add(D_CAP, "Média", "Dashboards sem excesso de painéis/consultas", pct(DR["pesados"], n) <= 5,
            f"{DR['pesados']} dashboards com > 50 painéis ou > 100 consultas.",
            "Dashboards pesados demoram a carregar e geram picos de consulta nas fontes.",
            "Dividir em visão geral → detalhe com links/drill-down e linhas recolhidas; usar recording rules.")
    if CF["min_refresh_s"] is not None:
        add(D_CAP, "Média", "Intervalo mínimo de refresh no servidor (≥ 10s)", CF["min_refresh_s"] >= 10, f"min_refresh_interval = {CF['min_refresh']}.",
            "Usuários conseguem configurar refresh de 1–5s e gerar carga contínua.", "Definir [dashboards] min_refresh_interval = 30s (ou 1m).")
    if nr:
        add(D_CAP, "Média", "Regras com intervalo de avaliação ≥ 1 min", pct(RR["agressivas"], nr) <= 5,
            f"{RR['agressivas']} de {nr} regras avaliadas a cada < 1 min ({pct(RR['agressivas'], nr)}%).",
            "Avaliação muito frequente multiplica consultas nas fontes sem ganho real de detecção.", "Padronizar grupos com intervalo de 1 min (ou mais).")
    if CF["log_level"]:
        add(D_CAP, "Baixa", "Log do servidor fora do modo debug", CF["log_level"] not in ("debug", "trace"), f"log.level = {CF['log_level']}.",
            "Debug gera volume alto de log, consome disco/CPU e pode registrar dados sensíveis.", "Usar log.level = info (ou warn).")
    if CF["ann_retencao"] is not None:
        a_ = CF["ann_max_age"]
        add(D_HK, "Baixa", "Retenção de anotações definida", CF["ann_retencao"],
            "max_age: " + ", ".join(f"{k.split('.')[1]}={v or 'ilimitado'}" for k, v in a_.items()) + ".",
            "Anotações (inclusive histórico de alertas) crescem sem limite no banco.", "Definir max_age (ex.: 365d) em [annotations.*].")
    if CF["versions_to_keep"] is not None:
        add(D_HK, "Baixa", "Histórico de versões de dashboards (≥ 20)", CF["versions_to_keep"] >= 20, f"versions_to_keep = {CF['versions_to_keep']}.",
            "Poucas versões impedem desfazer alterações e investigar quem mudou o quê.", "Manter versions_to_keep ≥ 20.")
    if SE["snapshots"]:
        add(D_HK, "Baixa", "Snapshots com expiração", SE["snap_sem_expiracao"] == 0, f"{SE['snap_sem_expiracao']} de {SE['snapshots']} snapshots sem expiração (> 1 ano).",
            "Snapshots guardam dados copiados indefinidamente, acessíveis por link.", "Excluir snapshots antigos e criar novos sempre com expiração.")

    # ---------------- Cobertura de observabilidade ---------------- #
    if nd:
        if DS["verificadas"]:
            add(D_DS, "Alta", "Fontes de dados saudáveis (health check)", pct(DS["falhas"], DS["verificadas"]) <= 5,
                f"{DS['falhas']} de {DS['verificadas']} fontes verificadas com falha{_ls(DS['falhas_lista'])}.",
                "Painéis e alertas dessas fontes ficam vazios: o alerta não dispara (ou vira NoData) e a falha passa despercebida.",
                "Corrigir URL/credencial/rede e monitorar a saúde das fontes (meta-monitoramento).")
        add(D_DS, "Média", "Fonte de dados padrão definida em cada organização", not DS["orgs_sem_padrao"],
            f"{len(DS['orgs_sem_padrao'])} organizações sem fonte padrão{_ls(DS['orgs_sem_padrao'])}.",
            "Painéis novos e importados ficam sem fonte e quebram silenciosamente.", "Definir a fonte de métricas principal como padrão.")
        add(D_DS, "Baixa", "Fontes de dados em uso", pct(DS["sem_uso"], nd) <= 20, f"{DS['sem_uso']} de {nd} fontes sem dashboards nem regras ({pct(DS['sem_uso'], nd)}%).",
            "Fontes órfãs guardam credenciais e ampliam superfície de ataque sem uso.", "Remover fontes sem uso após validar com os donos.")
    if n and DS["lidas"]:
        add(D_DS, "Média", "Dashboards sem referência a fonte inexistente", pct(DR["quebrados"], n) <= 2,
            f"{DR['quebrados']} de {n} dashboards referenciam fontes inexistentes ({pct(DR['quebrados'], n)}%).",
            "Painéis com fonte inexistente aparecem vazios ou com erro e confundem a operação.", "Reapontar para a fonte correta (ou variável de datasource) ou excluir.")
    if nd:
        sig = DS["por_sinal"]
        miss = [s for s in CORE_SIGNALS if not sig.get(s)]
        add(D_SIG, "Média", "Métricas, logs e traces disponíveis", not miss,
            "Fontes por sinal: " + ", ".join(f"{k} {v}" for k, v in sig.items()) + (f". Ausentes: {', '.join(miss)}." if miss else "."),
            "Sem os três sinais a investigação de incidentes depende de várias ferramentas e o MTTR aumenta.",
            "Conectar logs (Loki/Elastic) e traces (Tempo/Jaeger/OTel) e padronizar labels (service, env) entre sinais.")
        add(D_SIG, "Baixa", "Correlação entre sinais (traces ↔ logs ↔ métricas)", DS["com_correlacao"] > 0 or (DS["correlacoes"] or 0) > 0,
            f"{DS['com_correlacao']} fontes com correlação configurada (trace→logs/métricas, derived fields, exemplars) · {num(DS['correlacoes'])} correlações.",
            "Sem correlação, o time pula manualmente entre ferramentas durante o incidente.", "Configurar tracesToLogs/derivedFields/exemplars e Correlations.")
    if n:
        add(D_DASH, "Alta" if ver >= (11, 0) else "Média", "Sem painéis Angular/descontinuados", pct(DR["com_descontinuado"], n) <= 2,
            f"{DR['com_descontinuado']} de {n} dashboards com {DR['paineis_descontinuados']} painéis descontinuados"
            + _ls([f"{k} ({v})" for k, v in DR["tipos_descontinuados"].items()], 6) + ".",
            "Angular está desabilitado no Grafana 11 e removido no 12: esses painéis param de renderizar (ou já não renderizam).",
            "Migrar graph → Time series, singlestat → Stat, table-old → Table e trocar plugins Angular antes do upgrade.")
        add(D_DASH, "Média", "Dashboards organizados em pastas (fora da General)", pct(DR["na_general"], n) <= 10,
            f"{DR['na_general']} de {n} dashboards na pasta General ({pct(DR['na_general'], n)}%).",
            "Sem pastas por time/serviço não há dono claro nem permissão adequada.", "Criar pastas por time/serviço e mover os dashboards com permissões por time.")
        add(D_DASH, "Baixa", "Dashboards classificados com tags", pct(DR["com_tag"], n) >= 50, f"{DR['com_tag']} de {n} dashboards com tags ({pct(DR['com_tag'], n)}%).",
            "Sem tags a busca e a navegação dependem de conhecer o nome do dashboard.", "Padronizar tags (serviço, camada, time).")
        add(D_DASH, "Baixa", "Dashboards parametrizados com variáveis", pct(DR["com_variaveis"], n) >= 30,
            f"{DR['com_variaveis']} de {n} dashboards usam variáveis ({pct(DR['com_variaveis'], n)}%).",
            "Dashboards fixos por host/serviço se multiplicam e divergem.", "Usar variáveis (ambiente, serviço, host, datasource) e um dashboard por tipo.")
        add(D_DASH, "Baixa", "Dashboards versionados como código (provisioning/Git)", pct(DR["provisionados"], n) >= 10,
            f"{DR['provisionados']} de {n} dashboards provisionados ({pct(DR['provisionados'], n)}%).",
            "Alterações manuais sem revisão quebram dashboards críticos sem rastreabilidade.", "Versionar dashboards críticos em Git (provisioning, Terraform ou Git Sync).")
        add(D_DASH, "Baixa", "Dashboards vazios removidos", DR["vazios"] == 0, f"{DR['vazios']} dashboards sem painéis.",
            "Poluem a busca e a navegação.", "Excluir dashboards vazios.")
        add(D_DASH, "Baixa", "Sem alertas legados residuais nos painéis", DR["alertas_legados"] == 0, f"{DR['alertas_legados']} painéis com alerta legado (pré-Unified Alerting).",
            "Alertas legados não são avaliados a partir do Grafana 11: a falsa sensação de cobertura esconde lacunas.",
            "Confirmar a migração para Unified Alerting e remover a configuração legada dos painéis.")
    if DR["library_total"]:
        add(D_DASH, "Baixa", "Library panels em uso", DR["library_sem_uso"] == 0, f"{DR['library_sem_uso']} de {DR['library_total']} library panels sem dashboards conectados.",
            "Componentes órfãos confundem a padronização.", "Excluir library panels sem uso.")
    if n:
        add(D_ADOPT, "Baixa", "Dashboards mantidos (alterados no último ano)", pct(DR["parados_1a"], n) <= 30,
            f"{DR['parados_1a']} de {n} dashboards sem alteração há mais de 1 ano ({pct(DR['parados_1a'], n)}%).",
            "Dashboards abandonados mostram métricas obsoletas e dificultam achar o que importa.", "Revisar com os donos; arquivar o que não é usado.")
        add(D_ADOPT, "Baixa", "Dashboards com descrição (contexto/dono)", pct(DR["com_descricao"], n) >= 30,
            f"{DR['com_descricao']} de {n} dashboards com descrição ({pct(DR['com_descricao'], n)}%).",
            "Sem contexto, quem chega no plantão não sabe para que serve nem a quem perguntar.", "Descrever objetivo, dono e links (runbook, serviço).")
    if SE["usuarios_ativos"]:
        add(D_ADOPT, "Baixa", "Usuários ativos nos últimos 30 dias", pct(SE["ativos_30d"], SE["usuarios_ativos"]) >= 30,
            f"{SE['ativos_30d']} de {SE['usuarios_ativos']} usuários habilitados acessaram nos últimos 30 dias ({pct(SE['ativos_30d'], SE['usuarios_ativos'])}%).",
            "Baixa adoção indica que a ferramenta não está no fluxo de operação.", "Levar os dashboards para rituais (daily, NOC, postmortem) e treinar os times.")

    # ---------------- Qualidade de alertas ---------------- #
    if CF["unified_alerting"] is not None:
        add(D_RULE, "Alta", "Unified Alerting habilitado", bool(CF["unified_alerting"]), f"Unified Alerting {'habilitado' if CF['unified_alerting'] else 'desabilitado'}.",
            "O alerting legado foi removido no Grafana 11; sem Unified Alerting não há regras, roteamento nem silêncios modernos.",
            "Habilitar Unified Alerting e migrar as regras legadas.")
    if RR["coletado"]:
        add(D_RULE, "Média", "Regras de alerta configuradas no Grafana", nr > 0, f"{nr} regras de alerta em {RR['grupos']} grupos.",
            "Sem regras, dashboards são só visualização: falhas dependem de alguém olhando a tela.",
            "Criar regras para os sinais dourados dos serviços críticos (ou documentar que o alerting é feito em outra ferramenta, ex.: Zabbix).")
    if nr:
        add(D_RULE, "Alta", "Regras sem erro de avaliação", pct(RR["erro"], nr) <= 2,
            f"{RR['erro']} de {nr} regras com erro de avaliação" + (f". Erro mais comum: {RR['erros'][0][0]}" if RR["erros"] else "") + ".",
            "Regra com erro não detecta a falha que deveria: lacuna silenciosa de monitoramento.", "Corrigir consultas/fontes e alertar sobre regras em erro.")
        add(D_RULE, "Média", "Regras sem NoData", pct(RR["nodata"], nr) <= 5, f"{RR['nodata']} de {nr} regras em NoData.",
            "NoData persistente indica consulta quebrada ou série que deixou de existir.", "Revisar consultas e definir o tratamento de NoData por regra.")
        add(D_RULE, "Média", "Regras com label de severidade", pct(RR["com_severidade"], nr) >= 80,
            f"{RR['com_severidade']} de {nr} regras com label de severidade ({pct(RR['com_severidade'], nr)}%).",
            "Sem severidade, roteamento, priorização e escalonamento não funcionam.", "Padronizar label severity (critical/warning/info) alinhado à matriz do ITSM.")
        add(D_RULE, "Baixa", "Regras pausadas sob controle", pct(RR["pausadas"], nr) <= 10, f"{RR['pausadas']} de {nr} regras pausadas.",
            "Regras pausadas esquecidas viram lacunas de cobertura.", "Revisar regras pausadas: reativar ou excluir.")
        add(D_NOISE, "Média", "Regras com período de pendência (for ≥ 1 min)", pct(RR["sem_for"], nr) <= 20,
            f"{RR['sem_for']} de {nr} regras sem período de pendência (for = 0).", "Sem 'for', qualquer pico momentâneo notifica e gera ruído.",
            "Definir 'for' de 1–5 min conforme a criticidade.")
    if EV["total"] >= 50 and EV["top_regras"]:
        top = EV["top_regras"][0]
        add(D_NOISE, "Média", "Ruído de alertas concentrado", pct(top["disparos"], EV["total"]) < 20,
            f"{num(EV['total'])} disparos em {days}d ({num(EV['por_dia'], 1)}/dia); a regra mais frequente (\"{clip(top['regra'], 60)}\") responde por {pct(top['disparos'], EV['total'])}%.",
            "Alertas repetitivos geram fadiga e reduzem a confiança no monitoramento.", "Ajustar limiares/histerese, usar janelas (avg/min) e tratar a causa raiz recorrente.")
    if nr and EV["transicoes"]:
        add(D_NOISE, "Média", "Regras em flapping", pct(EV["flapping_total"], nr) <= 2,
            f"{EV['flapping_total']} regras com ≥ 10 disparos e duração mediana < 10 min em {days}d.",
            "Flapping gera notificações em rajada sem incidente real.", "Adicionar 'for', histerese (keep firing for) e janelas de avaliação maiores.")
    if EV["resolvidos"] >= 20:
        add(D_NOISE, "Baixa", "Alertas de curta duração (< 5 min)", pct(EV["curta_duracao"], EV["resolvidos"]) <= 30,
            f"{pct(EV['curta_duracao'], EV['resolvidos'])}% dos alertas resolvidos duraram menos de 5 minutos.",
            "Alertas que se resolvem sozinhos raramente exigem ação humana.", "Aumentar 'for'/janela ou atrasar a notificação (group_wait).")
    if nr and CF["state_history"] is False:
        add(D_NOISE, "Baixa", "Histórico de estados de alerta habilitado", False, "[unified_alerting.state_history] desabilitado.",
            "Sem histórico não há como medir ruído, MTTR nem auditar disparos.", "Habilitar state_history (backend annotations ou Loki).")
    if nr:
        f_ = AC["disparando"]
        if f_:
            add(D_STATE, "Média", "Alertas disparando há mais de 30 dias", pct(AC["mais_30d"], f_) <= 10,
                f"{AC['mais_30d']} de {f_} instâncias disparando há mais de 30 dias ({pct(AC['mais_30d'], f_)}%).",
                "Alertas eternos viram paisagem e escondem incidentes novos.", "Resolver a causa, ajustar o limiar ou desabilitar regras sem ação.")
        add(D_STATE, "Média", "Sem tempestade de instâncias (regra com > 50 alertas)", not AC["tempestade"],
            f"{len(AC['tempestade'])} regras com mais de 50 instâncias disparando{_ls(AC['tempestade'])}.",
            "Uma causa comum gera dezenas de notificações e esconde o problema real.", "Agrupar por labels (group_by), usar regras agregadas e inibição.")
        if AC["criticos"] is not None:
            add(D_STATE, "Alta", "Alertas críticos tratados em até 24h", AC["criticos_24h"] == 0,
                f"{AC['criticos']} instâncias críticas disparando; {AC['criticos_24h']} há mais de 24h.",
                "Alerta crítico sem tratamento indica alerta ignorado ou ruído normalizado.", "Definir dono e SLA por severidade; integrar com ITSM/on-call.")

    # ---------------- Resposta e operação ---------------- #
    if AL["coletado"]:
        add(D_NOTIF, "Alta", "Política padrão com contact point real (não o e-mail de exemplo)", not AL["padrao_exemplo"] and not AL["exemplo_em_uso"],
            f"Contact point padrão: {AL['padrao']}" + (f" · e-mail de exemplo em uso{_ls(AL['exemplo_em_uso'] or AL['padrao_exemplo'])}" if AL["padrao_exemplo"] or AL["exemplo_em_uso"] else "") + ".",
            "Alertas sem rota específica vão para <example@email.com>: ninguém é notificado.", "Configurar o contact point padrão para o time de plataforma/NOC.")
        add(D_NOTIF, "Média", "Roteamento por labels (políticas específicas)", AL["rotas"] > 0, f"{AL['rotas']} políticas de notificação abaixo da padrão.",
            "Todos os alertas vão para o mesmo destino, sem separação por time/serviço/severidade.", "Criar políticas por labels (team, service, severity) com destinos por time.")
        add(D_NOTIF, "Baixa", "Repeat interval ≥ 1h", AL["repeat_curto"] == 0, f"{AL['repeat_curto']} políticas com repeat_interval < 1h (mínimo {num((AL['repeat_min_s'] or 0) / 60)} min).",
            "Reenvio frequente do mesmo alerta gera fadiga.", "Usar repeat_interval de 4h (padrão) e escalonamento no on-call.")
        if AL["integracoes"]:
            add(D_NOTIF, "Baixa", "Notificação de resolução habilitada", pct(AL["resolve_off"], AL["integracoes"]) <= 20,
                f"{AL['resolve_off']} de {AL['integracoes']} integrações sem mensagem de resolução.", "O time não sabe quando o problema normalizou.",
                "Habilitar a notificação de resolução (disableResolveMessage = false).")
        if AL["email"] and CF["smtp"] is not None:
            add(D_NOTIF, "Alta", "SMTP configurado para os contact points de e-mail", bool(CF["smtp"]), f"[smtp] {'habilitado' if CF['smtp'] else 'desabilitado'} · há contact points de e-mail.",
                "Contact points de e-mail sem SMTP não entregam nada.", "Configurar [smtp] com relay corporativo autenticado.")
        add(D_NOTIF, "Baixa", "Contact points em uso", not AL["cp_sem_uso"], f"{len(AL['cp_sem_uso'])} contact points sem uso{_ls(AL['cp_sem_uso'])}.",
            "Configuração órfã confunde quem mantém o roteamento.", "Remover contact points não referenciados.")
    if AL["entregas"] is not None and AL["entregas_tentadas"]:
        fl = AL["falhas"]
        add(D_NOTIF, "Alta", "Notificações entregues sem falha", not fl,
            f"{len(fl)} integrações com erro na última tentativa de envio"
            + _ls([(f"{f['org']} / " if len(PL["orgs_avaliadas"]) > 1 else "") + f"{f['receiver']} ({f['tipo']})" for f in fl]) + (f". Erro: {fl[0]['erro']}" if fl else "") + ".",
            "Alerta que não chega equivale a não ter monitoramento.", "Corrigir credenciais/URLs dos contact points e monitorar falhas de notificação.")
    if AL["coletado"]:
        add(D_INT, "Média", "Integração com ITSM/on-call/chat", bool(AL["oncall"]),
            f"Integrações detectadas: {', '.join(AL['oncall'][:8]) or 'nenhuma'} · webhooks: {len(AL['webhooks'])}.",
            "Sem integração, incidentes não são abertos automaticamente e o acionamento 24x7 depende de e-mail.",
            "Integrar com o ITSM (ServiceNow/Jira/GLPI) e on-call (Grafana OnCall/PagerDuty/Opsgenie/Teams).")
        if AL["templates"] is not None:
            add(D_INT, "Baixa", "Templates de notificação padronizados", AL["templates"] > 0, f"{AL['templates']} templates de notificação.",
                "Mensagens genéricas obrigam o plantonista a abrir o Grafana para entender o alerta.", "Criar templates com resumo, severidade, runbook e link do painel.")
    for t, hit in (AL.get("esperadas") or {}).items():
        add(D_INT, "Média", f"Integração Grafana ↔ {t.title()} detectada", bool(hit), ("Referências: " + ", ".join(hit[:6]) + ".") if hit else "Nenhuma fonte, plugin ou contact point com referência.",
            f"Dados/alertas não circulam entre Grafana e {t.title()}: sem correlação com o restante da operação.",
            f"Configurar a fonte de dados/plugin ou contact point oficial do {t.title()} e testar ponta a ponta.")
    if AL["mute_timings"] is not None:
        add(D_MAINT, "Baixa", "Mute timings (janelas de manutenção recorrentes)", AL["mute_timings"] > 0, f"{AL['mute_timings']} mute timings configurados.",
            "Manutenções programadas geram alertas falsos ou exigem silêncio manual a cada janela.", "Criar mute timings para janelas recorrentes e associá-los às políticas.")
    if AL["silencios_ativos"] is not None:
        add(D_MAINT, "Média", "Silêncios ativos com prazo ≤ 30 dias", not AL["silencios_longos"],
            f"{len(AL['silencios_longos'])} de {AL['silencios_ativos']} silêncios ativos expiram em mais de 30 dias.",
            "Silêncio longo é um alerta desligado na prática, sem revisão.", "Usar silêncios curtos com justificativa; para recorrência, mute timing ou ajuste da regra.")
    if nr:
        add(D_RUN, "Média", "Regras com runbook (runbook_url)", pct(RR["com_runbook"], nr) >= 50, f"{RR['com_runbook']} de {nr} regras com runbook ({pct(RR['com_runbook'], nr)}%).",
            "Sem runbook o plantonista improvisa e o MTTR aumenta.", "Criar runbooks para as regras críticas e preencher runbook_url.")
        add(D_RUN, "Média", "Regras com resumo/descrição", pct(RR["com_resumo"], nr) >= 80, f"{RR['com_resumo']} de {nr} regras com summary/description ({pct(RR['com_resumo'], nr)}%).",
            "A notificação chega sem dizer o que está errado nem o impacto.", "Preencher summary/description com impacto e próximos passos.")
        add(D_RUN, "Baixa", "Regras vinculadas a dashboard/painel", pct(RR["com_dashboard"], nr) >= 30, f"{RR['com_dashboard']} de {nr} regras ligadas a um painel.",
            "Sem o painel, quem recebe o alerta perde tempo procurando o contexto.", "Vincular a regra ao painel (dashboard UID/panel ID).")
        if CF["renderer"] is not None:
            img = bool(CF["renderer"]) and CF["screenshots"] is not False
            add(D_RUN, "Baixa", "Imagens de painel nas notificações", img,
                f"Image renderer: {'disponível' if CF['renderer'] else 'ausente'} · screenshots: {'N/D' if CF['screenshots'] is None else 'sim' if CF['screenshots'] else 'não'}.",
                "Sem imagem, a notificação não mostra a tendência que disparou o alerta.", "Instalar o grafana-image-renderer e habilitar [unified_alerting.screenshots] capture.")

    # ---------------- Segurança e governança ---------------- #
    if SE["anonimo"] is not None:
        add(D_IAM, "Alta", "Acesso anônimo desabilitado", not SE["anonimo"],
            f"auth.anonymous {'habilitado' + (' (papel ' + str(SE['anonimo_papel']) + ')' if SE['anonimo_papel'] else '') if SE['anonimo'] else 'desabilitado'}.",
            "Qualquer pessoa na rede vê dashboards, consultas e topologia sem login.", "Desabilitar [auth.anonymous]; usar dashboards públicos só quando aprovado.")
    if SE["sso"] is not None:
        add(D_IAM, "Alta", "Autenticação centralizada (LDAP/OAuth/SAML)", bool(SE["sso"]), f"Provedores habilitados: {', '.join(SE['sso']) or 'nenhum (só contas locais)'}.",
            "Contas locais não acompanham desligamentos nem a política corporativa de senha/MFA.", "Integrar com AD/Entra ID (LDAP, OAuth ou SAML) com mapeamento de grupos para papéis.")
    if SE["admin_padrao_ativo"] is not None:
        add(D_IAM, "Média", f"Usuário '{SE['admin_user']}' padrão desabilitado ou renomeado", not SE["admin_padrao_ativo"],
            f"Usuário '{SE['admin_user']}' {'ativo' if SE['admin_padrao_ativo'] else 'inexistente/desabilitado'}.",
            "Conta padrão conhecida é o primeiro alvo de força bruta.", "Criar admins nominais e desabilitar/renomear a conta padrão (guardar senha em cofre).")
    if SE["cadastro_livre"] is not None:
        add(D_IAM, "Média", "Auto-cadastro de usuários desabilitado", not SE["cadastro_livre"] and not SE["criar_org"],
            f"allow_sign_up: {'sim' if SE['cadastro_livre'] else 'não'} · allow_org_create: {'sim' if SE['criar_org'] else 'não'}.",
            "Qualquer pessoa cria conta/organização sem aprovação.", "Desabilitar allow_sign_up e allow_org_create.")
    if SE["server_admins"] is not None and SE["usuarios_ativos"]:
        add(D_IAM, "Média", "Grafana Admins (server admin) restritos", SE["server_admins"] <= max(3, round(0.05 * SE["usuarios_ativos"])),
            f"{SE['server_admins']} server admins entre {SE['usuarios_ativos']} usuários habilitados.",
            "Server admin controla todas as orgs, usuários e plugins: alto raio de impacto se a conta vazar.", "Limitar a 2–3 contas nominais com MFA via IdP.")
    if SE["org_admins_max"] is not None and SE["usuarios_ativos"]:
        add(D_IAM, "Baixa", "Admins de organização restritos", SE["org_admins_max"] <= max(5, round(0.1 * SE["usuarios_ativos"])),
            f"Até {SE['org_admins_max']} admins em uma organização ({SE['org_admins_total']} no total).",
            "Admins de org alteram fontes de dados, alerting e permissões.", "Aplicar menor privilégio: Editor por pasta via times.")
    if SE["usuarios_ativos"]:
        add(D_IAM, "Média", "Usuários inativos (> 90 dias) desabilitados", pct(SE["inativos_90d"], SE["usuarios_ativos"]) <= 10,
            f"{SE['inativos_90d']} de {SE['usuarios_ativos']} usuários habilitados sem acesso há mais de 90 dias ({pct(SE['inativos_90d'], SE['usuarios_ativos'])}%).",
            "Contas esquecidas (ex.: desligados) continuam com acesso.", "Desabilitar inativos periodicamente ou sincronizar via SSO/SCIM.")
        if SE["sso"] and SE["locais"] is not None:
            add(D_IAM, "Baixa", "Contas locais restritas a emergência", SE["locais"] <= max(3, round(0.05 * SE["usuarios_ativos"])),
                f"{SE['locais']} contas locais habilitadas com SSO disponível.", "Contas locais fogem da política de MFA/desligamento do IdP.",
                "Migrar usuários para o SSO e manter só 1–2 contas de emergência.")
    if SE["api_keys"] is not None:
        add(D_IAM, "Média", "API keys legadas migradas para service accounts", SE["api_keys"] == 0, f"{SE['api_keys']} API keys ativas{_ls(SE['api_keys_lista'])}.",
            "API keys são descontinuadas, não têm dono e raramente expiram.", "Migrar para service accounts com tokens com expiração.")
    if SE["tokens_ativos"]:
        add(D_IAM, "Média", "Tokens de service account com expiração", SE["tokens_sem_expiracao"] == 0,
            f"{SE['tokens_sem_expiracao']} de {SE['tokens_ativos']} tokens ativos sem expiração.", "Token vazado sem expiração dá acesso permanente à API.",
            "Definir expiração (≤ 1 ano), rotacionar e guardar em cofre.")
        add(D_IAM, "Baixa", "Tokens sem uso revogados", SE["tokens_sem_uso_90d"] == 0, f"{SE['tokens_sem_uso_90d']} tokens ativos sem uso há mais de 90 dias.",
            "Credenciais órfãs aumentam a superfície de ataque.", "Revogar tokens sem uso.")
    if SE["sa_total"]:
        add(D_IAM, "Baixa", "Service accounts com menor privilégio", pct(SE["sa_admin"], SE["sa_total"]) <= 30,
            f"{SE['sa_admin']} de {SE['sa_total']} service accounts com papel Admin.", "Automação com Admin pode alterar qualquer coisa na org.",
            "Usar Viewer/Editor por padrão e Admin só quando necessário.")
    if SE["brute_force_off"] is not None:
        add(D_IAM, "Média", "Proteção contra força bruta no login", not SE["brute_force_off"],
            f"disable_brute_force_login_protection = {'true' if SE['brute_force_off'] else 'false'}.", "Senhas podem ser testadas sem limite.",
            "Manter a proteção habilitada.")
    if SE["senha_politica"] is not None and not SE["login_form_off"] and (not SE["sso"] or SE["locais"]):
        add(D_IAM, "Baixa", "Política de senha forte (contas locais)", bool(SE["senha_politica"]), f"[auth.basic] password_policy = {'true' if SE['senha_politica'] else 'false'}.",
            "Senhas fracas facilitam força bruta.", "Habilitar password_policy (12+ caracteres com complexidade).")
    add(D_EXP, "Alta", "Acesso ao Grafana via HTTPS", SE["https"],
        f"URL avaliada: {d['meta']['url']} · protocol: {CF['protocol'] or 'N/D'} · root_url: {CF['root_url'] or 'N/D'}.",
        "Senhas, cookies de sessão e dados trafegam em texto claro.", "Publicar o Grafana somente em HTTPS (proxy reverso ou protocol = https).")
    if SE["cookie_secure"] is not None and SE["https"]:
        add(D_EXP, "Média", "Cookies seguros (cookie_secure)", SE["cookie_secure"], f"cookie_secure = {'true' if SE['cookie_secure'] else 'false'}.",
            "O cookie de sessão pode ser enviado em HTTP e interceptado.", "Definir [security] cookie_secure = true.")
    if SE["hsts"] is not None and SE["https"]:
        add(D_EXP, "Baixa", "HSTS habilitado", SE["hsts"], f"strict_transport_security = {'true' if SE['hsts'] else 'false'}.",
            "O navegador aceita downgrade para HTTP.", "Habilitar strict_transport_security (ou no proxy reverso).")
    if SE["embedding"] is not None:
        add(D_EXP, "Média", "Embedding desabilitado (anti-clickjacking)", not SE["embedding"], f"allow_embedding = {'true' if SE['embedding'] else 'false'}.",
            "Permite clickjacking; com acesso anônimo, expõe dashboards em sites de terceiros.", "Manter allow_embedding = false (ou restringir no proxy por origem).")
    if SE["csp"] is not None:
        add(D_EXP, "Baixa", "Content Security Policy habilitada", SE["csp"], f"content_security_policy = {'true' if SE['csp'] else 'false'}.",
            "Sem CSP, painéis com HTML/JS injetado têm mais impacto (XSS).", "Habilitar content_security_policy.")
    if SE["publicos"] is not None:
        add(D_EXP, "Média", "Dashboards públicos sob controle", SE["publicos"] == 0, f"{SE['publicos']} dashboards públicos ativos{_ls(SE['publicos_lista'])}.",
            "Dashboard público é acessível sem login por quem tiver o link.", "Revisar cada dashboard público com o dono dos dados; desativar os não aprovados.")
    if SE["snap_externo_habilitado"] is not None:
        add(D_EXP, "Média", "Snapshots externos desabilitados", not SE["snap_externo_habilitado"],
            f"snapshots.external_enabled = {'true' if SE['snap_externo_habilitado'] else 'false'} · {SE['snap_externos']} snapshots externos.",
            "Usuários podem publicar dados internos em serviço externo (snapshots.raintank.io).", "Definir [snapshots] external_enabled = false.")
    if nd:
        add(D_EXP, "Média", "Fontes de dados validando certificado TLS", not DS["tls_skip"], f"{len(DS['tls_skip'])} fontes com tlsSkipVerify{_ls(DS['tls_skip'])}.",
            "Conexão sujeita a interceptação (man-in-the-middle) com as credenciais da fonte.", "Instalar a CA interna (tlsAuthWithCACert) e desligar tlsSkipVerify.")
        add(D_EXP, "Média", "Fontes de dados acessadas pelo servidor (sem modo browser)", not DS["direct"], f"{len(DS['direct'])} fontes em modo browser/direct{_ls(DS['direct'])}.",
            "No modo browser a fonte precisa ficar exposta à rede dos usuários e as credenciais vão ao navegador.", "Trocar para acesso Server (proxy).")
        if DS["com_url"]:
            add(D_EXP, "Baixa", "Fontes de dados com transporte criptografado (https)", pct(DS["http"], DS["com_url"]) <= 20,
                f"{DS['http']} de {DS['com_url']} fontes com URL http:// (fora de localhost).", "Consultas e credenciais da fonte trafegam em texto claro.",
                "Habilitar TLS nas fontes (ou mTLS na malha interna).")
    if SE["plugins_externos"]:
        bad = SE["plugins_nao_assinados"]
        add(D_EXP, "Média", "Plugins assinados (sem plugins não assinados)", not bad and not SE["unsigned_permitidos"],
            f"{len(bad)} plugins não assinados{_ls(bad)}" + (f" · allow_loading_unsigned_plugins = {SE['unsigned_permitidos']}" if SE["unsigned_permitidos"] else "") + ".",
            "Plugin não assinado pode ter sido alterado e roda com acesso aos dados do Grafana.", "Usar só plugins assinados do catálogo; remover a exceção de não assinados.")
    if SE["gravatar_off"] is not None:
        add(D_EXP, "Baixa", "Sem chamadas a serviços externos (Gravatar/analytics)", bool(SE["gravatar_off"]) and not SE["reporting"],
            f"disable_gravatar = {'true' if SE['gravatar_off'] else 'false'} · reporting_enabled = {'true' if SE['reporting'] else 'false'}.",
            "Navegadores e servidor contactam serviços externos com dados de uso (e-mails em hash).", "Definir disable_gravatar = true e reporting_enabled = false.")
    if SE["pastas_perm_lidas"]:
        add(D_AUD, "Média", "Pastas sem edição liberada a Viewers", not SE["pastas_viewer_edita"],
            f"{len(SE['pastas_viewer_edita'])} de {SE['pastas_perm_lidas']} pastas dão Edit/Admin ao papel Viewer{_ls(SE['pastas_viewer_edita'])}.",
            "Qualquer usuário pode alterar ou apagar dashboards dessas pastas.", "Conceder edição só a times donos da pasta.")
    if SE["times"] is not None:
        add(D_AUD, "Baixa", "Acesso gerenciado por times (teams)", SE["times"] > 0 and SE["perm_por_time"] > 0,
            f"{SE['times']} times · {SE['perm_por_time']} pastas com permissão por time.", "Permissão por usuário individual não escala e fica desatualizada.",
            "Criar times (sincronizados do IdP quando possível) e dar permissão por pasta aos times.")
    if SE["viewers_edit"] is not None:
        add(D_AUD, "Baixa", "Viewers sem edição temporária (viewers_can_edit)", not SE["viewers_edit"], f"viewers_can_edit = {'true' if SE['viewers_edit'] else 'false'}.",
            "Viewers podem editar consultas no Explore/painéis e consultar qualquer coisa nas fontes.", "Manter viewers_can_edit = false.")
    if SE["auditoria"] is not None:
        add(D_AUD, "Média", "Audit log habilitado (Enterprise)", SE["auditoria"], f"[auditing] enabled = {'true' if SE['auditoria'] else 'false'}.",
            "Sem trilha de quem alterou dashboards, fontes, usuários e permissões.", "Habilitar [auditing] e enviar para o SIEM.")
    if SE["router_logging"] is not None:
        add(D_AUD, "Baixa", "Log de acesso HTTP (router_logging)", SE["router_logging"], f"router_logging = {'true' if SE['router_logging'] else 'false'}.",
            "Sem log de acesso, investigação de incidente de segurança fica limitada.", "Habilitar router_logging e enviar os logs ao SIEM.")
    return out


def score(checks: list[Check], key: str = "domain") -> tuple[dict[str, int], int]:
    acc: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for c in checks:
        if c.passed is None:
            continue
        w = SEV_W[c.severity]
        k = getattr(c, key)
        acc[k][1] += w
        acc[k][0] += w if c.passed else 0
    dom = {k: pct(a, b) for k, (a, b) in acc.items() if b}
    ta, tb = sum(a for a, _ in acc.values()), sum(b for _, b in acc.values())
    return dom, pct(ta, tb)


def score_actions(checks: list[Check], pillar: str) -> list[dict]:
    """Para cada lacuna do pilar: score do pilar e global se só ela fosse resolvida, e o acumulado resolvendo em ordem de ganho."""
    pil0, _ = score(checks, "pillar")
    _, ov0 = score(checks)

    def sim(fixed: set[int]) -> tuple[int, int]:
        cs = [replace(c, passed=True) if i in fixed else c for i, c in enumerate(checks)]
        p, _ = score(cs, "pillar")
        _, o = score(cs)
        return p.get(pillar, 0), o

    gaps = [i for i, c in enumerate(checks) if c.pillar == pillar and c.passed is False]
    rows = []
    for i in gaps:
        p, o = sim({i})
        rows.append({"idx": i, "check": checks[i], "pilar_de": pil0.get(pillar, 0), "pilar_para": p, "global_de": ov0, "global_para": o})
    rows.sort(key=lambda r: (-(r["global_para"] - r["global_de"]), -(r["pilar_para"] - r["pilar_de"]), SEV_ORDER[r["check"].severity]))
    fixed: set[int] = set()
    for r in rows:
        fixed.add(r["idx"])
        r["pilar_acum"], r["global_acum"] = sim(fixed)
    return rows


def level(sc: int) -> str:
    return "Inicial" if sc < 40 else "Em desenvolvimento" if sc < 65 else "Estruturado" if sc < 85 else "Otimizado"


# --------------------------------------------------------------------------- #
# Relatório HTML
# --------------------------------------------------------------------------- #

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--tx:#1b1f24;--mut:#667085;--bd:#e4e7ec;--ok:#12805c;--warn:#b54708;--bad:#c01048;--acc:#e8590c}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--tx:#e8eaed;--mut:#9aa3b2;--bd:#262b36;--ok:#3ddc97;--warn:#ffb020;--bad:#ff6b8b;--acc:#ff8a3d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1120px;margin:0 auto;padding:32px 20px 64px}h1{margin:0 0 4px;font-size:28px}h2{margin:40px 0 14px;font-size:20px}h3{margin:18px 0 8px;font-size:15px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.sub{color:var(--mut)}.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:18px 20px;overflow-x:auto}
.grid{display:grid;gap:14px}.g4{grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}.g2{grid-template-columns:repeat(auto-fit,minmax(min(340px,100%),1fr))}
.kpi b{display:block;font-size:28px;line-height:1.2}.kpi span{color:var(--mut);font-size:13px}
.hero{display:flex;gap:28px;align-items:center;flex-wrap:wrap}.ring{--p:0;--c:var(--ok);width:130px;height:130px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--p)*3.6deg),var(--bd) 0);display:grid;place-items:center;flex:none}
.ring i{font-style:normal;width:98px;height:98px;border-radius:50%;background:var(--card);display:grid;place-items:center;font-size:30px;font-weight:700}
.bar{height:8px;background:var(--bd);border-radius:6px;overflow:hidden}.bar i{display:block;height:100%}
.row{display:grid;grid-template-columns:minmax(120px,220px) 1fr 44px;gap:12px;align-items:center;margin:9px 0}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--bd);vertical-align:top}th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase}
.badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600;white-space:nowrap}
.Alta,.nao{background:color-mix(in srgb,var(--bad) 16%,transparent);color:var(--bad)}.Média,.parcial{background:color-mix(in srgb,var(--warn) 16%,transparent);color:var(--warn)}
.Baixa,.nd{background:var(--bd);color:var(--mut)}.sim{background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)}
ul{margin:6px 0;padding-left:20px}.mut{color:var(--mut)}.road{border-left:4px solid var(--bd)}
@media print{body{background:#fff}.card{break-inside:avoid}}
"""


def esc(x: Any) -> str:
    return html.escape(str(x))


def color(sc: int) -> str:
    return "var(--ok)" if sc >= 75 else "var(--warn)" if sc >= 50 else "var(--bad)"


def table(headers: list[str], rows: list[list[Any]], raw: bool = False) -> str:
    if not rows:
        return '<p class="mut">Sem dados.</p>'
    th = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c if raw else esc(c)}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def badge(txt: str, cls: str | None = None) -> str:
    return f'<span class="badge {cls or txt}">{esc(txt)}</span>'


def dict_rows(d: dict | None) -> list[list[Any]]:
    return [[k, v] for k, v in sorted((d or {}).items(), key=lambda kv: -kv[1] if isinstance(kv[1], (int, float)) else 0)]


def cov_badge(n: int, t: int) -> str:
    p = pct(n, t)
    return badge(f"{n}/{t} · {p}%", "sim" if p >= 80 else "parcial" if p >= 40 else "nao")


def yn(v: Any) -> str:
    return "N/D" if v is None else "sim" if v else "não"


def health_badge(h: str | None) -> str:
    return badge("OK", "sim") if h == "OK" else badge("falha", "nao") if h == "ERROR" else badge("N/D", "nd")


def capability_items(d: dict) -> list[tuple[str, Any]]:
    PL, DR, DS, AL, SE, CF, RR = d["platform"], d["dash_resumo"], d["ds_resumo"], d["alerting"], d["security"], d["config"], d["rules_resumo"]
    sig, col = DS["por_sinal"], AL["coletado"]
    db = (CF["db_tipo"] or "").lower()
    return [
        ("Organizações avaliadas", len(PL["orgs_avaliadas"])), ("Pastas", DR["pastas"]), ("Dashboards", DR["total"]),
        ("Dashboards como código (provisionados)", DR["provisionados"]), ("Library panels", DR["library_total"]),
        ("Fontes de métricas", sig.get("Métricas", 0)), ("Fontes de logs", sig.get("Logs", 0)), ("Fontes de traces", sig.get("Traces", 0)),
        ("Fontes de perfis (profiling)", sig.get("Perfis", 0)), ("Correlação entre sinais", DS["com_correlacao"] + (DS["correlacoes"] or 0)),
        ("Regras de alerta", RR["total"] if RR["coletado"] else None), ("Contact points", AL["contact_points"] if col else None),
        ("Políticas de notificação específicas", AL["rotas"] if col else None), ("Mute timings", AL["mute_timings"]),
        ("Templates de notificação", AL["templates"]), ("Integrações ITSM/on-call/chat", len(AL["oncall"]) if col else None),
        ("Image renderer", None if CF["renderer"] is None else int(bool(CF["renderer"]))),
        ("Banco externo (PostgreSQL/MySQL)", None if not db else int(db not in ("sqlite3", "sqlite"))),
        ("Alerting em HA", None if not db else int(bool(CF["ha_peers"] or CF["ha_redis"]))),
        ("SSO (LDAP/OAuth/SAML)", None if SE["sso"] is None else len(SE["sso"])), ("Times", SE["times"]), ("Service accounts", SE["sa_total"]),
        ("Audit log (Enterprise)", None if SE["auditoria"] is None else int(bool(SE["auditoria"]))),
    ]


def capability_matrix(d: dict) -> list[list[Any]]:
    rows = []
    for name, n in capability_items(d):
        b = badge("N/D", "nd") if n is None else badge("Em uso", "sim") if n > 0 else badge("Não detectado", "nao")
        rows.append([esc(name), "-" if n is None else num(n), b])
    return rows


def report_ctx(d: dict, checks: list[Check], pil: dict[str, int], overall: int) -> dict:
    """Dados derivados compartilhados por HTML, PDF e PowerPoint."""
    porder = {p: i for i, p in enumerate(PILLARS)}
    fails = sorted((c for c in checks if c.passed is False), key=lambda c: (SEV_ORDER[c.severity], porder.get(c.pillar, 9)))
    DR, DS, RR, AC = d["dash_resumo"], d["ds_resumo"], d["rules_resumo"], d["active"]
    ds_ok = pct(DS["verificadas"] - DS["falhas"], DS["verificadas"]) if DS["verificadas"] else None
    kpis = [("Organizações", num(len(d["platform"]["orgs_avaliadas"]))), ("Dashboards", num(DR["total"])), ("Fontes de dados", num(DS["total"])),
            ("Regras de alerta", num(RR["total"])), ("Fontes saudáveis", "N/D" if ds_ok is None else f"{ds_ok}%"),
            ("Dashboards com painel descontinuado", f"{pct(DR['com_descontinuado'], DR['lidos'])}%"),
            ("Regras com erro", f"{pct(RR['erro'], RR['total'])}%" if RR["total"] else "N/D"), ("Alertas disparando", num(AC["disparando"]))]
    return {"fails": fails, "oks": [c for c in checks if c.passed], "high": [c for c in fails if c.severity == "Alta"],
            "evaluated": [c for c in checks if c.passed is not None], "kpis": kpis, "ds_ok": ds_ok,
            "worst": sorted(pil.items(), key=lambda kv: kv[1])[:2], "best": max(pil.items(), key=lambda kv: kv[1], default=None),
            "overall": overall, "pil": pil, "hy": d["hygiene"], "n_orgs": len(d["platform"]["orgs_avaliadas"])}


def exec_summary(d: dict, x: dict, b: Callable[[Any], str] = lambda s: f"<b>{s}</b>", e: Callable[[Any], str] = esc) -> str:
    """Parágrafo do resumo executivo; `b` marca destaque e `e` escapa texto (HTML, PDF ou texto puro)."""
    M, PL, EV, HY, ov = d["meta"], d["platform"], d["events"], d["hygiene"], x["overall"]
    DR, DS, RR, SE = d["dash_resumo"], d["ds_resumo"], d["rules_resumo"], d["security"]
    s = (f"O ambiente Grafana {b(e(M['ambiente']))} (versão {b(e(PL['versao']))}, {e(PL['edicao'])}, suporte {e(PL['suporte']['status'])}) tem "
         f"{b(num(x['n_orgs']))} organização(ões) avaliada(s), {b(num(DR['total']))} dashboards, {b(num(DS['total']))} fontes de dados e "
         f"{b(num(RR['total']))} regras de alerta, com {b(num(SE['ativos_30d']))} usuários ativos nos últimos 30 dias. "
         + "A maturidade de observabilidade é " + b(f"{ov}/100 ({level(ov)})") + "; os pilares mais frágeis são "
         + " e ".join(f"{b(e(k))} ({v})" for k, v in x["worst"]) + ". "
         + f"Foram identificadas {b(len(x['fails']))} lacunas, {b(len(x['high']))} de prioridade alta"
         + (": " + "; ".join(e(c.title.lower()) for c in x["high"][:4]) if x["high"] else "") + ". ")
    if EV["total"]:
        s += (f"Nos últimos {M['days']} dias houve {b(num(EV['total']))} disparos de alerta ({num(EV['por_dia'], 1)}/dia)"
              + (f", com MTTR mediano de {b(num(EV['mttr_mediana_min'], 1) + ' min')}" if EV["mttr_mediana_min"] is not None else "") + ". ")
    if HY["oportunidades"]:
        dp = HY.get("de_para") or []
        red = sum(r["reducao"] for r in dp)
        s += (f"Há {b(len(HY['oportunidades']))} oportunidades de higiene da configuração"
              + (f", que reduzem {b(num(red, 1) + ' consultas/min')} ({pct(red, HY['qpm_base'])}% da carga estimada de consultas)" if red else "") + ".")
    return s


ROADMAP = (("Alta", "0 – 30 dias"), ("Média", "30 – 60 dias"), ("Baixa", "60 – 90 dias"))
PNOTE = "Pilares de maturidade de observabilidade (SRE); pontuação ponderada por criticidade (Alta=3, Média=2, Baixa=1)."
QNOTE = ("Consultas/min = consultas × 60 ÷ intervalo. Regras: avaliação contínua no servidor. "
         "Dashboards: carga por sessão aberta com auto-refresh (multiplica pelo número de telas abertas).")


def platform_rows(d: dict) -> list[list[Any]]:
    PL, CF, SE, AL = d["platform"], d["config"], d["security"], d["alerting"]
    sp, st = PL["suporte"], PL.get("stats") or {}
    db = CF["db_tipo"] or "N/D"
    return [["Versão", f"{PL['versao']} ({PL['edicao']})"], ["Suporte do fabricante", f"{sp['status']} · major vigente considerado: {sp['major_vigente']}"],
            ["Atualização disponível", "N/D (sem acesso a grafana.com)" if PL.get("has_update") is None else f"sim ({PL.get('latest')})" if PL["has_update"] else "não"],
            ["Banco de configuração", f"{db} · saúde: {PL.get('db_status') or 'N/D'}"], ["Cache remoto", CF["remote_cache"] or "N/D"],
            ["Alerting em HA", "N/D" if not CF["db_tipo"] else ("ha_peers" if CF["ha_peers"] else "redis" if CF["ha_redis"] else "não")],
            ["Unified Alerting", yn(CF["unified_alerting"])], ["Alertmanager", AL.get("am_choice") or "N/D"], ["Image renderer", yn(CF["renderer"])],
            ["Organizações (avaliadas / total)", f"{len(PL['orgs_avaliadas'])} / {num(PL.get('orgs_total'))}"],
            ["Plugins externos (Angular / não assinados)", f"{SE['plugins_externos']} ({len(SE['plugins_angular'])} / {len(SE['plugins_nao_assinados'])})"],
            ["Usuários (habilitados / ativos 30d)", f"{num(SE['usuarios_ativos'])} / {num(SE['ativos_30d'])}"],
            ["Sessões ativas / usuários ativos (stats)", f"{num(st.get('activeSessions'))} / {num(st.get('activeUsers'))}"],
            ["Configuração do servidor (admin/settings)", "lida" if CF["disponivel"] else "não lida (requer Grafana Admin)"]]


def build_report(d: dict, checks: list[Check], dom: dict[str, int], pil: dict[str, int], overall: int, customer: str) -> str:
    M, PL, DR, DS, RR, AC, EV = d["meta"], d["platform"], d["dash_resumo"], d["ds_resumo"], d["rules_resumo"], d["active"], d["events"]
    AL, SE, HY = d["alerting"], d["security"], d["hygiene"]
    days, multi = M["days"], len(PL["orgs_avaliadas"]) > 1
    x = report_ctx(d, checks, pil, overall)
    fails, oks = x["fails"], x["oks"]
    summary = exec_summary(d, x)
    kpi_html = "".join(f'<div class="card kpi"><b>{esc(v)}</b><span>{esc(k)}</span></div>' for k, v in x["kpis"])

    def bars(items):
        return "".join(f'<div class="row"><span>{esc(k)}</span><div class="bar"><i style="width:{min(v, 100)}%;background:{color(v)}"></i></div><b>{v}</b></div>' for k, v in items)

    pil_rows = []
    for p in PILLARS:
        cs = [c for c in checks if c.pillar == p and c.passed is not None]
        pil_rows.append([esc(p), f"<b style='color:{color(pil[p])}'>{pil[p]}</b>" if p in pil else "N/A", sum(1 for c in cs if c.passed),
                         sum(1 for c in cs if not c.passed), sum(1 for c in cs if not c.passed and c.severity == "Alta")])
    dom_by_p = "".join(
        f"<h3>{esc(p)}</h3>" + bars(sorted(((k, v) for k, v in dom.items() if any(c.domain == k and c.pillar == p for c in checks)), key=lambda kv: kv[1]))
        for p in PILLARS if any(c.pillar == p for c in checks))
    find_rows = [[badge(c.severity), esc(c.pillar), esc(c.domain), f"<b>{esc(c.title)}</b><br><span class='mut'>{esc(c.evidence)}</span>", esc(c.impact), esc(c.recommendation)] for c in fails]
    road = ""
    for sev, label in ROADMAP:
        items = [c for c in fails if c.severity == sev]
        if items:
            road += f'<div class="card road"><h3>{label} · prioridade {sev}</h3><ul>' + "".join(
                f"<li><span class='badge nd'>{esc(c.pillar)}</span> <b>{esc(c.title)}</b> — {esc(c.recommendation)}</li>" for c in items) + "</ul></div>"

    # 7 · Plataforma
    plg = sorted((p for p in PL["plugins"] if not p["core"]), key=lambda p: (not p["angular"], str(p["assinatura"]) == "valid", str(p["id"])))
    plg_rows = [[esc(p["id"]), esc(p["tipo"] or "-"), esc(p["versao"] or "-"),
                 badge(str(p["assinatura"] or "-"), "sim" if p["assinatura"] in ("valid",) else "nao" if str(p["assinatura"]).lower() in ("unsigned", "invalid", "modified") else "nd"),
                 badge("sim", "nao") if p["angular"] else badge("não", "sim"), "N/D" if p["atualizacao"] is None else ("sim · " + str(p["ultima_versao"] or "")) if p["atualizacao"] else "não"]
                for p in plg[:40]]
    org_rows = [[esc(o["nome"]), esc(o.get("papel") or "-"), num(o.get("dashboards")), num(o.get("fontes")), num(o.get("regras"))] for o in PL["orgs_avaliadas"]]
    sem = PL.get("orgs_sem_acesso") or []
    plat_html = (f'<div class="grid g2"><div class="card"><h3>Instância</h3>{table(["Item", "Valor"], platform_rows(d))}</div>'
                 f'<div class="card"><h3>Organizações avaliadas</h3>{table(["Organização", "Papel do usuário", "Dashboards", "Fontes", "Regras"], org_rows, raw=True)}'
                 + (f'<p class="mut">Organizações sem acesso do usuário (não avaliadas): {esc(", ".join(o["nome"] for o in sem[:20]))}</p>' if sem else "") + '</div></div>'
                 f'<div class="card" style="margin-top:14px"><h3>Plugins externos ({len(plg)})</h3>{table(["Plugin", "Tipo", "Versão", "Assinatura", "Angular", "Atualização"], plg_rows, raw=True)}</div>')
    # 8 · Cobertura
    sig_rows = [[esc(k), v, DS["saudaveis_por_sinal"].get(k, 0)] for k, v in DS["por_sinal"].items()]
    ds_sorted = sorted(d["datasources"], key=lambda s: (s["health"] != "ERROR", -(s["usos_dash"] + s["usos_regras"])))
    ds_rows = [[esc(s["nome"]) + (f"<br><span class='mut'>{esc(s['org'])}</span>" if multi else ""), esc(s["tipo_nome"]), esc(s["sinal"]), health_badge(s["health"])
                + (f"<br><span class='mut'>{esc(clip(s['health_msg'], 80))}</span>" if s["health"] == "ERROR" else ""), "sim" if s["padrao"] else "", s["usos_dash"], s["usos_regras"]]
               for s in ds_sorted[:40]]
    cov_rows = [[esc(g), v["dashboards"], cov_badge(v.get("com_tag", 0), v["dashboards"]), cov_badge(v.get("sem_descontinuado", 0), v["dashboards"]),
                 cov_badge(v.get("sem_quebrado", 0), v["dashboards"]), cov_badge(v.get("mantidos", 0), v["dashboards"]), cov_badge(v.get("refresh_ok", 0), v["dashboards"]),
                 cov_badge(v.get("provisionados", 0), v["dashboards"])] for g, v in list(d["coverage"].items())[:40]]
    heavy = [[esc(h["titulo"]), esc(h["pasta"]), h["paineis"], h["queries"], esc(h["refresh"] or "-")] for h in DR["mais_pesados"][:10]]
    cov_html = (f'<div class="card">{table(["Capacidade", "Itens", "Situação"], capability_matrix(d), raw=True)}</div>'
                f'<div class="grid g2" style="margin-top:14px"><div class="card"><h3>Fontes por sinal</h3>{table(["Sinal", "Fontes", "Saudáveis/não verificadas"], sig_rows, raw=True)}</div>'
                f'<div class="card"><h3>Painéis descontinuados por tipo</h3>{table(["Tipo de painel", "Painéis"], dict_rows(DR["tipos_descontinuados"]))}</div></div>'
                f'<h3>Fontes de dados (falhas primeiro, depois mais usadas · top 40)</h3><div class="card">{table(["Fonte", "Tipo", "Sinal", "Health", "Padrão", "Dashboards", "Regras"], ds_rows, raw=True)}'
                f'<p class="mut">Lista completa em fontes_dados.csv.</p></div>'
                f'<h3>Cobertura por pasta (top 40)</h3><div class="card">{table(["Pasta", "Dashboards", "Com tag", "Sem descontinuado", "Sem fonte quebrada", "Alterado < 1 ano", "Refresh ≥ 1 min", "Como código"], cov_rows, raw=True)}'
                f'<p class="mut">Detalhe por dashboard em inventario_dashboards.csv; por pasta em cobertura_pastas.csv.</p></div>'
                f'<div class="card" style="margin-top:14px"><h3>Dashboards mais pesados</h3>{table(["Dashboard", "Pasta", "Painéis", "Consultas", "Refresh"], heavy, raw=True)}</div>')
    # 9 · Alertas
    st_rows = [["Disparando (firing)", RR["disparando"]], ["Pendentes", RR["pendentes"]], ["Com erro de avaliação", RR["erro"]], ["Em NoData", RR["nodata"]],
               ["Pausadas", RR["pausadas"]], ["Sem label de severidade", RR["total"] - RR["com_severidade"]], ["Sem período de pendência (for = 0)", RR["sem_for"]],
               ["Sem runbook", RR["total"] - RR["com_runbook"]], ["Intervalo < 1 min", RR["agressivas"]]]
    top_rows = [[esc(clip(t["regra"], 90)), esc(t["org"]), t["disparos"], num(t["mttr_mediana_min"], 1)] for t in EV["top_regras"][:15]]
    old_rows = [[esc(clip(p["regra"], 90)), esc(p["pasta"]), esc(p["sev"]), p["instancias"], p["dias"]] for p in AC["mais_antigos"][:15]]
    alr_html = ('<div class="grid g4">' + "".join(f'<div class="card kpi"><b>{esc(v)}</b><span>{esc(k)}</span></div>' for k, v in [
        (f"Disparos em {days}d", num(EV["total"])), ("Por dia", num(EV["por_dia"], 1)), ("MTTR mediano (min)", num(EV["mttr_mediana_min"], 1)),
        ("Regras de alerta", num(RR["total"])), ("Regras com erro", num(RR["erro"])), ("Regras em NoData", num(RR["nodata"])),
        ("Instâncias disparando", num(AC["disparando"])), ("Disparando > 30 dias", num(AC["mais_30d"]))]) + "</div>"
        f'<div class="grid g2" style="margin-top:14px"><div class="card"><h3>Estado e qualidade das regras</h3>{table(["Situação", "Regras"], st_rows)}</div>'
        f'<div class="card"><h3>Severidades (label)</h3>{table(["Severidade", "Regras"], dict_rows(RR["severidades"]))}'
        f'<h3>Erros mais comuns</h3>{table(["Erro", "Regras"], RR["erros"][:8])}</div></div>'
        f'<div class="card" style="margin-top:14px"><h3>Regras que mais dispararam ({days}d)</h3>{table(["Regra", "Organização", "Disparos", "MTTR mediano (min)"], top_rows, raw=True)}'
        f'<p class="mut">Lista completa em top_regras.csv. Fonte: histórico de estados (anotações de alerta).'
        + (" Coleta truncada pelo limite diário (--max-events-per-day)." if EV["truncado"] else "") + '</p></div>'
        f'<div class="card" style="margin-top:14px"><h3>Alertas disparando há mais tempo</h3>{table(["Regra", "Pasta", "Severidade", "Instâncias", "Dias"], old_rows, raw=True)}</div>')
    # 10 · Resposta
    notif_rows = [["Contact points / integrações", f"{AL['contact_points']} / {AL['integracoes']}"], ["Contact point padrão", AL["padrao"]],
                  ["Políticas específicas (rotas)", AL["rotas"]], ["Menor repeat interval", "N/D" if not AL["repeat_min_s"] else f"{num(AL['repeat_min_s'] / 60)} min"],
                  ["Mute timings", num(AL["mute_timings"])], ["Templates de notificação", num(AL["templates"])],
                  ["Silêncios ativos (> 30 dias)", f"{num(AL['silencios_ativos'])} ({len(AL['silencios_longos'])})"],
                  ["Alertas no Alertmanager (suprimidos)", f"{num(AL['alertas_am'])} ({AL['suprimidos']})"],
                  ["Integrações ITSM/on-call/chat", ", ".join(AL["oncall"][:10]) or "nenhuma"]]
    fail_rows = [[esc(f["receiver"]), esc(f["tipo"]), esc(f["erro"])] for f in AL["falhas"][:15]]
    sil_rows = [[esc(s["matchers"]), esc(s["comentario"]), s["dias_restantes"]] for s in AL["silencios_longos"][:15]]
    resp_html = (f'<div class="grid g2"><div class="card"><h3>Notificação e roteamento</h3>{table(["Item", "Valor"], notif_rows)}</div>'
                 f'<div class="card"><h3>Integrações por tipo</h3>{table(["Tipo", "Integrações"], dict_rows(AL["por_tipo"]))}</div>'
                 f'<div class="card"><h3>Falhas na última entrega</h3>{table(["Contact point", "Tipo", "Erro"], fail_rows, raw=True)}</div>'
                 f'<div class="card"><h3>Silêncios de longa duração</h3>{table(["Matchers", "Comentário", "Dias restantes"], sil_rows, raw=True)}</div></div>')
    # 11 · Segurança
    sec_rows = [["Usuários habilitados / inativos > 90d", f"{num(SE['usuarios_ativos'])} / {num(SE['inativos_90d'])}"], ["Grafana Admins", num(SE["server_admins"])],
                [f"Usuário '{SE['admin_user']}' ativo", yn(SE["admin_padrao_ativo"])], ["Acesso anônimo", yn(SE["anonimo"])],
                ["SSO", "N/D" if SE["sso"] is None else ", ".join(SE["sso"]) or "não"], ["Contas locais habilitadas", num(SE["locais"])],
                ["Auto-cadastro / criar org", f"{yn(SE['cadastro_livre'])} / {yn(SE['criar_org'])}"],
                ["Service accounts (Admin)", f"{num(SE['sa_total'])} ({SE['sa_admin']})"],
                ["Tokens ativos (sem expiração / sem uso 90d)", f"{num(SE['tokens_ativos'])} ({SE['tokens_sem_expiracao']} / {SE['tokens_sem_uso_90d']})"],
                ["API keys legadas", num(SE["api_keys"])], ["HTTPS / cookie_secure / HSTS", f"{yn(SE['https'])} / {yn(SE['cookie_secure'])} / {yn(SE['hsts'])}"],
                ["Embedding / CSP", f"{yn(SE['embedding'])} / {yn(SE['csp'])}"], ["Dashboards públicos ativos", num(SE["publicos"])],
                ["Snapshots (externos / sem expiração)", f"{num(SE['snapshots'])} ({SE['snap_externos']} / {SE['snap_sem_expiracao']})"],
                ["Fontes com tlsSkipVerify / modo browser", f"{len(DS['tls_skip'])} / {len(DS['direct'])}"],
                ["Pastas com edição para Viewer", len(SE["pastas_viewer_edita"])], ["Times / pastas com permissão por time", f"{num(SE['times'])} / {SE['perm_por_time']}"],
                ["Audit log", yn(SE["auditoria"])]]
    sec_html = (f'<div class="grid g2"><div class="card"><h3>Postura</h3>{table(["Item", "Valor"], sec_rows)}</div>'
                f'<div class="card"><h3>Itens sensíveis</h3><p><b>Dashboards públicos:</b> {esc(", ".join(SE["publicos_lista"][:15]) or "—")}</p>'
                f'<p><b>Fontes com tlsSkipVerify:</b> {esc(", ".join(DS["tls_skip"][:15]) or "—")}</p>'
                f'<p><b>Plugins não assinados:</b> {esc(", ".join(SE["plugins_nao_assinados"][:15]) or "—")}</p>'
                f'<p><b>Pastas com edição para Viewer:</b> {esc(", ".join(SE["pastas_viewer_edita"][:15]) or "—")}</p>'
                f'<p><b>Tokens sem expiração:</b> {esc(", ".join(SE["tokens_sem_expiracao_lista"][:15]) or "—")}</p></div></div>')
    # 12 · Higiene
    opp, dp = HY["oportunidades"], HY.get("de_para") or []
    hy_html = (f'<div class="grid g2"><div class="card"><h3>Oportunidades por categoria</h3>{table(["Categoria", "Qtde"], dict_rows(HY["resumo"]))}</div>'
               f'<div class="card"><h3>Carga de consultas · DE/PARA (consultas/min)</h3>{table(["Categoria", "Objetos", "DE", "PARA", "Redução", "% da carga"], [[r["categoria"], r["objetos"], num(r["de"], 1), num(r["para"], 1), num(r["reducao"], 1), num(r["pct_carga"], 1) + "%"] for r in dp])}'
               f'<p class="mut">{esc(QNOTE)} Base estimada: {num(HY["qpm_base"], 1)} consultas/min (regras {num(HY["qpm_regras"], 1)} · dashboards {num(HY["qpm_dashboards"], 1)}).</p></div></div>'
               f'<div class="card" style="margin-top:14px"><h3>Maiores oportunidades (amostra)</h3>{table(["Categoria", "Objeto", "Grupo", "Detalhe"], [[o["categoria"], o["nome"], o["grupo"], o["detalhe"]] for o in opp[:25]])}'
               f'<p class="mut">Lista completa em higiene_otimizacao.csv.</p></div>')
    app_rows = [[k, v] for k, v in M["coleta"].items()]
    scope = f"{len(PL['orgs_avaliadas'])} org(s)" + (f" · {DR['analisados']} de {DR['total']} dashboards (--max-dashboards)" if DR["analisados"] < DR["total"] else "")

    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Assessment Grafana · {esc(customer)}</title><style>{CSS}</style></head><body><main>
<h1>Assessment Grafana · Observabilidade e SRE</h1>
<p class="sub">{esc(customer)} · Ambiente {esc(M['ambiente'])} · Grafana {esc(PL['versao'])} · {esc(M['url_host'])} · Gerado em {M['gerado_em']} · Janela: {days} dias · Escopo: {esc(scope)} · Coleta somente leitura</p>

<h2>1. Resumo executivo</h2>
<div class="card hero"><div class="ring" style="--p:{overall};--c:{color(overall)}"><i>{overall}</i></div><div style="flex:1;min-width:260px"><h3 style="margin-top:0">Maturidade · {level(overall)}</h3><p style="margin:0">{summary}</p></div></div>
<div class="grid g4" style="margin-top:14px">{kpi_html}</div>

<h2>2. Maturidade por pilar</h2><div class="card">{bars([(p, pil[p]) for p in PILLARS if p in pil])}
{table(["Pilar", "Score", "Atende", "Lacunas", "Lacunas Alta"], pil_rows, raw=True)}<p class="mut" style="margin-bottom:0">{PNOTE}</p></div>

<h2>3. Maturidade por domínio</h2><div class="card">{dom_by_p}</div>

<h2>4. Lacunas priorizadas e recomendações</h2><div class="card">{table(["Prioridade", "Pilar", "Domínio", "Lacuna", "Impacto no negócio", "Recomendação"], find_rows, raw=True) if fails else '<p>Nenhuma lacuna identificada.</p>'}</div>

<h2>5. Roadmap sugerido</h2><div class="grid">{road}</div>

<h2>6. Pontos fortes</h2><div class="card"><ul>{''.join(f'<li><span class="badge sim">{esc(c.pillar)}</span> <b>{esc(c.title)}</b> — {esc(c.evidence)}</li>' for c in oks) or '<li>—</li>'}</ul></div>

<h2>7. Plataforma (instância, organizações, plugins)</h2>{plat_html}

<h2>8. Cobertura de observabilidade (fontes, sinais, dashboards)</h2>{cov_html}

<h2>9. Alertas</h2>{alr_html}

<h2>10. Resposta e notificação</h2>{resp_html}

<h2>11. Segurança e governança</h2>{sec_html}

<h2>12. Higiene e otimização da configuração</h2>{hy_html}

<h2>Apêndice A · Status da coleta</h2><div class="card">{table(["Coletor", "Status"], app_rows)}<p class="mut">"parcial" indica endpoint sem permissão para o usuário ou erro de coleta; "n/a" indica recurso inexistente na versão/edição ou desabilitado. Os controles dependentes ficam N/A ou subestimados.</p></div>
</main></body></html>"""


# --------------------------------------------------------------------------- #
# Relatórios PDF (executivo e técnico) · reportlab  —  imports lazy: opcionais
# --------------------------------------------------------------------------- #

HEX_OK, HEX_WARN, HEX_BAD, HEX_ACC = "#12805C", "#B54708", "#C01048", "#E8590C"
HEX_TX, HEX_MUT, HEX_BD, HEX_BG, HEX_SOFT = "#1B1F24", "#667085", "#E4E7EC", "#F6F7F9", "#C9CED6"
SEV_HEX = {"Alta": HEX_BAD, "Média": HEX_WARN, "Baixa": HEX_MUT}
_PDF_FONT = ["Helvetica", "Helvetica-Bold", False]
_ASCII_MAP = str.maketrans({"→": "->", "↔": "<->", "≥": ">=", "≤": "<=", "✓": "v", "✗": "x", "×": "x", "÷": "/"})


def hex_score(sc: int) -> str:
    return HEX_OK if sc >= 75 else HEX_WARN if sc >= 50 else HEX_BAD


def next_level(sc: int) -> tuple[str, int] | None:
    for lim in (40, 65, 85):
        if sc < lim:
            return level(lim), lim
    return None


def _pdf_fonts() -> list:
    """Registra uma fonte TrueType com acentuação (DejaVu/Liberation no Linux, Arial no Windows/macOS)."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    if _PDF_FONT[2]:
        return _PDF_FONT
    win = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
    pairs = [(Path(p) / "DejaVuSans.ttf", Path(p) / "DejaVuSans-Bold.ttf") for p in
             ("/usr/share/fonts/dejavu", "/usr/share/fonts/dejavu-sans-fonts", "/usr/share/fonts/truetype/dejavu")]
    pairs += [(win / "arial.ttf", win / "arialbd.ttf"), (win / "segoeui.ttf", win / "segoeuib.ttf"),
              (Path("/System/Library/Fonts/Supplemental/Arial.ttf"), Path("/System/Library/Fonts/Supplemental/Arial Bold.ttf"))]
    pairs += [(Path(p) / "LiberationSans-Regular.ttf", Path(p) / "LiberationSans-Bold.ttf") for p in
              ("/usr/share/fonts/liberation-sans", "/usr/share/fonts/truetype/liberation")]
    for reg, bold in pairs:
        if reg.is_file() and bold.is_file():
            try:
                pdfmetrics.registerFont(TTFont("GRF", str(reg)))
                pdfmetrics.registerFont(TTFont("GRF-Bold", str(bold)))
                pdfmetrics.registerFontFamily("GRF", normal="GRF", bold="GRF-Bold", italic="GRF", boldItalic="GRF-Bold")
                _PDF_FONT[:] = ["GRF", "GRF-Bold", True]
                break
            except Exception:  # noqa: BLE001
                continue
    return _PDF_FONT


def _plain(s: Any) -> str:
    s = str(s)
    return s if _PDF_FONT[2] else s.translate(_ASCII_MAP)


def _xe(s: Any) -> str:
    return _plain(html.escape(str(s), quote=False))


def _pdf_styles(font: str, bold: str) -> dict:
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    c = colors.HexColor
    base = ParagraphStyle("base", fontName=font, fontSize=9.5, leading=13.5, textColor=c(HEX_TX))
    return {
        "base": base,
        "h2": ParagraphStyle("h2", parent=base, fontName=bold, fontSize=14, leading=18, spaceBefore=12, spaceAfter=8, textColor=c(HEX_ACC)),
        "h3": ParagraphStyle("h3", parent=base, fontName=bold, fontSize=10, leading=13, spaceBefore=8, spaceAfter=4, textColor=c(HEX_MUT)),
        "small": ParagraphStyle("small", parent=base, fontSize=7.5, leading=10, textColor=c(HEX_MUT)),
        "td": ParagraphStyle("td", parent=base, fontSize=7.8, leading=10),
        "th": ParagraphStyle("th", parent=base, fontName=bold, fontSize=7.5, leading=9.5, textColor=colors.white),
        "kpi": ParagraphStyle("kpi", parent=base, fontName=bold, fontSize=14, leading=17),
        "bullet": ParagraphStyle("bullet", parent=base, leftIndent=12, bulletIndent=2, spaceAfter=3),
    }


def _pdf_table(S: dict, headers: list[str], rows: list[list[Any]], width: float, fr: list[float] | None = None) -> Any:
    from reportlab.lib import colors
    from reportlab.platypus import Flowable, Paragraph, Table, TableStyle
    if not rows:
        return Paragraph("Sem dados.", S["small"])
    fr = fr or [1] * len(headers)
    data = [[Paragraph(_xe(h), S["th"]) for h in headers]]
    data += [[v if isinstance(v, (Flowable, list)) else Paragraph(_xe("-" if v is None else v), S["td"]) for v in r] for r in rows]
    t = Table(data, colWidths=[width * f / sum(fr) for f in fr], repeatRows=1, hAlign="LEFT")
    st = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(HEX_TX)), ("VALIGN", (0, 0), (-1, -1), "TOP"),
          ("LINEBELOW", (0, 1), (-1, -1), 0.4, colors.HexColor(HEX_BD)), ("TOPPADDING", (0, 0), (-1, -1), 3.5),
          ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
    st += [("BACKGROUND", (0, i), (-1, i), colors.HexColor(HEX_BG)) for i in range(2, len(data), 2)]
    t.setStyle(TableStyle(st))
    return t


def _pdf_side(blocks: list[list[Any]], width: float) -> Any:
    from reportlab.platypus import Table, TableStyle
    t = Table([blocks], colWidths=[width / len(blocks)] * len(blocks))
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 10)]))
    return t


def _pdf_kpis(S: dict, kpis: list[tuple[str, Any]], width: float, cols: int = 4) -> Any:
    from reportlab.lib import colors
    from reportlab.platypus import Paragraph, Table, TableStyle
    cells = [[Paragraph(_xe(v), S["kpi"]), Paragraph(_xe(k), S["small"])] for k, v in kpis]
    cells += [""] * (-len(cells) % cols)
    t = Table([cells[i:i + cols] for i in range(0, len(cells), cols)], colWidths=[width / cols] * cols)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(HEX_BG)), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("LINEAFTER", (0, 0), (-1, -1), 4, colors.white), ("LINEBELOW", (0, 0), (-1, -1), 4, colors.white),
                           ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(HEX_ACC)),
                           ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7), ("LEFTPADDING", (0, 0), (-1, -1), 9)]))
    return t


def _pdf_bars(items: list[tuple[str, int]], width: float, label_w: float = 165, row_h: float = 17, invert: bool = False, suffix: str = "") -> Any:
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.lib import colors
    font, bold, _ = _PDF_FONT
    h = row_h * len(items) + 2
    dr = Drawing(width, h)
    bw = width - label_w - 34
    for i, (k, v) in enumerate(items):
        y = h - (i + 1) * row_h + 3
        col = colors.HexColor(hex_score(100 - v if invert else v))
        dr.add(String(0, y + 1.5, _plain(clip(k, 38)), fontName=font, fontSize=8.5, fillColor=colors.HexColor(HEX_TX)))
        dr.add(Rect(label_w, y + 1, bw, 8, rx=4, ry=4, fillColor=colors.HexColor(HEX_BD), strokeColor=None))
        if v:
            dr.add(Rect(label_w, y + 1, max(8, bw * min(v, 100) / 100), 8, rx=4, ry=4, fillColor=col, strokeColor=None))
        dr.add(String(width, y + 1.5, f"{round(v)}{suffix}", fontName=bold, fontSize=9, textAnchor="end", fillColor=col))
    return dr


def _pdf_gauge(sc: int, size: float) -> Any:
    from reportlab.graphics.shapes import Circle, Drawing, String, Wedge
    from reportlab.lib import colors
    font, bold, _ = _PDF_FONT
    dr, c, r = Drawing(size, size), size / 2, size / 2
    col = colors.HexColor(hex_score(sc))
    dr.add(Circle(c, c, r, fillColor=colors.HexColor(HEX_BD), strokeColor=None))
    if sc >= 100:
        dr.add(Circle(c, c, r, fillColor=col, strokeColor=None))
    elif sc > 0:
        dr.add(Wedge(c, c, r, 90 - 3.6 * sc, 90, fillColor=col, strokeColor=None))
    dr.add(Circle(c, c, r * 0.76, fillColor=colors.white, strokeColor=None))
    dr.add(String(c, c - size * 0.06, str(sc), fontName=bold, fontSize=size * 0.30, textAnchor="middle", fillColor=col))
    dr.add(String(c, c - size * 0.22, "/100", fontName=font, fontSize=size * 0.09, textAnchor="middle", fillColor=colors.HexColor(HEX_MUT)))
    return dr


def _pdf_doc(path: Path, d: dict, customer: str, subtitle: str, x: dict, land: bool) -> tuple:
    """Documento A4 com capa (1ª página) e cabeçalho/rodapé nas demais."""
    from reportlab.graphics import renderPDF
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.units import mm
    from reportlab.platypus import Flowable, PageBreak, SimpleDocTemplate
    font, bold, _ = _pdf_fonts()
    S = _pdf_styles(font, bold)
    ps = landscape(A4) if land else A4
    M, hx, PL = d["meta"], colors.HexColor, d["platform"]
    doc = SimpleDocTemplate(str(path), pagesize=ps, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=18 * mm, bottomMargin=16 * mm,
                            title=f"Assessment Grafana - {subtitle} - {customer}", author="grafana_assessment.py", subject="Assessment Grafana")

    def later(cv, dc):
        w, h = ps
        cv.saveState()
        cv.setFillColor(hx(HEX_ACC))
        cv.rect(0, h - 5, w, 5, fill=1, stroke=0)
        cv.setFont(font, 7.5)
        cv.setFillColor(hx(HEX_MUT))
        cv.drawString(dc.leftMargin, h - 11 * mm, _plain(f"Assessment Grafana · {subtitle} · {customer}"))
        cv.drawRightString(w - dc.rightMargin, h - 11 * mm, "Confidencial")
        cv.drawString(dc.leftMargin, 8 * mm, _plain(f"Ambiente {M['ambiente']} · Grafana {PL['versao']} · gerado em {M['gerado_em']} · coleta somente leitura"))
        cv.drawRightString(w - dc.rightMargin, 8 * mm, f"Página {dc.page}")
        cv.restoreState()

    def first(cv, dc):
        w, h = ps
        by, L, gs, ov = h * (0.46 if land else 0.57), 22 * mm, 130, x["overall"]
        DR, DS, RR = d["dash_resumo"], d["ds_resumo"], d["rules_resumo"]
        cv.saveState()
        cv.setFillColor(hx(HEX_TX))
        cv.rect(0, by, w, h - by, fill=1, stroke=0)
        cv.setFillColor(hx(HEX_ACC))
        cv.rect(0, by - 6, w, 6, fill=1, stroke=0)
        cv.setFont(bold, 9.5)
        cv.drawString(L, h - 70, "GRAFANA · OBSERVABILIDADE E SRE")
        cv.setFillColor(colors.white)
        cv.setFont(bold, 30)
        cv.drawString(L, h - 115, "Assessment de observabilidade")
        cv.setFillColor(hx(HEX_SOFT))
        cv.setFont(font, 17)
        cv.drawString(L, h - 142, _plain(subtitle))
        cv.setFillColor(colors.white)
        cv.setFont(bold, 16)
        cv.drawString(L, h - 192, _plain(clip(customer, 70)))
        cv.setFillColor(hx(HEX_SOFT))
        cv.setFont(font, 10)
        for i, ln in enumerate([f"Ambiente {M['ambiente']} · Grafana {PL['versao']} ({PL['edicao']}) · {M['url_host']}",
                                f"{x['n_orgs']} org(s) · {num(DR['total'])} dashboards · {num(DS['total'])} fontes de dados · {num(RR['total'])} regras de alerta",
                                f"Gerado em {M['gerado_em']} · janela de {M['days']} dias · coleta somente leitura"]):
            cv.drawString(L, h - 214 - i * 15, _plain(clip(ln, 120)))
        gy = by / 2 - gs / 2 + 12
        renderPDF.draw(_pdf_gauge(ov, gs), cv, L, gy)
        tx = L + gs + 32
        cv.setFillColor(hx(HEX_MUT))
        cv.setFont(bold, 9)
        cv.drawString(tx, gy + gs - 8, "MATURIDADE DE OBSERVABILIDADE")
        cv.setFillColor(hx(hex_score(ov)))
        cv.setFont(bold, 20)
        cv.drawString(tx, gy + gs - 34, level(ov))
        bars = _pdf_bars([(p, x["pil"][p]) for p in PILLARS if p in x["pil"]], min(w - tx - L, 340), label_w=150)
        renderPDF.draw(bars, cv, tx, gy + gs - 46 - bars.height)
        cv.setFillColor(hx(HEX_MUT))
        cv.setFont(font, 7.5)
        cv.drawString(L, 12 * mm, "Confidencial · gerado automaticamente por grafana_assessment.py a partir da API do Grafana (somente leitura)")
        cv.restoreState()

    class _CoverFill(Flowable):
        def wrap(self, aw, ah):
            return aw, ah - 1

        def draw(self):
            pass

    doc._grf_pages = (first, later)
    return doc, S, [_CoverFill(), PageBreak()], doc.width


def _pdf_sev(S: dict, sev: str) -> Any:
    from reportlab.platypus import Paragraph
    return Paragraph(f'<font color="{SEV_HEX.get(sev, HEX_MUT)}"><b>{_xe(sev)}</b></font>', S["td"])


def _pdf_score(S: dict, v: int | None) -> Any:
    from reportlab.platypus import Paragraph
    return Paragraph("N/A" if v is None else f'<font color="{hex_score(v)}"><b>{v}</b></font>', S["td"])


def _pdf_cov(S: dict, n: int, t: int) -> Any:
    from reportlab.platypus import Paragraph
    if not t:
        return Paragraph("—", S["td"])
    p = pct(n, t)
    col = HEX_OK if p >= 80 else HEX_WARN if p >= 40 else HEX_BAD
    return Paragraph(f'<font color="{col}"><b>{n}/{t}</b> · {p}%</font>', S["td"])


def _pdf_pillar_rows(S: dict, checks: list[Check], pil: dict[str, int], with_counts: bool) -> list[list[Any]]:
    rows = []
    for p in PILLARS:
        cs = [c for c in checks if c.pillar == p and c.passed is not None]
        if not cs:
            continue
        sc = pil.get(p)
        fs = [c for c in cs if not c.passed]
        base = [p, _pdf_score(S, sc), level(sc) if sc is not None else "—"]
        if with_counts:
            rows.append(base + [sum(1 for c in cs if c.passed), len(fs), sum(1 for c in fs if c.severity == "Alta")])
        else:
            rows.append(base + [sum(1 for c in fs if c.severity == s) for s in SEV_ORDER])
    return rows


def build_pdf_exec(d: dict, checks: list[Check], dom: dict[str, int], pil: dict[str, int], overall: int, customer: str, path: Path) -> None:
    from reportlab.platypus import CondPageBreak, KeepTogether, Paragraph, Spacer
    x = report_ctx(d, checks, pil, overall)
    doc, S, story, W = _pdf_doc(path, d, customer, "Relatório executivo", x, land=False)
    EV, HY, AC, RR = d["events"], x["hy"], d["active"], d["rules_resumo"]
    P = lambda m, s="base": Paragraph(m, S[s])  # noqa: E731

    story += [P("1. Resumo executivo", "h2"), P(exec_summary(d, x, e=_xe)), Spacer(1, 10), _pdf_kpis(S, x["kpis"], W),
              KeepTogether([P("Maturidade por pilar", "h3"), _pdf_bars([(p, pil[p]) for p in PILLARS if p in pil], W),
                            Spacer(1, 6), _pdf_table(S, ["Pilar", "Score", "Nível", "Lacunas Alta", "Média", "Baixa"],
                                                     _pdf_pillar_rows(S, checks, pil, False), W, [3, 1, 2, 1.2, 1, 1]),
                            P(PNOTE, "small")])]
    story += [CondPageBreak(140), P("2. Principais riscos para a operação", "h2")]
    top = x["high"] or x["fails"]
    if top:
        story.append(P(f"{len(x['high'])} lacunas de prioridade alta exigem ação nos próximos 30 dias. "
                       + ("Os itens abaixo concentram o maior risco de falha não detectada, alerta perdido ou exposição de dados." if x["high"] else
                          "Não há lacunas de prioridade alta; abaixo, as mais relevantes.")))
        story.append(Spacer(1, 6))
        story.append(_pdf_table(S, ["Prioridade", "Pilar", "Risco identificado", "Impacto", "Ação recomendada"],
                                [[_pdf_sev(S, c.severity), c.pillar, P(f"<b>{_xe(c.title)}</b>", "td"), c.impact, c.recommendation] for c in top[:12]],
                                W, [1, 1.4, 1.9, 2.4, 2.6]))
        if len(top) > 12:
            story.append(P(f"+{len(top) - 12} itens no relatório técnico.", "small"))
    else:
        story.append(P("Nenhuma lacuna identificada nos controles avaliados."))

    dp = HY.get("de_para") or []
    story += [CondPageBreak(200), P("3. Alertas, carga e higiene", "h2"),
              _pdf_kpis(S, [(f"Disparos em {d['meta']['days']}d", num(EV["total"])), ("MTTR mediano (min)", num(EV["mttr_mediana_min"], 1)),
                            ("Regras com erro", num(RR["erro"])), ("Oportunidades de higiene", num(len(HY["oportunidades"])))], W),
              Spacer(1, 8),
              _pdf_side([[P("Regras mais ruidosas", "h3"), _pdf_table(S, ["Regra", "Disparos"], [[clip(t["regra"], 60), t["disparos"]] for t in EV["top_regras"][:6]], W / 2 - 10, [3, 1])],
                         [P("Higiene por categoria", "h3"), _pdf_table(S, ["Categoria", "Qtde"], dict_rows(HY["resumo"])[:7], W / 2 - 10, [3, 1])]], W)]
    if dp:
        de, para = sum(r["de"] for r in dp), sum(r["para"] for r in dp)
        story.append(KeepTogether([P("Carga de consultas · DE/PARA (consultas/min)", "h3"),
                                   _pdf_table(S, ["Categoria", "Objetos", "DE", "PARA", "Redução", "% da carga"],
                                              [[r["categoria"], r["objetos"], num(r["de"], 1), num(r["para"], 1),
                                                P(f'<font color="{HEX_OK}"><b>{_xe(num(r["reducao"], 1))}</b></font>', "td"), num(r["pct_carga"], 1) + "%"] for r in dp]
                                              + [[P("<b>Total</b>", "td"), sum(r["objetos"] for r in dp), num(de, 1), num(para, 1),
                                                  P(f'<font color="{HEX_OK}"><b>{_xe(num(de - para, 1))}</b></font>', "td"), num(pct(de - para, HY["qpm_base"])) + "%"]],
                                              W, [2.4, 0.8, 1, 1, 1, 0.9]),
                                   P(_xe(QNOTE) + " Menos consultas reduzem a carga nas fontes (Prometheus, Zabbix, bancos) e o custo de infraestrutura.", "small")]))

    story += [CondPageBreak(140), P("4. Roadmap sugerido (30 · 60 · 90 dias)", "h2")]
    for sev, label in ROADMAP:
        items = [c for c in x["fails"] if c.severity == sev]
        if items:
            story.append(KeepTogether([P(f"{label} · prioridade {sev} ({len(items)})", "h3")]
                                      + [Paragraph(f"<b>{_xe(c.title)}</b> <font color='{HEX_MUT}'>· {_xe(c.pillar)}</font>", S["bullet"], bulletText="•") for c in items]))
    story += [CondPageBreak(140), P("5. Pontos fortes", "h2")]
    story += [Paragraph(f"<b>{_xe(c.title)}</b> <font color='{HEX_MUT}'>· {_xe(c.pillar)}</font>", S["bullet"], bulletText="✓" if _PDF_FONT[2] else "•")
              for c in x["oks"][:14]] or [P("—")]
    nl = next_level(overall)
    steps = ["Validar os achados com os times de plataforma, operações (NOC/on-call), segurança e donos de serviço.",
             f"Designar responsáveis e datas para as {len(x['high'])} lacunas de prioridade alta (janela de 0 a 30 dias).",
             "Aprovar o roadmap 30/60/90 e o modelo de execução (dashboards, alertas e fontes como código via provisioning/Terraform)."]
    if HY["oportunidades"]:
        steps.append(f"Tratar as {len(HY['oportunidades'])} oportunidades de higiene (detalhe em higiene_otimizacao.csv).")
    if AC["disparando"]:
        steps.append(f"Revisar as {AC['disparando']} instâncias de alerta disparando ({AC['mais_30d']} há mais de 30 dias).")
    steps.append("Reexecutar o assessment em 90 dias para medir a evolução" + (f" (meta: nível {nl[0]}, score ≥ {nl[1]})." if nl else " e manter o nível Otimizado."))
    story.append(KeepTogether([P("6. Próximos passos e decisões", "h2")] + [Paragraph(_xe(s), S["bullet"], bulletText=f"{i}.") for i, s in enumerate(steps, 1)]
                              + [Spacer(1, 8), P("Evidências por controle e inventário: relatorio_tecnico.pdf · backlog: achados.csv.", "small")]))
    first, later = doc._grf_pages
    doc.build(story, onFirstPage=first, onLaterPages=later)


def build_pdf_tech(d: dict, checks: list[Check], dom: dict[str, int], pil: dict[str, int], overall: int, customer: str, path: Path) -> None:
    from reportlab.platypus import CondPageBreak, KeepTogether, PageBreak, Paragraph, Spacer
    x = report_ctx(d, checks, pil, overall)
    doc, S, story, W = _pdf_doc(path, d, customer, "Relatório técnico", x, land=True)
    M, PL, DR, DS, RR, AC, EV, AL, SE, HY = (d["meta"], d["platform"], d["dash_resumo"], d["ds_resumo"], d["rules_resumo"], d["active"], d["events"],
                                             d["alerting"], d["security"], x["hy"])
    days, H, multi = M["days"], W / 2 - 10, len(PL["orgs_avaliadas"]) > 1
    P = lambda m, s="base": Paragraph(m, S[s])  # noqa: E731
    T = lambda h, r, w=W, fr=None: _pdf_table(S, h, r, w, fr)  # noqa: E731

    def h2(t):
        story.extend([CondPageBreak(150), P(t, "h2")])

    h2("1. Escopo e metodologia")
    story.append(_pdf_side([[T(["Item", "Valor"], [
        ["Cliente", customer], ["Ambiente", M["ambiente"]], ["Endpoint", M["url_host"]], ["Versão", f"{PL['versao']} ({PL['edicao']})"],
        ["Organizações avaliadas", ", ".join(o["nome"] for o in PL["orgs_avaliadas"])], ["Dashboards (analisados / total)", f"{DR['analisados']} / {DR['total']}"],
        ["Janela de histórico de alertas", f"{days} dias"], ["Autenticação", AUTH_LBL.get(M.get("auth"), M.get("auth", "-"))], ["Usuário Grafana Admin", yn(M.get("server_admin"))],
        ["Chamadas de API (leitura)", M.get("chamadas_api", "-")], ["Duração da coleta", f"{M.get('duracao_s', '-')} s"], ["Gerado em", M["gerado_em"]]], H, [1, 2])],
        [P("<b>Abordagem.</b> Coleta 100% somente leitura via HTTP API: o cliente só executa GET em /api/... e bloqueia proxies de fonte de dados e "
           "recursos de plugin. Os dados são avaliados contra controles de cinco pilares de maturidade de observabilidade."),
         Spacer(1, 6), P(f"<b>Pontuação.</b> {_xe(PNOTE)} Controles sem dados (N/A) não entram no cálculo. "
                         f"Foram avaliados {len(x['evaluated'])} controles: {len(x['oks'])} atendidos e {len(x['fails'])} lacunas."),
         Spacer(1, 6), P("<b>Níveis.</b> Inicial (&lt;40) · Em desenvolvimento (40–64) · Estruturado (65–84) · Otimizado (≥85)."),
         Spacer(1, 6), P("<b>Limitações.</b> Ruído e MTTR vêm do histórico de estados (anotações de alerta); se o state history estiver em Loki ou "
                         "desabilitado, esses controles ficam N/A. Configuração do servidor exige Grafana Admin" + (" (indisponível para token de API: avaliada só a org do token)" if M.get("auth") == "token_api" else "") + ". Consultas/min são estimadas pela "
                         "configuração (intervalo/refresh). Coletores 'parcial' (Apêndice A) indicam permissões ausentes.")]], W))
    h2("2. Maturidade por pilar")
    story += [P(exec_summary(d, x, e=_xe)), Spacer(1, 8),
              _pdf_side([[_pdf_bars([(p, pil[p]) for p in PILLARS if p in pil], H)],
                         [T(["Pilar", "Score", "Nível", "Atende", "Lacunas", "Alta"], _pdf_pillar_rows(S, checks, pil, True), H, [3, 1, 2, 1, 1, 1])]], W)]
    h2("3. Maturidade por domínio")
    blocks = []
    for p in PILLARS:
        items = sorted(((k, v) for k, v in dom.items() if any(c.domain == k and c.pillar == p for c in checks)), key=lambda kv: kv[1])
        if items:
            blocks.append([P(p, "h3"), _pdf_bars(items, H)])
    for i in range(0, len(blocks), 2):
        pair = blocks[i:i + 2]
        story.append(_pdf_side(pair + [[]] * (2 - len(pair)), W))
    h2("4. Lacunas priorizadas e recomendações")
    story.append(T(["Prioridade", "Pilar", "Domínio", "Lacuna e evidência", "Impacto", "Recomendação"],
                   [[_pdf_sev(S, c.severity), c.pillar, c.domain, P(f"<b>{_xe(c.title)}</b><br/><font color='{HEX_MUT}'>{_xe(c.evidence)}</font>", "td"),
                     c.impact, c.recommendation] for c in x["fails"]], W, [0.8, 1.2, 1.2, 3.2, 2.2, 2.6]) if x["fails"] else P("Nenhuma lacuna identificada."))
    h2("5. Roadmap sugerido")
    for sev, label in ROADMAP:
        items = [c for c in x["fails"] if c.severity == sev]
        if items:
            story += [P(f"{label} · prioridade {sev} ({len(items)} itens)", "h3"),
                      T(["Pilar", "Domínio", "Ação", "Recomendação"], [[c.pillar, c.domain, P(f"<b>{_xe(c.title)}</b>", "td"), c.recommendation] for c in items], W, [1.2, 1.2, 2.2, 4.5])]
    h2("6. Pontos fortes")
    story.append(T(["Pilar", "Domínio", "Controle atendido", "Evidência"], [[c.pillar, c.domain, P(f"<b>{_xe(c.title)}</b>", "td"), c.evidence] for c in x["oks"]], W, [1.2, 1.2, 2.2, 4.5]))

    h2("7. Plataforma (instância, organizações, plugins)")
    plg = sorted((p for p in PL["plugins"] if not p["core"]), key=lambda p: (not p["angular"], str(p["assinatura"]) == "valid", str(p["id"])))
    story.append(_pdf_side([[P("Instância", "h3"), T(["Item", "Valor"], platform_rows(d), H, [1.3, 2])],
                            [P("Organizações avaliadas", "h3"), T(["Organização", "Papel", "Dashboards", "Fontes", "Regras"],
                                                                  [[o["nome"], o.get("papel") or "-", num(o.get("dashboards")), num(o.get("fontes")), num(o.get("regras"))]
                                                                   for o in PL["orgs_avaliadas"]], H, [2, 1, 1, 1, 1]),
                             P("Sem acesso (não avaliadas): " + _xe(", ".join(o["nome"] for o in (PL.get("orgs_sem_acesso") or [])[:20]) or "—"), "small")]], W))
    if plg:
        story += [P(f"Plugins externos ({len(plg)})", "h3"), T(["Plugin", "Tipo", "Versão", "Assinatura", "Angular", "Atualização"],
                                                              [[p["id"], p["tipo"] or "-", p["versao"] or "-", p["assinatura"] or "-", yn(p["angular"]),
                                                                yn(p["atualizacao"])] for p in plg[:60]], W, [3, 1, 1, 1, 0.8, 0.8])]

    h2("8. Cobertura de observabilidade")
    cap = [[n, "-" if v is None else num(v), P(f'<font color="{HEX_MUT if v is None else HEX_OK if v > 0 else HEX_BAD}"><b>'
                                              + ("N/D" if v is None else "Em uso" if v > 0 else "Não detectado") + "</b></font>", "td")] for n, v in capability_items(d)]
    half = (len(cap) + 1) // 2
    story.append(_pdf_side([[T(["Capacidade", "Itens", "Situação"], cap[:half], H, [3, 1, 1.3])], [T(["Capacidade", "Itens", "Situação"], cap[half:], H, [3, 1, 1.3])]], W))
    dss = sorted(d["datasources"], key=lambda s: (s["health"] != "ERROR", -(s["usos_dash"] + s["usos_regras"])))
    story += [P("Fontes de dados (falhas primeiro · top 40)", "h3"),
              T(["Fonte", "Tipo", "Sinal", "Health", "Padrão", "Dashboards", "Regras", "Mensagem"],
                [[s["nome"] + (f" ({s['org']})" if multi else ""), s["tipo_nome"], s["sinal"], s["health"] or "N/D", yn(s["padrao"]), s["usos_dash"], s["usos_regras"],
                  clip(s["health_msg"], 90) if s["health"] == "ERROR" else ""] for s in dss[:40]], W, [2.2, 1.4, 1, 0.7, 0.6, 0.8, 0.6, 3])]
    cov = [[g, v["dashboards"], _pdf_cov(S, v.get("com_tag", 0), v["dashboards"]), _pdf_cov(S, v.get("sem_descontinuado", 0), v["dashboards"]),
            _pdf_cov(S, v.get("sem_quebrado", 0), v["dashboards"]), _pdf_cov(S, v.get("mantidos", 0), v["dashboards"]),
            _pdf_cov(S, v.get("refresh_ok", 0), v["dashboards"]), _pdf_cov(S, v.get("provisionados", 0), v["dashboards"])]
           for g, v in list(d["coverage"].items())[:40]]
    story += [P("Cobertura por pasta (top 40)", "h3"),
              T(["Pasta", "Dashboards", "Com tag", "Sem descontinuado", "Sem fonte quebrada", "Alterado < 1 ano", "Refresh ≥ 1 min", "Como código"], cov, W,
                [2.6, 0.8, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1]),
              _pdf_side([[P("Painéis descontinuados por tipo", "h3"), T(["Tipo", "Painéis"], dict_rows(DR["tipos_descontinuados"])[:12], H, [3, 1])],
                         [P("Dashboards mais pesados", "h3"), T(["Dashboard", "Painéis", "Consultas", "Refresh"],
                                                               [[h["titulo"], h["paineis"], h["queries"], h["refresh"] or "-"] for h in DR["mais_pesados"][:10]], H, [3, 0.8, 0.8, 0.8])]], W)]

    h2("9. Alertas")
    story += [_pdf_kpis(S, [(f"Disparos em {days}d", num(EV["total"])), ("Por dia", num(EV["por_dia"], 1)), ("MTTR mediano (min)", num(EV["mttr_mediana_min"], 1)),
                            ("Regras de alerta", num(RR["total"])), ("Regras com erro", num(RR["erro"])), ("Regras em NoData", num(RR["nodata"])),
                            ("Instâncias disparando", num(AC["disparando"])), ("Disparando > 30 dias", num(AC["mais_30d"]))], W), Spacer(1, 6),
              _pdf_side([[P("Estado e qualidade das regras", "h3"), T(["Situação", "Regras"], [
                  ["Disparando", RR["disparando"]], ["Pendentes", RR["pendentes"]], ["Com erro", RR["erro"]], ["NoData", RR["nodata"]], ["Pausadas", RR["pausadas"]],
                  ["Sem severidade", RR["total"] - RR["com_severidade"]], ["Sem 'for'", RR["sem_for"]], ["Sem runbook", RR["total"] - RR["com_runbook"]],
                  ["Intervalo < 1 min", RR["agressivas"]]], H, [3, 1])],
                  [P("Erros de avaliação mais comuns", "h3"), T(["Erro", "Regras"], RR["erros"][:8], H, [4, 1]),
                   P("Severidades (label)", "h3"), T(["Severidade", "Regras"], dict_rows(RR["severidades"]), H, [3, 1])]], W),
              P(f"Regras que mais dispararam ({days}d)", "h3"),
              T(["Regra", "Organização", "Disparos", "MTTR mediano (min)"], [[t["regra"], t["org"], t["disparos"], num(t["mttr_mediana_min"], 1)] for t in EV["top_regras"][:20]],
                W, [5, 2, 1, 1])]
    if EV["flapping"]:
        story += [P("Regras em flapping", "h3"), T(["Regra", "Organização", "Disparos", "Duração mediana (min)"],
                                                   [[t["regra"], t["org"], t["disparos"], num(t["mttr_mediana_min"], 1)] for t in EV["flapping"][:15]], W, [5, 2, 1, 1])]
    story += [P("Alertas disparando há mais tempo", "h3"), T(["Regra", "Pasta", "Severidade", "Instâncias", "Dias"],
                                                            [[p["regra"], p["pasta"], p["sev"], p["instancias"], p["dias"]] for p in AC["mais_antigos"][:20]], W, [4, 2.5, 1, 0.8, 0.6])]

    h2("10. Resposta e notificação")
    story.append(_pdf_side([[P("Notificação e roteamento", "h3"), T(["Item", "Valor"], [
        ["Contact points / integrações", f"{AL['contact_points']} / {AL['integracoes']}"], ["Contact point padrão", AL["padrao"]],
        ["Políticas específicas", AL["rotas"]], ["Menor repeat interval", "N/D" if not AL["repeat_min_s"] else f"{num(AL['repeat_min_s'] / 60)} min"],
        ["Mute timings / templates", f"{num(AL['mute_timings'])} / {num(AL['templates'])}"],
        ["Silêncios ativos (> 30d)", f"{num(AL['silencios_ativos'])} ({len(AL['silencios_longos'])})"],
        ["Integrações ITSM/on-call/chat", ", ".join(AL["oncall"][:8]) or "nenhuma"]], H, [2, 1.5])],
        [P("Integrações por tipo", "h3"), T(["Tipo", "Integrações"], dict_rows(AL["por_tipo"])[:10], H, [3, 1]),
         P("Falhas na última entrega", "h3"), T(["Contact point", "Tipo", "Erro"], [[f["receiver"], f["tipo"], f["erro"]] for f in AL["falhas"][:8]], H, [1.5, 1, 3])]], W))

    h2("11. Segurança e governança")
    story.append(_pdf_side([[P("Postura", "h3"), T(["Item", "Valor"], [
        ["Usuários habilitados / inativos > 90d", f"{num(SE['usuarios_ativos'])} / {num(SE['inativos_90d'])}"], ["Grafana Admins", num(SE["server_admins"])],
        [f"Usuário '{SE['admin_user']}' ativo", yn(SE["admin_padrao_ativo"])], ["Acesso anônimo", yn(SE["anonimo"])],
        ["SSO", "N/D" if SE["sso"] is None else ", ".join(SE["sso"]) or "não"], ["Tokens ativos (sem expiração)", f"{num(SE['tokens_ativos'])} ({SE['tokens_sem_expiracao']})"],
        ["API keys legadas", num(SE["api_keys"])], ["HTTPS / cookie_secure", f"{yn(SE['https'])} / {yn(SE['cookie_secure'])}"],
        ["Dashboards públicos", num(SE["publicos"])], ["Fontes com tlsSkipVerify", len(DS["tls_skip"])], ["Plugins não assinados", len(SE["plugins_nao_assinados"])],
        ["Pastas com edição para Viewer", len(SE["pastas_viewer_edita"])], ["Audit log", yn(SE["auditoria"])]], H, [2, 1.3])],
        [P("Itens sensíveis", "h3"), P("<b>Dashboards públicos:</b> " + _xe(", ".join(SE["publicos_lista"][:12]) or "—"), "td"), Spacer(1, 4),
         P("<b>Fontes com tlsSkipVerify:</b> " + _xe(", ".join(DS["tls_skip"][:12]) or "—"), "td"), Spacer(1, 4),
         P("<b>Plugins não assinados:</b> " + _xe(", ".join(SE["plugins_nao_assinados"][:12]) or "—"), "td"), Spacer(1, 4),
         P("<b>Pastas com edição para Viewer:</b> " + _xe(", ".join(SE["pastas_viewer_edita"][:12]) or "—"), "td"), Spacer(1, 4),
         P("<b>Tokens sem expiração:</b> " + _xe(", ".join(SE["tokens_sem_expiracao_lista"][:12]) or "—"), "td")]], W))
    acts = score_actions(checks, P_SEC)
    if acts:
        g = lambda a, b: P(f'<font color="{HEX_OK if b > a else HEX_MUT}"><b>{a} → {b}</b>' + (f" (+{b - a})" if b > a else "") + "</font>", "td")  # noqa: E731
        story += [P("Ações para elevar o score de segurança", "h3"),
                  T(["#", "Ação", "Prioridade", "Recomendação", "Score segurança", "Score global", "Global acumulado"],
                    [[i, P(f"<b>{_xe(a['check'].title)}</b>", "td"), _pdf_sev(S, a["check"].severity), a["check"].recommendation,
                      g(a["pilar_de"], a["pilar_para"]), g(a["global_de"], a["global_para"]), _pdf_score(S, a["global_acum"])] for i, a in enumerate(acts, 1)],
                    W, [0.3, 2.4, 0.8, 3.6, 1.1, 1.1, 1]),
                  P("Score se apenas a ação da linha for resolvida; 'Global acumulado' resolve as ações na ordem da tabela.", "small")]

    h2("12. Higiene e otimização da configuração")
    dp, opp = HY.get("de_para") or [], HY["oportunidades"]
    story.append(_pdf_side([[P("Oportunidades por categoria", "h3"), T(["Categoria", "Qtde"], dict_rows(HY["resumo"]), H, [3, 1])],
                            [P("Carga de consultas · DE/PARA (consultas/min)", "h3"),
                             T(["Categoria", "Objetos", "DE", "PARA", "Redução"], [[r["categoria"], r["objetos"], num(r["de"], 1), num(r["para"], 1), num(r["reducao"], 1)] for r in dp], H, [2.5, 0.8, 0.8, 0.8, 0.8]),
                             P(f"Base estimada: {num(HY['qpm_base'], 1)} consultas/min (regras {num(HY['qpm_regras'], 1)} · dashboards {num(HY['qpm_dashboards'], 1)}). " + _xe(QNOTE), "small")]], W))
    story += [P(f"Oportunidades ({min(len(opp), 50)} de {len(opp)}; lista completa em higiene_otimizacao.csv)", "h3"),
              T(["Categoria", "Tipo", "Objeto", "Grupo", "Detalhe", "Consultas/min DE→PARA"],
                [[o["categoria"], o["tipo"], o["nome"], o["grupo"], o["detalhe"], "-" if o["qpm_de"] is None else f"{num(o['qpm_de'], 2)} → {num(o['qpm_para'], 2)}"] for o in opp[:50]],
                W, [1.6, 0.8, 2.2, 1.6, 2.6, 1.1])]

    st = list(M["coleta"].items())
    half = (len(st) + 1) // 2
    story += [PageBreak() if len(st) > 30 else CondPageBreak(150),
              KeepTogether([P("Apêndice A · Status da coleta", "h2"),
                            _pdf_side([[T(["Coletor", "Status"], [[k, v] for k, v in st[:half]], H, [1, 2])],
                                       [T(["Coletor", "Status"], [[k, v] for k, v in st[half:]], H, [1, 2])]], W),
                            P("'parcial' indica endpoint sem permissão ou erro de coleta; 'n/a' indica recurso inexistente na versão/edição.", "small")])]
    first, later = doc._grf_pages
    doc.build(story, onFirstPage=first, onLaterPages=later)


# --------------------------------------------------------------------------- #
# Apresentação PowerPoint para stakeholders · python-pptx (16:9, gráficos nativos editáveis)
# --------------------------------------------------------------------------- #


def build_pptx(d: dict, checks: list[Check], dom: dict[str, int], pil: dict[str, int], overall: int, customer: str, path: Path) -> None:
    from pptx import Presentation
    from pptx.chart.data import CategoryChartData
    from pptx.dml.color import RGBColor
    from pptx.enum.chart import XL_CHART_TYPE, XL_LABEL_POSITION, XL_LEGEND_POSITION, XL_TICK_MARK
    from pptx.enum.shapes import MSO_SHAPE
    from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
    from pptx.oxml.ns import qn
    from pptx.util import Inches, Pt

    x = report_ctx(d, checks, pil, overall)
    M, PL, DR, DS, RR, AC, EV, SE, HY, CF = (d["meta"], d["platform"], d["dash_resumo"], d["ds_resumo"], d["rules_resumo"], d["active"], d["events"],
                                             d["security"], x["hy"], d["config"])
    W, FONT = 13.333, "Calibri"
    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(W), Inches(7.5)
    blank = prs.slide_layouts[6]
    rgb = lambda h: RGBColor.from_string(h.lstrip("#"))  # noqa: E731
    state = {"n": 0}

    def text(sl, l, t, w, h, paras, size=14, bold=False, color=HEX_TX, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP, space=0):
        tb = sl.shapes.add_textbox(Inches(l), Inches(t), Inches(w), Inches(h))
        tf = tb.text_frame
        tf.word_wrap, tf.vertical_anchor = True, anchor
        tf.margin_left = tf.margin_right = Inches(0.04)
        tf.margin_top = tf.margin_bottom = Inches(0.02)
        for i, para in enumerate(paras if isinstance(paras, list) else [paras]):
            p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
            p.alignment = align
            if space:
                p.space_after = Pt(space)
            for seg in (para if isinstance(para, list) else [(para, size, bold, color)]):
                r = p.add_run()
                r.text = str(seg[0])
                f = r.font
                f.name, f.size, f.bold = FONT, Pt(seg[1]), seg[2]
                f.color.rgb = rgb(seg[3])
        return tb

    def box(sl, l, t, w, h, fill, line=None, rounded=False):
        s = sl.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE if rounded else MSO_SHAPE.RECTANGLE, Inches(l), Inches(t), Inches(w), Inches(h))
        if rounded:
            s.adjustments[0] = 0.06
        s.fill.solid()
        s.fill.fore_color.rgb = rgb(fill)
        if line:
            s.line.color.rgb, s.line.width = rgb(line), Pt(0.75)
        else:
            s.line.fill.background()
        s.shadow.inherit = False
        return s

    def slide(title, kicker="", notes=""):
        sl = prs.slides.add_slide(blank)
        state["n"] += 1
        box(sl, 0, 0, W, 0.08, HEX_ACC)
        if kicker:
            text(sl, 0.6, 0.32, 11, 0.3, kicker.upper(), 11, True, HEX_ACC)
        text(sl, 0.6, 0.58, 12.1, 0.7, title, 28, True)
        text(sl, 0.6, 7.02, 9, 0.3, f"{customer} · Assessment Grafana · Confidencial", 9, color=HEX_MUT)
        text(sl, W - 1.6, 7.02, 1.0, 0.3, str(state["n"]), 9, color=HEX_MUT, align=PP_ALIGN.RIGHT)
        if notes:
            sl.notes_slide.notes_text_frame.text = notes
        return sl

    def tile(sl, l, t, w, h, value, label, accent=HEX_ACC, vsize=26):
        box(sl, l, t, w, h, HEX_BG, rounded=True)
        box(sl, l, t + 0.12, 0.06, h - 0.24, accent)
        text(sl, l + 0.2, t + 0.12, w - 0.3, h * 0.55, str(value), vsize, True, accent if accent != HEX_ACC else HEX_TX, anchor=MSO_ANCHOR.MIDDLE)
        text(sl, l + 0.2, t + h * 0.6, w - 0.3, h * 0.38, label, 11, color=HEX_MUT)

    def style_chart(ch, legend=False):
        ch.font.name, ch.font.size = FONT, Pt(12)
        ch.font.color.rgb = rgb(HEX_TX)
        ch.has_title = False
        ch.has_legend = legend
        if legend:
            ch.legend.position, ch.legend.include_in_layout = XL_LEGEND_POSITION.BOTTOM, False

    def bar_chart(sl, l, t, w, h, cats, series, colors_=None, maxv=None, fmt="0", stacked=False, label_size=12):
        cd = CategoryChartData()
        cd.categories = cats
        for name, vals in series:
            cd.add_series(name, vals)
        ch = sl.shapes.add_chart(XL_CHART_TYPE.BAR_STACKED if stacked else XL_CHART_TYPE.BAR_CLUSTERED, Inches(l), Inches(t), Inches(w), Inches(h), cd).chart
        style_chart(ch, legend=stacked)
        plot = ch.plots[0]
        plot.gap_width = 55
        if stacked:
            plot.overlap = 100
        plot.has_data_labels = True
        dl = plot.data_labels
        dl.font.size, dl.font.bold = Pt(12), True
        dl.number_format, dl.number_format_is_linked = fmt, False
        if not stacked:
            dl.position = XL_LABEL_POSITION.OUTSIDE_END
        va = ch.value_axis
        va.minimum_scale = 0
        if maxv:
            va.maximum_scale = maxv
        va.has_major_gridlines, va.visible = False, False
        ca = ch.category_axis
        ca.reverse_order = True
        ca.major_tick_mark = XL_TICK_MARK.NONE
        ca.format.line.color.rgb = rgb(HEX_BD)
        ca.tick_labels.font.size = Pt(label_size)
        if stacked:
            for s, c in zip(plot.series, colors_ or []):
                s.format.fill.solid()
                s.format.fill.fore_color.rgb = rgb(c)
        else:
            for i, c in enumerate(colors_ or []):
                pt = plot.series[0].points[i]
                pt.format.fill.solid()
                pt.format.fill.fore_color.rgb = rgb(c)
        return ch

    def table(sl, l, t, w, h, headers, rows, widths, size=11, aligns=None):
        tb = sl.shapes.add_table(len(rows) + 1, len(headers), Inches(l), Inches(t), Inches(w), Inches(h)).table
        aligns = aligns or [PP_ALIGN.LEFT] * len(headers)
        for j, wd in enumerate(widths):
            tb.columns[j].width = Inches(w * wd / sum(widths))
        for i in range(len(rows) + 1):
            tb.rows[i].height = Inches(h / (len(rows) + 1))
        for i, r in enumerate([[(hd, "#FFFFFF", True) for hd in headers]] + rows):
            for j, v in enumerate(r):
                c = tb.cell(i, j)
                c.fill.solid()
                c.fill.fore_color.rgb = rgb(HEX_TX if i == 0 else HEX_BG if i % 2 == 0 else "#FFFFFF")
                c.margin_left = c.margin_right = Inches(0.07)
                c.margin_top = c.margin_bottom = Inches(0.03)
                c.vertical_anchor = MSO_ANCHOR.MIDDLE
                c.text_frame.word_wrap = True
                paras = v if isinstance(v, list) else [(v[0], size, v[2], v[1]) if isinstance(v, tuple) else (v, size, False, HEX_TX)]
                for k, (txt, sz, b, col) in enumerate(paras):
                    p = c.text_frame.paragraphs[0] if k == 0 else c.text_frame.add_paragraph()
                    p.alignment = aligns[j]
                    run = p.add_run()
                    run.text = str(txt)
                    run.font.name, run.font.size, run.font.bold = FONT, Pt(sz if i else size - 1), b
                    run.font.color.rgb = rgb(col)
        return tb

    def doughnut(sl, l, t, size, sc):
        cd = CategoryChartData()
        cd.categories = ["Score", ""]
        cd.add_series("Score", (sc, 100 - sc))
        ch = sl.shapes.add_chart(XL_CHART_TYPE.DOUGHNUT, Inches(l), Inches(t), Inches(size), Inches(size), cd).chart
        style_chart(ch)
        plot = ch.plots[0]
        plot.has_data_labels = False
        for i, c in enumerate((hex_score(sc), HEX_BD)):
            pt = plot.series[0].points[i]
            pt.format.fill.solid()
            pt.format.fill.fore_color.rgb = rgb(c)
            pt.format.line.fill.background()
        hs = plot._element.find(qn("c:holeSize"))
        if hs is not None:
            hs.set("val", "72")
        text(sl, l, t + size * 0.30, size, size * 0.28, str(sc), 54, True, hex_score(sc), align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
        text(sl, l, t + size * 0.58, size, size * 0.12, "/100", 14, color=HEX_MUT, align=PP_ALIGN.CENTER)

    pils = [p for p in PILLARS if p in pil]
    plain_summary = exec_summary(d, x, b=str, e=str)
    n_dash = DR["lidos"]

    # 1 · Capa
    sl = prs.slides.add_slide(blank)
    state["n"] += 1
    box(sl, 0, 0, W, 7.5, HEX_TX)
    box(sl, 0.8, 2.15, 1.4, 0.08, HEX_ACC)
    text(sl, 0.8, 1.6, 11, 0.4, "GRAFANA · OBSERVABILIDADE E SRE", 14, True, HEX_ACC)
    text(sl, 0.8, 2.45, 11.5, 1.2, "Assessment de observabilidade", 44, True, "#FFFFFF")
    text(sl, 0.8, 3.65, 11.5, 0.6, customer, 26, False, "#FFFFFF")
    text(sl, 0.8, 4.35, 11.5, 0.9, [f"Ambiente {M['ambiente']} · Grafana {PL['versao']} · {num(DR['total'])} dashboards · {num(DS['total'])} fontes de dados",
                                    f"Gerado em {M['gerado_em']} · coleta somente leitura"], 14, color=HEX_SOFT, space=4)
    text(sl, 0.8, 6.6, 11.5, 0.4, "Apresentação para stakeholders · Confidencial", 12, color=HEX_MUT)
    sl.notes_slide.notes_text_frame.text = (f"Objetivo: apresentar a maturidade de observabilidade do Grafana do ambiente {M['ambiente']}, os principais riscos "
                                            "e o plano de ação proposto, e obter as decisões necessárias.")

    # 2 · Escopo
    sl = slide("Escopo e abordagem", "Contexto", "A coleta usou apenas leituras (GET) da API do Grafana; nada foi alterado. Cada controle tem peso por criticidade.")
    text(sl, 0.6, 1.55, 6.6, 5.2, [
        [("Ambiente  ", 16, True, HEX_TX), (f"{M['ambiente']} · Grafana {PL['versao']} ({PL['edicao']})", 16, False, HEX_TX)],
        [("Escala  ", 16, True, HEX_TX), (f"{x['n_orgs']} org(s) · {num(DR['total'])} dashboards · {num(DS['total'])} fontes · {num(RR['total'])} regras", 16, False, HEX_TX)],
        [("Usuários  ", 16, True, HEX_TX), (f"{num(SE['usuarios_ativos'])} habilitados · {num(SE['ativos_30d'])} ativos em 30 dias", 16, False, HEX_TX)],
        [("Janela  ", 16, True, HEX_TX), (f"{M['days']} dias de histórico de alertas", 16, False, HEX_TX)],
        [("Coleta  ", 16, True, HEX_TX), (f"100% somente leitura via API ({M.get('chamadas_api', '-')} chamadas)", 16, False, HEX_TX)],
        [("Método  ", 16, True, HEX_TX), (f"{len(x['evaluated'])} controles em 5 pilares, ponderados por criticidade", 16, False, HEX_TX)],
    ], space=14)
    for i, p in enumerate(PILLARS):
        n = sum(1 for c in x["evaluated"] if c.pillar == p)
        y = 1.55 + i * 1.0
        box(sl, 7.7, y, 5.0, 0.82, HEX_BG, rounded=True)
        box(sl, 7.7, y + 0.12, 0.06, 0.58, HEX_ACC)
        text(sl, 7.95, y + 0.08, 3.6, 0.66, p, 16, True, anchor=MSO_ANCHOR.MIDDLE)
        text(sl, 11.3, y + 0.08, 1.25, 0.66, f"{n} controles", 12, color=HEX_MUT, align=PP_ALIGN.RIGHT, anchor=MSO_ANCHOR.MIDDLE)

    # 3 · Resultado geral
    sl = slide("Resultado geral", "Resumo executivo", plain_summary)
    doughnut(sl, 0.6, 1.5, 3.9, overall)
    text(sl, 0.6, 5.45, 3.9, 0.5, level(overall), 22, True, hex_score(overall), align=PP_ALIGN.CENTER)
    text(sl, 0.6, 5.95, 3.9, 0.4, "Maturidade de observabilidade", 12, color=HEX_MUT, align=PP_ALIGN.CENTER)
    text(sl, 5.0, 1.55, 7.7, 3.2, clip(plain_summary, 760), 14, space=6)
    dso = x["ds_ok"]
    for i, (k, v, c) in enumerate([("Dashboards", num(DR["total"]), HEX_ACC), ("Fontes saudáveis", "N/D" if dso is None else f"{dso}%", HEX_MUT if dso is None else hex_score(dso)),
                                    ("Lacunas identificadas", len(x["fails"]), HEX_ACC), ("Prioridade alta", len(x["high"]), HEX_BAD if x["high"] else HEX_OK)]):
        tile(sl, 5.0 + i * 1.97, 5.0, 1.82, 1.45, v, k, c, 24)

    # 4 · Pilares
    worst = x["worst"][0] if x["worst"] else None
    sl = slide("Maturidade por pilar", "Observabilidade e SRE", "Score de 0 a 100 por pilar. " + " · ".join(f"{p}: {pil[p]}" for p in pils))
    if pils:
        bar_chart(sl, 0.4, 1.45, 8.4, 5.3, pils, [("Score", [pil[p] for p in pils])], [hex_score(pil[p]) for p in pils], maxv=110)
    if x["best"]:
        tile(sl, 9.2, 1.6, 3.5, 1.5, f"{x['best'][1]}", f"Pilar mais forte · {x['best'][0]}", hex_score(x["best"][1]), 30)
    if worst:
        tile(sl, 9.2, 3.3, 3.5, 1.5, f"{worst[1]}", f"Pilar mais frágil · {worst[0]}", hex_score(worst[1]), 30)
    text(sl, 9.2, 5.05, 3.5, 1.7, ["Níveis de maturidade", "Inicial < 40", "Em desenvolvimento 40–64", "Estruturado 65–84", "Otimizado ≥ 85"], 12, color=HEX_MUT, space=2)

    # 5 · Lacunas
    sl = slide("Onde estão as lacunas", "Lacunas por pilar e prioridade",
               f"{len(x['fails'])} lacunas: " + ", ".join(f"{sum(1 for c in x['fails'] if c.severity == s)} {s.lower()}" for s in SEV_ORDER) + ".")
    gp = [p for p in PILLARS if any(c.pillar == p for c in x["evaluated"])]
    if gp:
        bar_chart(sl, 0.4, 1.45, 8.6, 5.4, gp, [(s, [sum(1 for c in x["fails"] if c.pillar == p and c.severity == s) for p in gp]) for s in SEV_ORDER],
                  [SEV_HEX[s] for s in SEV_ORDER], fmt="0;;;", stacked=True)
    tile(sl, 9.4, 1.6, 3.3, 1.5, len(x["fails"]), "Lacunas identificadas", HEX_ACC, 32)
    for i, s in enumerate(SEV_ORDER):
        tile(sl, 9.4, 3.3 + i * 1.18, 3.3, 1.05, sum(1 for c in x["fails"] if c.severity == s), f"Prioridade {s.lower()}", SEV_HEX[s], 20)

    # 6 · Riscos
    top = x["high"] or x["fails"]
    sl = slide("Principais riscos para a operação", f"{len(x['high'])} lacunas de prioridade alta",
               "\n".join(f"- {c.title}: {c.impact} Recomendação: {c.recommendation}" for c in top[:6]))
    for i, c in enumerate(top[:6]):
        l, t = 0.6 + (i % 2) * 6.15, 1.45 + (i // 2) * 1.74
        box(sl, l, t, 5.95, 1.62, HEX_BG, rounded=True)
        box(sl, l, t + 0.15, 0.06, 1.32, SEV_HEX[c.severity])
        text(sl, l + 0.22, t + 0.08, 5.6, 1.5, [[(c.pillar.upper(), 10, True, SEV_HEX[c.severity])], [(clip(c.title, 75), 15, True, HEX_TX)],
                                                 [(clip(c.impact, 130), 11, False, HEX_MUT)],
                                                 [("Ação: ", 11, True, HEX_TX), (clip(c.recommendation, 150), 11, False, HEX_TX)]], space=2)
    if len(top) > 6:
        text(sl, 0.6, 6.68, 12, 0.3, f"+{len(top) - 6} itens no relatório técnico e no backlog (achados.csv).", 11, color=HEX_MUT)
    if not top:
        text(sl, 0.6, 1.6, 12, 1, "Nenhuma lacuna identificada nos controles avaliados.", 18)

    # 7 · Plataforma
    sp = PL["suporte"]
    db = (CF["db_tipo"] or "").lower()
    ha = bool(CF["ha_peers"] or CF["ha_redis"])
    sl = slide("Saúde da plataforma e das fontes de dados", P_PLAT,
               f"Grafana {PL['versao']} (suporte {sp['status']}). Banco: {db or 'N/D'}. Fontes por sinal: " + ", ".join(f"{k} {v}" for k, v in DS["por_sinal"].items()) + ".")
    tiles_ = [(PL["versao"], f"Versão · suporte {sp['status']}", HEX_BAD if sp["status"] == "EOL" else HEX_WARN if sp["status"] == "limitado" else HEX_OK),
              (db or "N/D", "Banco de configuração", HEX_MUT if not db else HEX_BAD if db.startswith("sqlite") else HEX_OK),
              ("N/D" if not db else "sim" if ha else "não", "Alerting em HA", HEX_MUT if not db else HEX_OK if ha else HEX_WARN),
              (len(SE["plugins_angular"]), "Plugins Angular (descontinuado)", HEX_BAD if SE["plugins_angular"] else HEX_OK),
              ("N/D" if dso is None else f"{DS['verificadas'] - DS['falhas']}/{DS['verificadas']}", "Fontes de dados saudáveis",
               HEX_MUT if dso is None else HEX_BAD if DS["falhas"] else HEX_OK)]
    for i, (v, k, c) in enumerate(tiles_):
        tile(sl, 0.6, 1.4 + i * 1.08, 3.6, 0.98, v, k, c, 20)
    sig = list(DS["por_sinal"].items())
    if sig:
        text(sl, 4.6, 1.4, 8, 0.35, "Fontes de dados por sinal de observabilidade", 13, True, HEX_MUT)
        bar_chart(sl, 4.5, 1.75, 8.3, 5.0, [k for k, _ in sig], [("Fontes", [v for _, v in sig])],
                  [HEX_ACC if k in CORE_SIGNALS else HEX_MUT for k, _ in sig], label_size=12)
    else:
        text(sl, 4.6, 1.6, 8, 1.2, "Nenhuma fonte de dados lida: verifique a permissão do usuário (role Admin na organização).", 16, color=HEX_MUT)

    # 8 · Dashboards
    cats = [("Com painel descontinuado (Angular)", DR["com_descontinuado"], HEX_BAD), ("Fonte inexistente", DR["quebrados"], HEX_BAD),
            ("Refresh < 1 min", DR["refresh_agressivo"], HEX_WARN), ("Na pasta General", DR["na_general"], HEX_WARN),
            ("Sem alteração > 1 ano", DR["parados_1a"], HEX_MUT), ("Sem tags", n_dash - DR["com_tag"], HEX_MUT), ("Vazios", DR["vazios"], HEX_MUT)]
    sl = slide("Qualidade dos dashboards", P_COV, f"{num(DR['total'])} dashboards em {num(DR['pastas'])} pastas. "
               + "; ".join(f"{k}: {v}" for k, v, _ in cats) + ".")
    for i, (v, k, c) in enumerate([(num(DR["total"]), "Dashboards", HEX_TX), (num(DR["paineis"]), "Painéis", HEX_TX),
                                   (f"{pct(DR['com_descontinuado'], n_dash)}%", "Com painel descontinuado", HEX_BAD if DR["com_descontinuado"] else HEX_OK),
                                   (f"{pct(DR['provisionados'], n_dash)}%", "Versionados como código", HEX_OK if pct(DR["provisionados"], n_dash) >= 10 else HEX_WARN),
                                   (f"{pct(DR['na_general'], n_dash)}%", "Na pasta General", HEX_WARN if pct(DR["na_general"], n_dash) > 10 else HEX_OK)]):
        tile(sl, 0.6, 1.4 + i * 1.08, 3.6, 0.98, v, k, c, 20)
    if n_dash:
        text(sl, 4.6, 1.4, 8, 0.35, "Dashboards por situação", 13, True, HEX_MUT)
        bar_chart(sl, 4.5, 1.75, 8.3, 5.0, [k for k, _, _ in cats], [("Dashboards", [v for _, v, _ in cats])], [c for _, _, c in cats], label_size=11)

    # 9 · Alertas
    tt = EV["top_regras"][:8]
    sl = slide("Qualidade de alertas", P_ALR, f"{num(RR['total'])} regras; {num(EV['total'])} disparos em {M['days']} dias ({num(EV['por_dia'], 1)}/dia). "
               + "; ".join(f"{t['regra']}: {t['disparos']}" for t in tt))
    tiles_ = [(num(RR["total"]), "Regras de alerta", HEX_ACC), (num(EV["por_dia"], 1), f"Disparos por dia ({M['days']}d)", HEX_ACC),
              (num(EV["mttr_mediana_min"], 1), "MTTR mediano (min)", HEX_ACC), (num(RR["erro"]), "Regras com erro", HEX_BAD if RR["erro"] else HEX_OK),
              (num(AC["mais_30d"]), "Instâncias disparando > 30 dias", HEX_BAD if AC["mais_30d"] else HEX_OK)]
    for i, (v, k, c) in enumerate(tiles_):
        tile(sl, 0.6, 1.4 + i * 1.08, 3.6, 0.98, v, k, c, 20)
    if tt:
        text(sl, 4.6, 1.4, 8, 0.35, "Regras que mais dispararam", 13, True, HEX_MUT)
        bar_chart(sl, 4.5, 1.75, 8.3, 5.0, [clip(t["regra"], 48) for t in tt], [("Disparos", [t["disparos"] for t in tt])], [HEX_ACC] * len(tt), label_size=10)
    elif RR["total"]:
        rows = [("Com erro", RR["erro"], HEX_BAD), ("NoData", RR["nodata"], HEX_WARN), ("Sem severidade", RR["total"] - RR["com_severidade"], HEX_WARN),
                ("Sem runbook", RR["total"] - RR["com_runbook"], HEX_MUT), ("Sem 'for'", RR["sem_for"], HEX_MUT), ("Pausadas", RR["pausadas"], HEX_MUT)]
        text(sl, 4.6, 1.4, 8, 0.35, "Qualidade das regras (sem histórico de disparos na janela)", 13, True, HEX_MUT)
        bar_chart(sl, 4.5, 1.75, 8.3, 5.0, [k for k, _, _ in rows], [("Regras", [v for _, v, _ in rows])], [c for _, _, c in rows], label_size=12)
    else:
        text(sl, 4.6, 1.6, 8, 1.2, "Nenhuma regra de alerta no Grafana: o alerting pode estar em outra ferramenta (ex.: Zabbix). Confirmar com o cliente.", 16, color=HEX_MUT)

    # 10 · Higiene
    dp = HY.get("de_para") or []
    if HY["oportunidades"]:
        de, para = sum(r["de"] for r in dp), sum(r["para"] for r in dp)
        sl = slide("Higiene e carga de consultas", "Oportunidades de otimização",
                   f"{len(HY['oportunidades'])} oportunidades. Redução estimada de {num(de - para, 1)} consultas/min ({pct(de - para, HY['qpm_base'])}% da carga estimada).")
        for i, (v, k, c) in enumerate([(num(len(HY["oportunidades"])), "Oportunidades mapeadas", HEX_TX), (num(de, 1), "DE · consultas/min das categorias", HEX_TX),
                                       (num(para, 1), "PARA · consultas/min após ações", HEX_ACC), (f"{pct(de - para, HY['qpm_base'])}%", "Carga de consultas liberada", HEX_OK)]):
            tile(sl, 0.6 + i * 3.06, 1.4, 2.9, 1.15, v, k, c, 22)
        R = PP_ALIGN.RIGHT
        res = dict_rows(HY["resumo"])
        dpm = {r["categoria"]: r for r in dp}
        rows = [[[(cat, 11, True, HEX_TX), (QPM_RULES.get(cat, (0, ""))[1], 9, False, HEX_MUT)], f"{n}",
                 num(dpm[cat]["de"], 1) if cat in dpm else "—", num(dpm[cat]["para"], 1) if cat in dpm else "—",
                 (num(dpm[cat]["reducao"], 1), HEX_OK, True) if cat in dpm else "—"] for cat, n in res[:8]]
        table(sl, 0.6, 2.75, 12.1, min(3.75, 0.45 * (len(rows) + 1)), ["Categoria · ação", "Objetos", "Consultas/min DE", "PARA", "Redução"],
              rows, [6.2, 1.2, 1.5, 1.5, 1.5], 11, [PP_ALIGN.LEFT, R, R, R, R])
        text(sl, 0.6, 6.55, 12.1, 0.4, QNOTE + " Lista por objeto em higiene_otimizacao.csv.", 9, color=HEX_MUT)

    # 11 · Segurança
    acts = score_actions(checks, P_SEC)
    pil_sec = pil.get(P_SEC)
    sl = slide("Segurança e governança", P_SEC, "Ações ordenadas pelo ganho no score global: " + "; ".join(
        f"{a['check'].title}: segurança {a['pilar_de']}→{a['pilar_para']}, global {a['global_de']}→{a['global_para']}" for a in acts) if acts else "Sem lacunas no pilar.")
    if pil_sec is not None:
        text(sl, 9.0, 0.62, 3.7, 0.6, f"Score do pilar: {pil_sec}", 18, True, hex_score(pil_sec), align=PP_ALIGN.RIGHT)
    sso = SE["sso"]
    sec_t = [("N/D" if SE["anonimo"] is None else "sim" if SE["anonimo"] else "não", "Acesso anônimo", HEX_MUT if SE["anonimo"] is None else HEX_BAD if SE["anonimo"] else HEX_OK),
             ("N/D" if sso is None else "sim" if sso else "não", "SSO (LDAP/OAuth/SAML)", HEX_MUT if sso is None else HEX_OK if sso else HEX_BAD),
             (num(SE["server_admins"]), "Grafana Admins", HEX_MUT if SE["server_admins"] is None else HEX_WARN if SE["server_admins"] > 3 else HEX_OK),
             (num(SE["inativos_90d"]), "Usuários inativos > 90d", HEX_WARN if SE["inativos_90d"] else HEX_OK),
             (num(SE["tokens_sem_expiracao"]) if SE["tokens_ativos"] is not None else "N/D", "Tokens sem expiração", HEX_BAD if SE["tokens_sem_expiracao"] else HEX_OK),
             (num(SE["publicos"]), "Dashboards públicos", HEX_MUT if SE["publicos"] is None else HEX_WARN if SE["publicos"] else HEX_OK)]
    for i, (v, k, c) in enumerate(sec_t):
        tile(sl, 0.6 + i * 2.03, 1.4, 1.93, 1.0, v, k, c, 18)
    if acts:
        def gain(a, b):
            return (f"{a} → {b}" + (f"  (+{b - a})" if b > a else ""), HEX_OK if b > a else HEX_MUT, b > a)
        shown = acts[:5]
        rows = [[f"{i}", [(clip(a["check"].title, 70), 12, True, HEX_TX), (clip(a["check"].recommendation, 115), 10, False, HEX_MUT)],
                 (a["check"].severity, SEV_HEX[a["check"].severity], True), gain(a["pilar_de"], a["pilar_para"]), gain(a["global_de"], a["global_para"]),
                 (f"{a['global_acum']}", hex_score(a["global_acum"]), True)] for i, a in enumerate(shown, 1)]
        C_ = PP_ALIGN.CENTER
        text(sl, 0.6, 2.55, 12, 0.35, "Ações para elevar o score (ganho se apenas esta ação for resolvida)", 13, True, HEX_MUT)
        table(sl, 0.6, 2.92, 12.1, min(3.45, 0.62 * (len(rows) + 1)), ["#", "Ação recomendada", "Prioridade", "Score segurança", "Score global", "Global acumulado"],
              rows, [0.35, 6.1, 1.1, 1.55, 1.55, 1.45], 11, [C_, PP_ALIGN.LEFT, C_, C_, C_, C_])
        last = acts[-1]
        text(sl, 0.6, 6.45, 12.1, 0.45, [[("Resolvendo as " + str(len(acts)) + " lacunas de segurança: ", 12, True, HEX_TX),
                                          (f"pilar {acts[0]['pilar_de']} → {last['pilar_acum']} · score global {acts[0]['global_de']} → {last['global_acum']}", 12, True, HEX_OK)]])
    else:
        text(sl, 0.6, 2.7, 12, 0.6, "Nenhuma lacuna no pilar de segurança nos controles avaliados.", 16)

    # 12 · Roadmap
    sl = slide("Roadmap sugerido", "Plano 30 · 60 · 90 dias",
               " | ".join(f"{label}: {sum(1 for c in x['fails'] if c.severity == s)} itens de prioridade {s.lower()}" for s, label in ROADMAP))
    for i, (sev, label) in enumerate(ROADMAP):
        items = [c for c in x["fails"] if c.severity == sev]
        l = 0.6 + i * 4.1
        box(sl, l, 1.5, 3.9, 0.75, SEV_HEX[sev], rounded=True)
        text(sl, l + 0.15, 1.53, 3.6, 0.7, [[(label, 18, True, "#FFFFFF")], [(f"Prioridade {sev.lower()} · {len(items)} itens", 11, False, "#FFFFFF")]], anchor=MSO_ANCHOR.MIDDLE)
        box(sl, l, 2.35, 3.9, 4.45, HEX_BG, rounded=True)
        lines = [[("•  ", 12, True, SEV_HEX[sev]), (clip(c.title, 52), 12, False, HEX_TX)] for c in items[:11]]
        if len(items) > 11:
            lines.append([(f"+{len(items) - 11} itens no relatório técnico", 11, True, HEX_MUT)])
        text(sl, l + 0.15, 2.5, 3.6, 4.2, lines or "Nenhum item.", 12, color=HEX_MUT, space=5)

    # 13 · Pontos fortes
    sl = slide("Pontos fortes", f"{len(x['oks'])} controles atendidos", "\n".join(f"- {c.title}: {c.evidence}" for c in x["oks"][:12]))
    oks = x["oks"][:12]
    for i, c in enumerate(oks):
        l, t = 0.6 + (i // 6) * 6.15, 1.5 + (i % 6) * 0.86
        text(sl, l, t, 0.4, 0.4, "✓", 18, True, HEX_OK)
        text(sl, l + 0.42, t, 5.5, 0.8, [[(clip(c.title, 62), 15, True, HEX_TX)], [(f"{c.pillar} · {clip(c.evidence, 70)}", 11, False, HEX_MUT)]])
    if len(x["oks"]) > 12:
        text(sl, 0.6, 6.68, 12, 0.3, f"+{len(x['oks']) - 12} controles atendidos no relatório técnico.", 11, color=HEX_MUT)
    if not oks:
        text(sl, 0.6, 1.6, 12, 1, "Nenhum controle atendido integralmente.", 18)

    # 14 · Próximos passos
    nl = next_level(overall)
    steps = [("Validar achados", "Confirmar evidências e priorização com plataforma, NOC/on-call, segurança e donos de serviço."),
             ("Designar responsáveis", f"Owners e datas para as {len(x['high'])} lacunas de prioridade alta (0–30 dias)."),
             ("Aprovar o roadmap", "Patrocínio e capacidade para o plano 30/60/90 (dashboards e alertas como código).")]
    if HY["oportunidades"]:
        steps.append(("Higienizar a configuração", f"Tratar as {len(HY['oportunidades'])} oportunidades mapeadas (dashboards, fontes, regras, acessos)."))
    steps.append(("Medir a evolução", "Reexecutar o assessment em 90 dias" + (f" · meta: {nl[0]} (score ≥ {nl[1]})." if nl else " · manter o nível Otimizado.")))
    sl = slide("Próximos passos e decisões", "Encaminhamentos", "Decisões solicitadas: aprovação do roadmap, responsáveis e cadência de acompanhamento.")
    for i, (h, t_) in enumerate(steps):
        y = 1.5 + i * 1.05
        box(sl, 0.6, y, 0.75, 0.75, HEX_ACC, rounded=True)
        text(sl, 0.6, y, 0.75, 0.75, str(i + 1), 22, True, "#FFFFFF", align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
        text(sl, 1.6, y - 0.02, 6.6, 0.85, [[(h, 17, True, HEX_TX)], [(t_, 13, False, HEX_MUT)]], anchor=MSO_ANCHOR.MIDDLE)
    box(sl, 8.7, 1.5, 4.0, 4.95, HEX_TX, rounded=True)
    text(sl, 8.95, 1.7, 3.5, 4.6, [[("Decisões solicitadas", 18, True, "#FFFFFF")], [("", 8, False, HEX_SOFT)],
                                   [("•  Aprovar o roadmap 30/60/90", 14, False, HEX_SOFT)], [("•  Nomear responsáveis por pilar", 14, False, HEX_SOFT)],
                                   [("•  Definir cadência de acompanhamento (quinzenal)", 14, False, HEX_SOFT)],
                                   [("•  Agendar reavaliação em 90 dias", 14, False, HEX_SOFT)]], space=8)
    prs.core_properties.title = f"Assessment Grafana - {customer}"
    prs.core_properties.author = "grafana_assessment.py"
    prs.save(str(path))


# --------------------------------------------------------------------------- #
# Saídas
# --------------------------------------------------------------------------- #

EXTRA_OUTPUTS = {"pdf": [("relatorio_executivo.pdf", build_pdf_exec), ("relatorio_tecnico.pdf", build_pdf_tech)],
                 "pptx": [("apresentacao_stakeholders.pptx", build_pptx)]}
COLLECTORS = ["identidade", "frontend_settings", "admin_settings", "admin_stats", "sso_settings", "plugins", "usuarios", "organizacoes",
              "fontes_dados", "pastas", "dashboards", "regras_alerta", "estado_alertas", "contact_points", "politicas", "mute_timings",
              "templates_notificacao", "silencios", "alertas_ativos", "entrega_notificacoes", "alertmanager_externo", "historico_alertas",
              "usuarios_org", "times", "service_accounts", "api_keys", "dashboards_publicos", "snapshots", "library_panels", "correlacoes",
              "permissoes_pastas"]


def render_extras(d: dict, checks: list[Check], dom: dict, pil: dict, overall: int, out: Path, customer: str, formats: list[str]) -> None:
    for fmt in formats:
        for name, fn in EXTRA_OUTPUTS.get(fmt, []):
            try:
                fn(d, checks, dom, pil, overall, customer, out / name)
                log(f"gerado {name}")
            except ImportError as e:
                log(f"{name} não gerado: módulo '{e.name}' ausente; instale com: pip install --user reportlab python-pptx "
                    "(ou gere em outra máquina com --render-only dados.json)")
            except Exception as e:  # noqa: BLE001
                log(f"falha ao gerar {name}: {e!r}")


def _csv(path: Path, header: list[str], rows: list[list[Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(header)
        w.writerows(rows)


def _br(v: Any) -> str:
    return "" if v is None else str(v).replace(".", ",")


def finalize(d: dict, out: Path, customer: str, formats: list[str] | None = None) -> int:
    checks = evaluate(d)
    dom, overall = score(checks)
    pil, _ = score(checks, "pillar")
    pil = {p: pil[p] for p in PILLARS if p in pil}
    d["checks"], d["scores"], d["scores_pilar"], d["score_global"] = [asdict(x) for x in checks], dom, pil, overall
    out.mkdir(parents=True, exist_ok=True)
    (out / "dados.json").write_text(json.dumps(d, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    (out / "relatorio.html").write_text(build_report(d, checks, dom, pil, overall, customer), encoding="utf-8")
    _csv(out / "achados.csv", ["Prioridade", "Pilar", "Domínio", "Lacuna", "Evidência", "Impacto", "Recomendação"],
         [[c.severity, c.pillar, c.domain, c.title, c.evidence, c.impact, c.recommendation]
          for c in sorted((c for c in checks if c.passed is False), key=lambda c: SEV_ORDER[c.severity])])
    dsname = {(s["org"], s["uid"]): s["nome"] for s in d["datasources"]}
    _csv(out / "inventario_dashboards.csv",
         ["Organização", "Pasta", "Dashboard", "UID", "Painéis", "Consultas", "Painéis descontinuados", "Tipos descontinuados", "Alertas legados", "Refresh",
          "Variáveis", "Tags", "Fontes usadas", "Fontes inexistentes", "Provisionado", "Versão", "Dias desde a alteração", "Descrição", "Permissão própria", "Lido"],
         [[x["org"], x["pasta"], x["titulo"], x["uid"], x.get("paineis", ""), x.get("queries", ""), x.get("descontinuados", ""),
           ", ".join(x.get("tipos_descontinuados") or []), x.get("alertas_legados", ""), x.get("refresh", ""), x.get("variaveis", ""), x.get("tags", ""),
           ", ".join(dsname.get((x["org"], u), u) for u in x.get("ds_usados") or []), ", ".join(x.get("ds_quebrados") or []),
           yn(x.get("provisionado")) if x["lido"] else "", x.get("versao", ""), _br(x.get("atualizado_dias")), yn(x.get("descricao")) if x["lido"] else "",
           yn(x.get("acl_propria")) if x["lido"] else "", yn(x["lido"])]
          for x in sorted(d["dashboards"], key=lambda x: (x["org"], x["pasta"], str(x["titulo"])))])
    _csv(out / "fontes_dados.csv", ["Organização", "Nome", "UID", "Tipo", "Sinal", "Padrão", "Acesso", "URL", "TLS skip verify", "Health", "Mensagem",
                                    "Dashboards", "Regras", "Correlação", "Provisionada"],
         [[s["org"], s["nome"], s["uid"], s["tipo_nome"], s["sinal"], yn(s["padrao"]), s["acesso"], s["url"], yn(s["tls_skip"]), s["health"] or "N/D",
           s["health_msg"], s["usos_dash"], s["usos_regras"], yn(s["correlacao"]), yn(s["readonly"])]
          for s in sorted(d["datasources"], key=lambda s: (s["health"] != "ERROR", s["org"], str(s["nome"])))])
    _csv(out / "regras_alerta.csv", ["Organização", "Pasta", "Grupo", "Regra", "UID", "Intervalo (s)", "For (s)", "Severidade", "Estado", "Saúde", "Erro",
                                     "Instâncias", "Disparando", "Pausada", "Runbook", "Resumo", "Vinculada a painel", "Fontes", "NoData", "Erro de execução",
                                     "Contact point (direto)"],
         [[r["org"], r["pasta"], r["grupo"], r["titulo"], r["uid"] or "", _br(r["intervalo_s"]), _br(r["for_s"]), r["severidade"] or "", r["estado"] or "",
           r["saude"] or "", r["erro"], r["instancias"], r["disparando"], yn(r["pausada"]), yn(r["runbook"]), yn(r["resumo"]), yn(r["dashboard"]),
           ", ".join(dsname.get((r["org"], u), u) for u in r["datasources"]), r["nodata_state"] or "", r["exec_err_state"] or "", r["receiver"] or ""]
          for r in sorted(d["rules"], key=lambda r: (r["saude"] != "error", r["org"], str(r["pasta"]), str(r["titulo"])))])
    _csv(out / "cobertura_pastas.csv", ["Pasta", "Dashboards", "Painéis", "Com tag", "Sem painel descontinuado", "Sem fonte inexistente", "Alterados < 1 ano",
                                        "Refresh ≥ 1 min", "Provisionados"],
         [[g, v.get("dashboards", 0), v.get("paineis", 0), v.get("com_tag", 0), v.get("sem_descontinuado", 0), v.get("sem_quebrado", 0), v.get("mantidos", 0),
           v.get("refresh_ok", 0), v.get("provisionados", 0)] for g, v in d["coverage"].items()])
    flap = {(t["org"], t["regra"]) for t in d["events"]["flapping"]}
    _csv(out / "top_regras.csv", ["Regra", "Organização", "Disparos", "MTTR mediano (min)", "Flapping"],
         [[t["regra"], t["org"], t["disparos"], _br(t["mttr_mediana_min"]), yn((t["org"], t["regra"]) in flap)] for t in d["events"]["top_regras"]])
    _csv(out / "higiene_otimizacao.csv", ["Categoria", "Tipo", "Objeto", "Grupo", "Detalhe", "Ação recomendada", "Consultas/min atual", "Consultas/min após ação"],
         [[o["categoria"], o["tipo"], o["nome"], o["grupo"], o["detalhe"], QPM_RULES.get(o["categoria"], (0, ""))[1], _br(o["qpm_de"]), _br(o["qpm_para"])]
          for o in d["hygiene"]["oportunidades"]])
    render_extras(d, checks, dom, pil, overall, out, customer, list(EXTRA_OUTPUTS) if formats is None else formats)
    log("Pilares: " + " · ".join(f"{k} {v}" for k, v in pil.items()))
    log(f"Concluído: score {overall}/100 · {d['meta'].get('chamadas_api', 0)} chamadas de leitura · saída em {out.resolve()}")
    return 0


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

PROBES = [("/api/user", {}, "identidade do usuário"), ("/api/user/orgs", {}, "organizações do usuário"), ("/api/frontend/settings", {}, "versão/edição/auth"),
          ("/api/admin/settings", {}, "config do servidor · requer Grafana Admin"), ("/api/admin/stats", {}, "estatísticas · requer Grafana Admin"),
          ("/api/users/search", {"perpage": 1}, "usuários · requer Grafana Admin"), ("/api/orgs", {"perpage": 1}, "todas as orgs · requer Grafana Admin"),
          ("/api/search", {"type": "dash-db", "limit": 1}, "dashboards"), ("/api/datasources", {}, "fontes de dados · requer Admin da org"),
          ("/api/plugins", {"embedded": 0}, "plugins"), ("/api/org/users", {}, "usuários da org · requer Admin da org"),
          ("/api/teams/search", {"perpage": 1}, "times"), ("/api/serviceaccounts/search", {"perpage": 1}, "service accounts · requer Admin da org"),
          ("/api/auth/keys", {}, "API keys legadas"), ("/api/ruler/grafana/api/v1/rules", {}, "regras de alerta"),
          ("/api/prometheus/grafana/api/v1/rules", {}, "estado das regras"), ("/api/v1/provisioning/contact-points", {}, "contact points · requer Admin da org"),
          ("/api/v1/provisioning/policies", {}, "políticas de notificação"), ("/api/alertmanager/grafana/api/v2/silences", {}, "silêncios"),
          ("/api/alertmanager/grafana/config/api/v1/receivers", {}, "status de entrega (10.x+)"), ("/api/annotations", {"type": "alert", "limit": 1}, "histórico de alertas"),
          ("/api/dashboards/public-dashboards", {}, "dashboards públicos"), ("/api/dashboard/snapshots", {}, "snapshots"),
          ("/api/library-elements", {"perPage": 1}, "library panels"), ("/api/v1/sso-settings", {}, "SSO (11.x+)")]


def run_test(G: Grafana, E: Errors) -> int:
    inst = collect_instance(G, E)
    me, sp = inst["me"], inst["suporte"]
    print(f"Conectado: {G.base}\nVersão: {inst['versao']} ({inst['edicao']}) · suporte {sp['status']} · autenticação: {G.auth_mode} · banco: {G.health.get('database', 'N/D')}")
    print(f"{'Identidade (service account)' if G.token_mode else 'Usuário'}: {me.get('login') or '-'} · "
          f"Grafana Admin (server admin): {'sim' if me.get('server_admin') else 'NÃO'}")
    orgs, _ = collect_orgs(G, E, [])
    for o in orgs:
        print(f"  org {o.get('id')}: {o.get('nome')} · papel {o.get('papel') or 'N/D'}" + ("" if o.get("papel") == "Admin" else "  <- recomendado Admin"))
    print(f"Endpoints (org atual {me.get('org_id') or '-'}):")
    for path, params, what in PROBES:
        try:
            r = G.get(path, retry=False, **params)
            n = len(r) if isinstance(r, list) else None
            if isinstance(r, dict) and n is None:
                n = next((i0(r[k]) for k in ("totalCount", "count") if isinstance(r.get(k), int)), None)
            print(f"  {path:<52} OK" + (f"  ({n} itens)" if n is not None else "") + f"  · {what}")
        except GfError as e:
            tag = "n/a " if e.status == 404 else "NEGADO"
            print(f"  {path:<52} {tag} HTTP {e.status} {clip(e.message, 60)}  · {what}")
        except PermissionError:
            raise
        except Exception as e:  # noqa: BLE001
            print(f"  {path:<52} ERRO  {type(e).__name__}: {clip(e, 60)}  · {what}")
    if G.token_mode:
        print("Token de API: escopo de 1 organização e sem Grafana Admin. NEGADO em /api/admin/*, /api/users/search e /api/orgs é "
              "esperado (configuração do servidor, usuários globais e demais orgs ficarão N/A/'parcial').")
        print("Se outros endpoints aparecerem NEGADO, dê role Admin à service account na organização e gere um novo token.")
    else:
        if not me.get("server_admin"):
            print("Aviso: sem Grafana Admin, configuração do servidor, usuários globais e demais organizações ficam 'parcial'/N/A.")
        print("Se algum endpoint aparecer NEGADO, ajuste o usuário (Grafana Admin = sim + Admin em cada org avaliada) antes de rodar.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Assessment read-only de ambiente Grafana (9.x–12.x)")
    ap.add_argument("--url", default=os.getenv("GRAFANA_URL"), help="URL do Grafana, ex.: https://grafana.interno/ (ou GRAFANA_URL)")
    ap.add_argument("--token", default=os.getenv("GRAFANA_TOKEN"),
                    help="Token de API: service account (glsa_...) ou API key (prefira GRAFANA_TOKEN ou o prompt oculto; escopo de 1 org)")
    ap.add_argument("--user", default=os.getenv("GRAFANA_USER"), help="Alternativa ao token: usuário (ou GRAFANA_USER); senha via GRAFANA_PASSWORD ou prompt")
    ap.add_argument("--insecure", action="store_true", help="Não valida o certificado TLS (CA interna/self-signed)")
    ap.add_argument("--ca-bundle", default=os.getenv("GRAFANA_CA_BUNDLE"), help="Arquivo PEM da CA interna (alternativa ao --insecure)")
    ap.add_argument("--no-proxy", action="store_true", help="Ignora HTTP(S)_PROXY do ambiente (acesso direto pela VPN)")
    ap.add_argument("--timeout", type=int, default=60, help="Timeout por chamada (s)")
    ap.add_argument("--customer", default="Assaí Atacadista")
    ap.add_argument("--env-name", default="Produção", help="Nome do ambiente exibido no relatório")
    ap.add_argument("--orgs", default=None, help="Organizações (nome com curingas ou ID, separados por vírgula). Padrão: todas do usuário")
    ap.add_argument("--days", type=int, default=30, help="Janela do histórico de alertas (máx. 365)")
    ap.add_argument("--max-events-per-day", type=int, default=5000, help="Limite de transições de alerta lidas por dia e org")
    ap.add_argument("--max-dashboards", type=int, default=0, help="Analisa no máximo N dashboards por org (0 = todos)")
    ap.add_argument("--skip-ds-health", action="store_true", help="Não executa o health check das fontes de dados")
    ap.add_argument("--expected-integrations", default="", help="Integrações esperadas, ex.: zabbix,teams,servicenow")
    ap.add_argument("--threads", type=int, default=4, help="Chamadas paralelas (padrão 4; aumente com cautela)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--test", action="store_true", help="Só testa conexão/permissões e sai")
    ap.add_argument("--render-only", default=None, help="Regera relatórios a partir de um dados.json existente (não conecta no Grafana)")
    ap.add_argument("--formats", default="pdf,pptx", help="Saídas além de HTML/CSV/JSON: pdf, pptx ou 'none'")
    a = ap.parse_args()
    formats = [f.strip().lower() for f in a.formats.split(",") if f.strip() and f.strip().lower() != "none"]
    bad = [f for f in formats if f not in EXTRA_OUTPUTS]
    if bad:
        ap.error(f"--formats inválido: {', '.join(bad)} (opções: {', '.join(EXTRA_OUTPUTS)}, none)")

    if a.render_only:
        jf = Path(a.render_only)
        d = json.loads(jf.read_text(encoding="utf-8"))
        return finalize(d, Path(a.out) if a.out else jf.parent, a.customer, formats)

    if not a.url:
        ap.error("informe --url ou GRAFANA_URL")
    password = None
    if not a.token and not a.user:
        a.token = getpass.getpass("Token de API do Grafana (service account glsa_... ; entrada oculta): ").strip()
        if not a.token:
            ap.error("informe o token (GRAFANA_TOKEN, --token ou prompt) ou, alternativamente, GRAFANA_USER")
    elif not a.token:
        password = os.getenv("GRAFANA_PASSWORD") or getpass.getpass(f"Senha do usuário {a.user}: ")
    try:
        G = Grafana(a.url, token=a.token, user=a.user, password=password, insecure=a.insecure, ca=a.ca_bundle, timeout=a.timeout, no_proxy=a.no_proxy)
    except ssl.SSLError as e:
        sys.exit(f"Erro TLS: {e}. Use --ca-bundle <ca.pem> ou --insecure.")
    except urllib.error.URLError as e:
        if isinstance(e.reason, ssl.SSLError):
            sys.exit(f"Erro TLS: {e.reason}. Use --ca-bundle <ca.pem> ou --insecure.")
        sys.exit(f"Sem conexão com {a.url}: {e.reason}. Verifique VPN/rota/DNS a partir desta máquina (e --no-proxy se houver proxy no ambiente).")
    except GfError as e:
        sys.exit(f"Falha ao acessar o Grafana: {e}")
    # Valida a credencial com UMA chamada antes de paralelizar (o Grafana bloqueia o login após tentativas erradas seguidas).
    try:
        G.get("/api/org", retry=False)
    except GfError as e:
        if e.status == 401 and G.token_mode:
            sys.exit("Token recusado pelo Grafana (HTTP 401). Confira se o token foi copiado inteiro (sem espaços/quebras), se não expirou, "
                     "não foi revogado e se a service account não está desabilitada. Se houver SSO/proxy na frente, ele precisa repassar "
                     "o header Authorization.")
        if e.status == 401:
            sys.exit("Credencial recusada pelo Grafana (HTTP 401). Confira usuário/senha, se [auth.basic] está habilitado e se o usuário não é "
                     "somente OAuth/SAML. Não repita várias vezes: o Grafana bloqueia o login após 5 tentativas erradas em 5 minutos.")
        sys.exit(f"Credencial sem acesso à organização (HTTP {e.status} {e.message}). "
                 + ("A service account precisa de uma role (recomendado Admin) na organização." if G.token_mode
                    else "O usuário precisa ser membro de ao menos uma organização."))
    E = Errors()
    if a.test:
        return run_test(G, E)

    t0, days = time.time(), max(1, min(a.days, 365))
    a.days, a.threads = days, max(1, a.threads)
    log(f"Grafana {G.health.get('version') or ''} · auth={G.auth_mode} · {G.base}")
    log("instância (versão, configuração, estatísticas, plugins, usuários, organizações)...")
    inst = collect_instance(G, E)
    if G.token_mode:
        log("token de API: avalia só a org do token; configuração do servidor, usuários globais e outras orgs ficarão N/A (esperado)")
    elif not inst["me"].get("server_admin"):
        log("aviso: usuário sem Grafana Admin -> configuração do servidor, usuários globais e outras orgs ficarão parciais")
    users = collect_users(G, E)
    orgs, allo = collect_orgs(G, E, [x for x in (a.orgs or "").split(",") if x.strip()])
    log(f"{len(orgs)} organização(ões) a avaliar: {', '.join(str(o['nome']) for o in orgs)}")
    angular = set(inst["angular_panels"]) | {p["id"] for p in inst["plugins"] if p["angular"] and p["tipo"] == "panel"}
    results = [collect_org(G, E, o, a, angular) for o in orgs]

    url_host = re.sub(r"^https?://", "", G.base).split("/")[0]
    ids = {o["id"] for o in orgs}
    inst["orgs_avaliadas"] = [{"id": o["id"], "nome": o["nome"], "papel": o.get("papel")} for o in orgs]
    inst["orgs_total"] = None if allo is None else len(allo)
    inst["orgs_sem_acesso"] = None if allo is None else [o for o in allo if o["id"] not in ids]
    d: dict[str, Any] = {"meta": {"days": days, "coleta": {}, "gerado_em": datetime.now().strftime("%d/%m/%Y %H:%M"), "ambiente": a.env_name,
                                  "url": G.base, "url_host": url_host, "auth": G.auth_mode, "server_admin": inst["me"].get("server_admin"),
                                  "escopo_orgs": a.orgs or ("org do token" if G.token_mode else "todas do usuário"), "max_dashboards": a.max_dashboards,
                                  "expected_integrations": [x.strip().lower() for x in a.expected_integrations.split(",") if x.strip()]},
                         "platform": inst}
    consolidate(d, inst, users, results, d["meta"]["expected_integrations"])
    for o, R in zip(inst["orgs_avaliadas"], results):
        o.update({"dashboards": R["dash_total"], "fontes": len(R["datasources"]), "regras": len(R["_rules"])})
    build_hygiene(d)
    d.pop("_libs", None)
    coleta = {k: E.status(k) for k in COLLECTORS}
    nh = sum(1 for s in d["datasources"] if s["health"] in ("OK", "ERROR"))
    coleta["health_fontes"] = ("pulado (--skip-ds-health)" if a.skip_ds_health else
                               f"ok ({nh} verificadas, {len(d['datasources']) - nh} sem suporte/permissão)")
    if d["dash_resumo"]["nao_lidos"]:
        coleta["dashboards"] += f" · {d['dash_resumo']['nao_lidos']} não lidos"
    d["meta"]["coleta"] = coleta
    d["meta"]["chamadas_api"] = G.stats["calls"]
    d["meta"]["duracao_s"] = round(time.time() - t0)
    out = Path(a.out or f"grafana-assessment-{datetime.now():%Y%m%d-%H%M}")
    return finalize(d, out, a.customer, formats)


if __name__ == "__main__":
    sys.exit(main())
