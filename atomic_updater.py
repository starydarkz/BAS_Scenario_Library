#!/usr/bin/env python3
"""
caldera_atomic_sync.py
======================
Compara las habilidades (abilities) existentes en una instalación de Caldera
con los ataques del repositorio Atomic Red Team y genera los archivos YAML
faltantes en el formato correcto que Caldera puede interpretar.

Uso:
    python3 caldera_atomic_sync.py --caldera-path /ruta/a/caldera [opciones]

Opciones:
    --caldera-path   Ruta raíz de la instalación de Caldera (requerido)
    --output-dir     Directorio donde guardar las nuevas abilities (default: <caldera>/data/abilities/atomic)
    --temp-dir       Directorio temporal para clonar Atomic Red Team (default: /tmp/atomic-red-team)
    --tactics        Lista de tácticas MITRE a procesar (default: todas)
    --platforms      Plataformas a incluir: windows,linux,macos (default: todas)
    --dry-run        Solo reporta sin crear archivos
    --limit          Límite de atomics a procesar (para pruebas)
    --skip-clone     Usar repositorio ya descargado (usa --temp-dir como ruta)
    --verbose        Mostrar más detalles en el debug

Ejemplo:
    python3 caldera_atomic_sync.py --caldera-path ~/caldera --platforms windows,linux
    python3 caldera_atomic_sync.py --caldera-path ~/caldera --tactics T1059 T1003 --dry-run
"""

import os
import sys
import re
import json
import uuid
import shutil
import argparse
import subprocess
import traceback
from pathlib import Path
from datetime import datetime
from collections import defaultdict

try:
    import yaml
except ImportError:
    print("[ERROR] PyYAML no instalado. Ejecuta: pip install pyyaml")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN Y CONSTANTES
# ─────────────────────────────────────────────────────────────────────────────

ART_REPO_URL = "https://github.com/redcanaryco/atomic-red-team.git"
ART_ATOMICS_SUBDIR = "atomics"

# Mapeo de plataformas ART → Caldera
PLATFORM_MAP = {
    "windows":        "windows",
    "linux":          "linux",
    "macos":          "darwin",
    "darwin":         "darwin",
    "office-365":     None,   # No soportado en Caldera directamente
    "azure-ad":       None,
    "google-workspace": None,
    "saas":           None,
    "iaas":           None,
    "containers":     None,
    "network":        None,
}

# Mapeo de executor ART → Caldera
EXECUTOR_MAP = {
    "command_prompt": "cmd",
    "powershell":     "psh",
    "sh":             "sh",
    "bash":           "sh",
    "python":         "python",
    "ruby":           None,    # No soportado nativamente
    "perl":           None,
    "java":           None,
    "manual":         "manual",
}

# Colores para terminal
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    GRAY   = "\033[90m"
    WHITE  = "\033[97m"

def cprint(msg, color=C.RESET, prefix=""):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{C.GRAY}[{ts}]{C.RESET} {color}{prefix}{msg}{C.RESET}")

def debug(msg):   cprint(msg, C.GRAY,   "  · ")
def info(msg):    cprint(msg, C.WHITE,  "[INF] ")
def success(msg): cprint(msg, C.GREEN,  "[OK]  ")
def warn(msg):    cprint(msg, C.YELLOW, "[WRN] ")
def error(msg):   cprint(msg, C.RED,    "[ERR] ")
def step(msg):    cprint(msg, C.CYAN,   "\n[>>>] ")
def banner(msg):
    line = "─" * (len(msg) + 4)
    print(f"\n{C.BLUE}{C.BOLD}┌{line}┐")
    print(f"│  {msg}  │")
    print(f"└{line}┘{C.RESET}\n")

# ─────────────────────────────────────────────────────────────────────────────
# PASO 1: CLONAR / ACTUALIZAR ATOMIC RED TEAM
# ─────────────────────────────────────────────────────────────────────────────

def clone_atomic_red_team(temp_dir: Path, skip_clone: bool) -> Path:
    step("Repositorio Atomic Red Team")
    atomics_path = temp_dir / ART_ATOMICS_SUBDIR

    if skip_clone:
        if not atomics_path.exists():
            error(f"--skip-clone activo pero no existe: {atomics_path}")
            sys.exit(1)
        info(f"Usando repositorio existente en: {temp_dir}")
        return atomics_path

    if temp_dir.exists():
        warn(f"Directorio temporal existe, eliminando: {temp_dir}")
        shutil.rmtree(temp_dir)

    info(f"Clonando {ART_REPO_URL}")
    info(f"  → destino: {temp_dir}")
    info("  → (esto puede tardar 1-3 minutos según la conexión...)")

    result = subprocess.run(
        ["git", "clone", "--depth=1", ART_REPO_URL, str(temp_dir)],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        error("Falló la clonación del repositorio:")
        error(result.stderr)
        sys.exit(1)

    success(f"Repositorio clonado exitosamente en {temp_dir}")
    return atomics_path

# ─────────────────────────────────────────────────────────────────────────────
# PASO 2: DESCUBRIR ABILITIES EXISTENTES EN CALDERA
# ─────────────────────────────────────────────────────────────────────────────

def load_existing_abilities(caldera_path: Path) -> dict:
    """
    Carga todas las abilities existentes en Caldera.
    Retorna dict: {ability_id: {name, technique_id, ...}}
    """
    step("Cargando abilities existentes en Caldera")
    
    abilities_dir = caldera_path / "data" / "abilities"
    if not abilities_dir.exists():
        error(f"No se encontró directorio de abilities: {abilities_dir}")
        error("Verifica que --caldera-path apunte al directorio raíz de Caldera.")
        sys.exit(1)

    existing = {}
    yml_files = list(abilities_dir.rglob("*.yml")) + list(abilities_dir.rglob("*.yaml"))
    info(f"Escaneando {len(yml_files)} archivos YAML en {abilities_dir}")

    loaded = 0
    errors = 0
    for yml_file in yml_files:
        try:
            with open(yml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            
            if not data:
                continue

            # Caldera guarda abilities como lista o como dict único
            items = data if isinstance(data, list) else [data]
            for item in items:
                if not isinstance(item, dict):
                    continue
                ability_id = item.get("id") or item.get("ability_id")
                if ability_id:
                    existing[str(ability_id)] = {
                        "name":         item.get("name", ""),
                        "technique_id": item.get("technique", {}).get("attack_id", "")
                                        if isinstance(item.get("technique"), dict)
                                        else item.get("attack_id", ""),
                        "file":         str(yml_file),
                    }
                    loaded += 1
        except Exception as e:
            errors += 1
            debug(f"  Error leyendo {yml_file.name}: {e}")

    # También revisamos por nombre de técnica en los metadatos
    technique_ids_in_caldera = set()
    for aid, meta in existing.items():
        tid = meta.get("technique_id", "")
        if tid:
            technique_ids_in_caldera.add(tid.upper())

    success(f"Abilities cargadas: {loaded}  |  Errores: {errors}")
    info(f"IDs de técnicas MITRE presentes: {len(technique_ids_in_caldera)}")
    
    return existing, technique_ids_in_caldera

# ─────────────────────────────────────────────────────────────────────────────
# PASO 3: LEER ATOMICS DE ART
# ─────────────────────────────────────────────────────────────────────────────

def load_atomic_tests(atomics_path: Path, tactic_filter: list, limit: int) -> list:
    """
    Lee todos los archivos .yaml dentro del directorio atomics/ de ART.
    Retorna lista de dicts con los tests.
    """
    step("Leyendo Atomic Red Team tests")

    pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
    technique_dirs = sorted([
        d for d in atomics_path.iterdir()
        if d.is_dir() and pattern.match(d.name)
    ])

    if tactic_filter:
        tactic_filter_upper = [t.upper() for t in tactic_filter]
        technique_dirs = [d for d in technique_dirs if d.name.upper() in tactic_filter_upper]
        info(f"Filtro de tácticas aplicado: {tactic_filter_upper}")

    info(f"Técnicas encontradas en ART: {len(technique_dirs)}")

    all_tests = []
    parse_errors = 0

    for i, tech_dir in enumerate(technique_dirs):
        yml_candidates = (
            list(tech_dir.glob(f"{tech_dir.name}.yaml")) +
            list(tech_dir.glob(f"{tech_dir.name}.yml"))
        )
        if not yml_candidates:
            debug(f"  Sin YAML en {tech_dir.name}")
            continue

        yml_file = yml_candidates[0]
        try:
            with open(yml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or not isinstance(data, dict):
                continue

            technique_id   = data.get("attack_technique", tech_dir.name).upper()
            technique_name = data.get("display_name", "")
            atomic_tests   = data.get("atomic_tests", [])

            debug(f"  [{i+1}/{len(technique_dirs)}] {technique_id}: {len(atomic_tests)} tests — {technique_name}")

            for test in atomic_tests:
                test["_technique_id"]   = technique_id
                test["_technique_name"] = technique_name
                all_tests.append(test)

            if limit and len(all_tests) >= limit:
                warn(f"Límite de {limit} tests alcanzado.")
                break

        except Exception as e:
            parse_errors += 1
            warn(f"  Error parseando {yml_file}: {e}")

    success(f"Total atomic tests leídos: {len(all_tests)}  |  Errores: {parse_errors}")
    return all_tests

# ─────────────────────────────────────────────────────────────────────────────
# PASO 4: DETERMINAR QUÉ FALTA
# ─────────────────────────────────────────────────────────────────────────────

def find_missing_atomics(all_tests: list, existing_abilities: dict,
                          existing_technique_ids: set, platforms_filter: list) -> list:
    """
    Filtra los atomic tests que no están cubiertos en Caldera.
    Se considera 'cubierto' si:
      - Existe una ability con el mismo technique_id Y la plataforma/executor coincide
    """
    step("Comparando contra abilities existentes en Caldera")

    # Índice: technique_id → lista de (platform, executor) cubiertos
    covered_combos = defaultdict(set)
    for aid, meta in existing_abilities.items():
        tid = meta.get("technique_id", "").upper()
        if tid:
            covered_combos[tid].add("_any_")  # marcador general

    missing = []
    skipped_platform = 0
    skipped_executor = 0
    already_covered  = 0

    for test in all_tests:
        tech_id = test.get("_technique_id", "").upper()
        supported_platforms = test.get("supported_platforms", [])
        executor_obj = test.get("executor", {})
        executor_name = (executor_obj.get("name", "") or "").lower()

        # Filtrar por plataformas
        if platforms_filter:
            pf = [p.lower() for p in platforms_filter]
            plat_match = [p for p in supported_platforms if p.lower() in pf]
        else:
            plat_match = [
                p for p in supported_platforms
                if PLATFORM_MAP.get(p.lower()) is not None
            ]

        if not plat_match:
            skipped_platform += 1
            continue

        # Filtrar executor soportado
        caldera_executor = EXECUTOR_MAP.get(executor_name)
        if caldera_executor is None:
            skipped_executor += 1
            debug(f"  Executor no soportado '{executor_name}' en {tech_id} — {test.get('name','')}")
            continue

        # ¿Ya está cubierto?
        if tech_id in covered_combos:
            already_covered += 1
            continue

        # Genera un UUID determinístico basado en technique_id + test name
        seed = f"{tech_id}::{test.get('name','')}"
        ability_id = str(uuid.uuid5(uuid.NAMESPACE_URL, seed))

        missing.append({
            "ability_id":      ability_id,
            "technique_id":    tech_id,
            "technique_name":  test.get("_technique_name", ""),
            "name":            test.get("name", ""),
            "description":     test.get("description", ""),
            "platforms":       plat_match,
            "executor_name":   executor_name,
            "caldera_executor":caldera_executor,
            "executor_obj":    executor_obj,
            "input_arguments": test.get("input_arguments", {}),
            "dependencies":    test.get("dependencies", []),
        })

    info(f"  Ya cubiertos en Caldera : {already_covered}")
    info(f"  Saltados (plataforma)   : {skipped_platform}")
    info(f"  Saltados (executor)     : {skipped_executor}")
    success(f"  Faltantes a generar     : {len(missing)}")
    return missing

# ─────────────────────────────────────────────────────────────────────────────
# PASO 5: CONVERTIR A FORMATO CALDERA
# ─────────────────────────────────────────────────────────────────────────────

def sanitize_command(cmd: str, input_arguments: dict) -> str:
    """
    Convierte variables ART  #{var_name}  →  formato Caldera  #{var_name}
    (El formato es el mismo, pero limpiamos espacios y líneas extra.)
    """
    if not cmd:
        return ""
    # ART usa #{var} igual que Caldera, no se necesita conversión extra
    # Solo limpiamos
    cmd = cmd.strip()
    return cmd

def build_caldera_ability(missing: dict) -> dict:
    """
    Construye el dict que representa una ability en formato Caldera.

    Estructura Caldera (v4+):
    - id
    - name
    - description
    - tactic           (categoría MITRE, se infiere del technique_id)
    - technique:
        attack_id
        name
    - platforms:
        <os>:
          <executor>:
            command
            cleanup
            parsers: []
    - requirements: []
    - privilege: ''
    - repeatable: false
    - singleton: false
    - buckets: [tactic]
    - access: {}
    """
    tech_id    = missing["technique_id"]
    exec_name  = missing["caldera_executor"]
    exec_obj   = missing["executor_obj"]
    input_args = missing.get("input_arguments", {})

    command_raw = exec_obj.get("command", "")
    cleanup_raw = exec_obj.get("cleanup_command", "")
    elevation   = exec_obj.get("elevation_required", False)

    command = sanitize_command(command_raw, input_args)
    cleanup = sanitize_command(cleanup_raw, input_args) if cleanup_raw else ""

    # Infiere táctica del technique_id (heurística simple por rango de ID)
    tactic = infer_tactic(tech_id)

    # Mapea plataformas ART → Caldera
    platforms_dict = {}
    for plat in missing["platforms"]:
        caldera_plat = PLATFORM_MAP.get(plat.lower())
        if caldera_plat:
            if caldera_plat not in platforms_dict:
                platforms_dict[caldera_plat] = {}
            executor_entry = {"command": command}
            if cleanup:
                executor_entry["cleanup"] = cleanup
            executor_entry["parsers"] = []
            platforms_dict[caldera_plat][exec_name] = executor_entry

    ability = {
        "id":          missing["ability_id"],
        "name":        missing["name"],
        "description": missing.get("description", "")[:1000],  # Caldera trunca descripciones largas
        "tactic":      tactic,
        "technique":   {
            "attack_id": tech_id,
            "name":      missing.get("technique_name", ""),
        },
        "platforms":   platforms_dict,
        "requirements": [],
        "privilege":    "Elevated" if elevation else "",
        "repeatable":  False,
        "singleton":   False,
        "buckets":     [tactic],
        "access":      {},
        "tags":        ["atomic-red-team"],
    }

    return ability

TACTIC_RANGES = [
    # (from_id, to_id, tactic_name)
    # Basado en MITRE ATT&CK Enterprise
    ("T1001", "T1029", "command-and-control"),
    ("T1030", "T1030", "exfiltration"),
    ("T1031", "T1055", "persistence"),
    ("T1056", "T1056", "collection"),
    ("T1057", "T1099", "discovery"),
    ("T1100", "T1135", "persistence"),
    ("T1136", "T1199", "persistence"),
    ("T1200", "T1209", "initial-access"),
    ("T1210", "T1220", "lateral-movement"),
    ("T1480", "T1499", "defense-evasion"),
    ("T1500", "T1599", "defense-evasion"),
]

# Mapeo exacto técnica → táctica (subset más comunes)
TECHNIQUE_TACTIC_MAP = {
    "T1003": "credential-access",
    "T1005": "collection",
    "T1006": "defense-evasion",
    "T1007": "discovery",
    "T1008": "command-and-control",
    "T1010": "discovery",
    "T1011": "exfiltration",
    "T1012": "discovery",
    "T1014": "defense-evasion",
    "T1016": "discovery",
    "T1018": "discovery",
    "T1020": "exfiltration",
    "T1021": "lateral-movement",
    "T1025": "collection",
    "T1027": "defense-evasion",
    "T1029": "exfiltration",
    "T1033": "discovery",
    "T1036": "defense-evasion",
    "T1037": "persistence",
    "T1039": "collection",
    "T1040": "credential-access",
    "T1041": "exfiltration",
    "T1046": "discovery",
    "T1047": "execution",
    "T1048": "exfiltration",
    "T1049": "discovery",
    "T1052": "exfiltration",
    "T1053": "execution",
    "T1055": "defense-evasion",
    "T1056": "collection",
    "T1057": "discovery",
    "T1059": "execution",
    "T1060": "persistence",
    "T1063": "discovery",
    "T1064": "defense-evasion",
    "T1069": "discovery",
    "T1070": "defense-evasion",
    "T1071": "command-and-control",
    "T1072": "execution",
    "T1074": "collection",
    "T1075": "lateral-movement",
    "T1076": "lateral-movement",
    "T1077": "lateral-movement",
    "T1078": "persistence",
    "T1082": "discovery",
    "T1083": "discovery",
    "T1086": "execution",
    "T1087": "discovery",
    "T1088": "privilege-escalation",
    "T1089": "defense-evasion",
    "T1090": "command-and-control",
    "T1091": "lateral-movement",
    "T1092": "command-and-control",
    "T1093": "defense-evasion",
    "T1095": "command-and-control",
    "T1097": "lateral-movement",
    "T1098": "persistence",
    "T1099": "defense-evasion",
    "T1100": "persistence",
    "T1101": "persistence",
    "T1102": "command-and-control",
    "T1103": "persistence",
    "T1105": "command-and-control",
    "T1106": "execution",
    "T1107": "defense-evasion",
    "T1108": "persistence",
    "T1110": "credential-access",
    "T1112": "defense-evasion",
    "T1113": "collection",
    "T1114": "collection",
    "T1115": "collection",
    "T1116": "defense-evasion",
    "T1117": "defense-evasion",
    "T1119": "collection",
    "T1120": "discovery",
    "T1121": "defense-evasion",
    "T1122": "persistence",
    "T1123": "collection",
    "T1124": "discovery",
    "T1125": "collection",
    "T1127": "defense-evasion",
    "T1128": "persistence",
    "T1129": "execution",
    "T1130": "defense-evasion",
    "T1131": "persistence",
    "T1132": "command-and-control",
    "T1133": "persistence",
    "T1134": "privilege-escalation",
    "T1135": "discovery",
    "T1136": "persistence",
    "T1137": "persistence",
    "T1138": "persistence",
    "T1139": "credential-access",
    "T1140": "defense-evasion",
    "T1141": "credential-access",
    "T1142": "credential-access",
    "T1143": "defense-evasion",
    "T1144": "defense-evasion",
    "T1145": "credential-access",
    "T1146": "defense-evasion",
    "T1147": "defense-evasion",
    "T1148": "defense-evasion",
    "T1150": "persistence",
    "T1152": "defense-evasion",
    "T1153": "execution",
    "T1154": "execution",
    "T1155": "execution",
    "T1156": "persistence",
    "T1157": "persistence",
    "T1158": "persistence",
    "T1159": "persistence",
    "T1160": "persistence",
    "T1161": "persistence",
    "T1162": "persistence",
    "T1163": "persistence",
    "T1164": "persistence",
    "T1165": "persistence",
    "T1166": "privilege-escalation",
    "T1167": "credential-access",
    "T1168": "persistence",
    "T1169": "privilege-escalation",
    "T1170": "defense-evasion",
    "T1171": "lateral-movement",
    "T1172": "command-and-control",
    "T1173": "execution",
    "T1174": "credential-access",
    "T1175": "lateral-movement",
    "T1176": "persistence",
    "T1177": "persistence",
    "T1178": "privilege-escalation",
    "T1179": "credential-access",
    "T1180": "persistence",
    "T1181": "defense-evasion",
    "T1182": "persistence",
    "T1183": "persistence",
    "T1184": "lateral-movement",
    "T1185": "collection",
    "T1186": "defense-evasion",
    "T1187": "credential-access",
    "T1188": "command-and-control",
    "T1189": "initial-access",
    "T1190": "initial-access",
    "T1191": "defense-evasion",
    "T1192": "initial-access",
    "T1193": "initial-access",
    "T1194": "initial-access",
    "T1195": "initial-access",
    "T1196": "execution",
    "T1197": "defense-evasion",
    "T1198": "defense-evasion",
    "T1199": "initial-access",
    "T1200": "initial-access",
    "T1201": "discovery",
    "T1202": "defense-evasion",
    "T1203": "execution",
    "T1204": "execution",
    "T1205": "command-and-control",
    "T1206": "privilege-escalation",
    "T1207": "defense-evasion",
    "T1208": "lateral-movement",
    "T1209": "persistence",
    "T1210": "lateral-movement",
    "T1211": "defense-evasion",
    "T1212": "credential-access",
    "T1213": "collection",
    "T1214": "credential-access",
    "T1215": "persistence",
    "T1216": "defense-evasion",
    "T1217": "discovery",
    "T1218": "defense-evasion",
    "T1219": "command-and-control",
    "T1220": "defense-evasion",
    "T1480": "defense-evasion",
    "T1482": "discovery",
    "T1484": "privilege-escalation",
    "T1485": "impact",
    "T1486": "impact",
    "T1489": "impact",
    "T1490": "impact",
    "T1491": "impact",
    "T1492": "impact",
    "T1494": "impact",
    "T1495": "impact",
    "T1496": "impact",
    "T1497": "defense-evasion",
    "T1498": "impact",
    "T1499": "impact",
    "T1500": "defense-evasion",
    "T1501": "persistence",
    "T1502": "defense-evasion",
    "T1503": "credential-access",
    "T1504": "persistence",
    "T1505": "persistence",
    "T1506": "defense-evasion",
    "T1518": "discovery",
    "T1519": "persistence",
    "T1522": "credential-access",
    "T1525": "persistence",
    "T1526": "discovery",
    "T1527": "persistence",
    "T1528": "credential-access",
    "T1529": "impact",
    "T1530": "collection",
    "T1531": "impact",
    "T1534": "lateral-movement",
    "T1535": "defense-evasion",
    "T1537": "exfiltration",
    "T1538": "discovery",
    "T1539": "credential-access",
    "T1542": "defense-evasion",
    "T1543": "persistence",
    "T1546": "persistence",
    "T1547": "persistence",
    "T1548": "privilege-escalation",
    "T1550": "defense-evasion",
    "T1552": "credential-access",
    "T1553": "defense-evasion",
    "T1554": "persistence",
    "T1555": "credential-access",
    "T1556": "credential-access",
    "T1557": "credential-access",
    "T1558": "credential-access",
    "T1559": "execution",
    "T1560": "collection",
    "T1561": "impact",
    "T1562": "defense-evasion",
    "T1563": "lateral-movement",
    "T1564": "defense-evasion",
    "T1565": "impact",
    "T1566": "initial-access",
    "T1567": "exfiltration",
    "T1568": "command-and-control",
    "T1569": "execution",
    "T1570": "lateral-movement",
    "T1571": "command-and-control",
    "T1572": "command-and-control",
    "T1573": "command-and-control",
    "T1574": "persistence",
    "T1578": "defense-evasion",
    "T1580": "discovery",
    "T1583": "resource-development",
    "T1584": "resource-development",
    "T1585": "resource-development",
    "T1586": "resource-development",
    "T1587": "resource-development",
    "T1588": "resource-development",
    "T1589": "reconnaissance",
    "T1590": "reconnaissance",
    "T1591": "reconnaissance",
    "T1592": "reconnaissance",
    "T1593": "reconnaissance",
    "T1594": "reconnaissance",
    "T1595": "reconnaissance",
    "T1596": "reconnaissance",
    "T1597": "reconnaissance",
    "T1598": "reconnaissance",
    "T1599": "defense-evasion",
    "T1600": "defense-evasion",
    "T1601": "defense-evasion",
    "T1602": "collection",
    "T1606": "credential-access",
    "T1608": "resource-development",
    "T1609": "execution",
    "T1610": "execution",
    "T1611": "privilege-escalation",
    "T1612": "resource-development",
    "T1613": "discovery",
    "T1614": "discovery",
    "T1615": "discovery",
    "T1619": "discovery",
    "T1620": "defense-evasion",
    "T1621": "credential-access",
    "T1622": "defense-evasion",
    "T1647": "defense-evasion",
    "T1648": "execution",
    "T1649": "credential-access",
    "T1650": "resource-development",
    "T1651": "execution",
    "T1652": "discovery",
    "T1653": "impact",
    "T1654": "discovery",
    "T1656": "defense-evasion",
    "T1657": "impact",
    "T1659": "command-and-control",
    "T1664": "execution",
    "T1666": "privilege-escalation",
}

def infer_tactic(technique_id: str) -> str:
    """Infiere la táctica MITRE a partir del technique_id."""
    # Primero busca en el mapa exacto (sin sub-técnica)
    base_id = technique_id.split(".")[0]
    if base_id in TECHNIQUE_TACTIC_MAP:
        return TECHNIQUE_TACTIC_MAP[base_id]
    return "execution"  # Fallback seguro

# ─────────────────────────────────────────────────────────────────────────────
# PASO 6: GUARDAR ARCHIVOS YAML
# ─────────────────────────────────────────────────────────────────────────────

def save_abilities(missing_list: list, output_dir: Path, dry_run: bool, verbose: bool) -> dict:
    step("Generando archivos YAML para Caldera")
    
    stats = {
        "created": 0,
        "skipped_empty": 0,
        "errors": 0,
        "tactics": defaultdict(int),
    }

    if not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        info(f"Directorio de salida: {output_dir}")

    for i, missing in enumerate(missing_list):
        try:
            ability = build_caldera_ability(missing)

            # Validación mínima: debe haber al menos un comando en alguna plataforma
            has_command = any(
                exec_data.get("command", "").strip()
                for plat_data in ability["platforms"].values()
                for exec_data in plat_data.values()
            )
            if not has_command:
                stats["skipped_empty"] += 1
                debug(f"  [{i+1}] Sin comando válido — saltando: {missing['name'][:60]}")
                continue

            tactic    = ability["tactic"]
            tech_id   = missing["technique_id"]
            safe_name = re.sub(r"[^\w\-]", "_", missing["name"])[:50]
            filename  = f"{tech_id}_{safe_name}_{missing['ability_id'][:8]}.yml"

            # Subtactica para organizar archivos
            tactic_dir = output_dir / tactic
            out_path   = tactic_dir / filename

            if verbose:
                debug(f"  [{i+1}/{len(missing_list)}] {tech_id} → {tactic}/{filename}")
            elif (i + 1) % 50 == 0 or i == 0:
                info(f"  Procesados: {i+1}/{len(missing_list)}  |  Creados: {stats['created']}")

            if not dry_run:
                tactic_dir.mkdir(parents=True, exist_ok=True)
                with open(out_path, "w", encoding="utf-8") as f:
                    yaml.dump(
                        [ability],           # Caldera espera una lista
                        f,
                        default_flow_style=False,
                        allow_unicode=True,
                        sort_keys=False,
                        width=120,
                    )

            stats["created"] += 1
            stats["tactics"][tactic] += 1

        except Exception as e:
            stats["errors"] += 1
            error(f"  Error generando ability para {missing.get('name','?')}: {e}")
            if verbose:
                traceback.print_exc()

    return stats

# ─────────────────────────────────────────────────────────────────────────────
# REPORTE FINAL
# ─────────────────────────────────────────────────────────────────────────────

def print_report(stats: dict, output_dir: Path, dry_run: bool):
    banner("REPORTE FINAL")

    action = "se GENERARÍAN" if dry_run else "GENERADOS"
    print(f"  {C.GREEN}Abilities {action}    : {stats['created']}{C.RESET}")
    print(f"  {C.YELLOW}Sin comando (saltados): {stats['skipped_empty']}{C.RESET}")
    print(f"  {C.RED}Errores               : {stats['errors']}{C.RESET}")

    if stats["tactics"]:
        print(f"\n  {C.CYAN}Por táctica:{C.RESET}")
        for tac, count in sorted(stats["tactics"].items(), key=lambda x: -x[1]):
            bar = "█" * min(count, 40)
            print(f"    {tac:<30} {bar} {count}")

    if not dry_run and stats["created"] > 0:
        print(f"\n  {C.GREEN}Archivos guardados en:{C.RESET}")
        print(f"    {output_dir}")
        print(f"\n  {C.YELLOW}Próximos pasos:{C.RESET}")
        print(f"    1. Reinicia Caldera para que detecte las nuevas abilities.")
        print(f"    2. O usa la API: POST /api/v2/abilities para cargarlas dinámicamente.")
        print(f"    3. Revisa las abilities en la UI: Operations → Abilities → atomic-red-team")

# ─────────────────────────────────────────────────────────────────────────────
# PUNTO DE ENTRADA
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Sincroniza abilities de Caldera con Atomic Red Team",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--caldera-path",  required=True,
                        help="Ruta raíz de la instalación de Caldera")
    parser.add_argument("--output-dir",    default=None,
                        help="Directorio de salida para las abilities (default: <caldera>/data/abilities/atomic)")
    parser.add_argument("--temp-dir",      default="/tmp/atomic-red-team",
                        help="Directorio temporal para clonar ART (default: /tmp/atomic-red-team)")
    parser.add_argument("--tactics",       nargs="+", default=None,
                        help="Lista de técnicas MITRE a procesar (ej: T1059 T1003)")
    parser.add_argument("--platforms",     default=None,
                        help="Plataformas separadas por coma (ej: windows,linux,macos)")
    parser.add_argument("--dry-run",       action="store_true",
                        help="Solo reporta, no crea archivos")
    parser.add_argument("--limit",         type=int, default=0,
                        help="Limita el número de atomics a procesar (0 = sin límite)")
    parser.add_argument("--skip-clone",    action="store_true",
                        help="No clona, usa el repositorio ya existente en --temp-dir")
    parser.add_argument("--verbose",       action="store_true",
                        help="Mostrar debug detallado por cada ability")
    return parser.parse_args()


def main():
    banner("Caldera ↔ Atomic Red Team — Sincronizador de Abilities")
    args = parse_args()

    caldera_path = Path(args.caldera_path).expanduser().resolve()
    temp_dir     = Path(args.temp_dir).expanduser().resolve()
    output_dir   = Path(args.output_dir).expanduser().resolve() if args.output_dir \
                   else caldera_path / "data" / "abilities" / "atomic"
    platforms    = [p.strip().lower() for p in args.platforms.split(",")] \
                   if args.platforms else []

    info(f"Caldera path : {caldera_path}")
    info(f"Output dir   : {output_dir}")
    info(f"Temp dir     : {temp_dir}")
    info(f"Plataformas  : {platforms or 'todas (con soporte en Caldera)'}")
    info(f"Tácticas     : {args.tactics or 'todas'}")
    info(f"Dry-run      : {args.dry_run}")
    info(f"Verbose      : {args.verbose}")
    if args.limit:
        warn(f"Límite       : {args.limit} atomics")

    if not caldera_path.exists():
        error(f"El directorio de Caldera no existe: {caldera_path}")
        sys.exit(1)

    # ── Paso 1: Clonar ART ──────────────────────────────────────────────────
    atomics_path = clone_atomic_red_team(temp_dir, args.skip_clone)

    # ── Paso 2: Cargar abilities existentes ─────────────────────────────────
    existing_abilities, existing_tech_ids = load_existing_abilities(caldera_path)

    # ── Paso 3: Leer ART tests ──────────────────────────────────────────────
    all_tests = load_atomic_tests(atomics_path, args.tactics, args.limit)

    # ── Paso 4: Encontrar faltantes ─────────────────────────────────────────
    missing_list = find_missing_atomics(
        all_tests, existing_abilities, existing_tech_ids, platforms
    )

    if not missing_list:
        success("¡Nada que hacer! Todas las técnicas ya están cubiertas.")
        return

    # ── Paso 5: Generar y guardar ───────────────────────────────────────────
    stats = save_abilities(missing_list, output_dir, args.dry_run, args.verbose)

    # ── Reporte ─────────────────────────────────────────────────────────────
    print_report(stats, output_dir, args.dry_run)


if __name__ == "__main__":
    main()