\# caldera-atomic-sync



> Sincroniza automáticamente las abilities de \[MITRE Caldera](https://github.com/mitre/caldera) con el repositorio \[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) de Red Canary, generando los archivos YAML faltantes en el formato nativo que Caldera puede interpretar y cargar directamente.



\---



\## ¿Qué problema resuelve?



Caldera viene con un conjunto limitado de abilities precargadas. Atomic Red Team cuenta con más de \*\*300 técnicas\*\* y más de \*\*1,400 pruebas atómicas\*\* alineadas con MITRE ATT\&CK. Este script automatiza el proceso de:



1\. Descargar el repositorio de Atomic Red Team

2\. Comparar qué técnicas ya existen en tu instalación de Caldera

3\. Convertir los atomic tests faltantes al formato YAML de Caldera

4\. Guardarlos organizados por táctica, listos para usar



Sin este script, importar manualmente cientos de técnicas tomaría horas y requeriría conocer a fondo las diferencias de formato entre ambas herramientas.



\---



\## Características



\- \*\*Descarga automática\*\* del repositorio ART con `git clone --depth=1` (shallow, rápido)

\- \*\*Detección de duplicados\*\* — no sobreescribe abilities ya existentes en Caldera

\- \*\*Conversión de formato\*\* completa: executors, plataformas, comandos, cleanup y privilegios

\- \*\*UUIDs determinísticos\*\* — el mismo atomic siempre genera el mismo ID, evitando duplicados en reruns

\- \*\*Organización por táctica\*\* — archivos guardados en subdirectorios por táctica MITRE (`credential-access/`, `execution/`, etc.)

\- \*\*Filtros flexibles\*\* — por plataforma, por técnica específica, por número de tests

\- \*\*Modo dry-run\*\* — ver exactamente qué se generaría sin tocar nada

\- \*\*Debug con timestamps\*\* — output a color con progreso en tiempo real

\- \*\*Mapeo completo\*\* de más de 100 technique IDs a su táctica MITRE correspondiente



\---



\## Requisitos



| Dependencia | Versión mínima | Instalación |

|-------------|---------------|-------------|

| Python      | 3.8+          | —           |

| PyYAML      | cualquiera    | `pip install pyyaml` |

| git         | cualquiera    | Sistema operativo |



```bash

pip install pyyaml

```



\---



\## Instalación



```bash

git clone https://github.com/tu-usuario/caldera-atomic-sync.git

cd caldera-atomic-sync

pip install pyyaml

```



\---



\## Uso



\### Ejecución completa (recomendado para empezar)



```bash

python3 caldera\_atomic\_sync.py --caldera-path \~/caldera

```



Esto descarga ART, compara contra tus abilities y genera todo lo faltante en `\~/caldera/data/abilities/atomic/`.



\### Ver qué se generaría sin crear archivos



```bash

python3 caldera\_atomic\_sync.py --caldera-path \~/caldera --dry-run

```



\### Filtrar por plataformas



```bash

\# Solo Windows y Linux

python3 caldera\_atomic\_sync.py --caldera-path \~/caldera --platforms windows,linux



\# Solo macOS

python3 caldera\_atomic\_sync.py --caldera-path \~/caldera --platforms macos

```



\### Filtrar por técnicas MITRE específicas



```bash

\# Solo T1059 (Command and Scripting Interpreter) y T1003 (Credential Dumping)

python3 caldera\_atomic\_sync.py --caldera-path \~/caldera --tactics T1059 T1003 T1082

```



\### Usar un repositorio ART ya descargado



```bash

\# Evita volver a clonar si ya tienes el repositorio local

python3 caldera\_atomic\_sync.py \\

&#x20; --caldera-path \~/caldera \\

&#x20; --skip-clone \\

&#x20; --temp-dir /opt/atomic-red-team

```



\### Debug detallado



```bash

python3 caldera\_atomic\_sync.py --caldera-path \~/caldera --verbose

```



\### Prueba con un número limitado de tests



```bash

\# Procesa solo los primeros 50 atomics (útil para probar configuración)

python3 caldera\_atomic\_sync.py --caldera-path \~/caldera --limit 50

```



\### Guardar en directorio personalizado



```bash

python3 caldera\_atomic\_sync.py \\

&#x20; --caldera-path \~/caldera \\

&#x20; --output-dir \~/caldera/data/abilities/art-custom

```



\---



\## Referencia de argumentos



| Argumento | Tipo | Default | Descripción |

|-----------|------|---------|-------------|

| `--caldera-path` | ruta | \*\*requerido\*\* | Directorio raíz de la instalación de Caldera |

| `--output-dir` | ruta | `<caldera>/data/abilities/atomic` | Donde guardar las abilities generadas |

| `--temp-dir` | ruta | `/tmp/atomic-red-team` | Dónde clonar el repositorio ART |

| `--tactics` | lista | todas | Técnicas MITRE a procesar (ej: `T1059 T1003`) |

| `--platforms` | string | todas | Plataformas separadas por coma: `windows,linux,macos` |

| `--dry-run` | flag | false | Solo reporta, no crea archivos |

| `--limit` | int | 0 (sin límite) | Máximo de atomics a procesar |

| `--skip-clone` | flag | false | Usa repositorio ya existente en `--temp-dir` |

| `--verbose` | flag | false | Muestra debug por cada ability generada |



\---



\## Formato de salida



Cada ability generada sigue el esquema YAML nativo de Caldera v4+:



```yaml

\- id: ae753596-e899-546e-910d-72ee8f83e3c2

&#x20; name: Dump LSASS Memory using ProcDump

&#x20; description: Dumps credentials from LSASS using ProcDump

&#x20; tactic: credential-access

&#x20; technique:

&#x20;   attack\_id: T1003

&#x20;   name: OS Credential Dumping

&#x20; platforms:

&#x20;   windows:

&#x20;     cmd:

&#x20;       command: procdump.exe -ma lsass.exe lsass\_dump

&#x20;       cleanup: del lsass\_dump.dmp

&#x20;       parsers: \[]

&#x20; requirements: \[]

&#x20; privilege: Elevated

&#x20; repeatable: false

&#x20; singleton: false

&#x20; buckets:

&#x20;   - credential-access

&#x20; access: {}

&#x20; tags:

&#x20;   - atomic-red-team

```



Los archivos se organizan en subdirectorios por táctica:



```

caldera/data/abilities/atomic/

├── credential-access/

│   ├── T1003\_Dump\_LSASS\_Memory\_ae753596.yml

│   └── T1003\_Mimikatz\_logonpasswords\_9a1b8d39.yml

├── execution/

│   └── T1059\_Command-Line\_Interface\_c2dc8f09.yml

├── discovery/

│   └── T1082\_System\_Information\_Discovery\_e36ecad0.yml

└── ...

```



\---



\## Mapeo de plataformas y executors



\### Plataformas soportadas



| ART | Caldera | Soportado |

|-----|---------|-----------|

| `windows` | `windows` | ✅ |

| `linux` | `linux` | ✅ |

| `macos` | `darwin` | ✅ |

| `office-365` | — | ❌ |

| `azure-ad` | — | ❌ |

| `google-workspace` | — | ❌ |

| `containers` | — | ❌ |

| `network` | — | ❌ |



\### Executors soportados



| ART | Caldera | Soportado |

|-----|---------|-----------|

| `command\_prompt` | `cmd` | ✅ |

| `powershell` | `psh` | ✅ |

| `sh` / `bash` | `sh` | ✅ |

| `python` | `python` | ✅ |

| `manual` | `manual` | ✅ |

| `ruby` | — | ❌ |

| `perl` | — | ❌ |

| `java` | — | ❌ |



Los tests con plataformas o executors no soportados se saltan automáticamente y se reportan al final.



\---



\## Lógica de deduplicación



El script considera que una técnica \*\*ya está cubierta\*\* si existe en Caldera al menos una ability con el mismo `technique.attack\_id`. En ese caso, todos los atomic tests de esa técnica se omiten para no crear conflictos.



Los IDs de las abilities nuevas son \*\*UUID v5 determinísticos\*\* generados a partir de `technique\_id + nombre del test`. Esto garantiza que si corres el script múltiples veces, siempre se genera el mismo ID para el mismo atomic, evitando duplicados.



\---



\## Después de ejecutar



Una vez generados los archivos, Caldera necesita detectarlos. Tienes dos opciones:



\*\*Opción 1 — Reiniciar Caldera\*\* (método más simple):

```bash

\# Detener y reiniciar el servidor

python3 server.py

```



\*\*Opción 2 — API REST\*\* (sin downtime, Caldera v4+):

```bash

\# Cargar una ability específica vía API

curl -X POST http://localhost:8888/api/v2/abilities \\

&#x20; -H "KEY: your-api-key" \\

&#x20; -H "Content-Type: application/json" \\

&#x20; -d @ability.yml

```



\*\*Verificar en la UI:\*\*

`Operations → Abilities → Filtrar por tag: atomic-red-team`



\---



\## Ejemplo de output del script



```

┌──────────────────────────────────────────────────────────┐

│  Caldera ↔ Atomic Red Team — Sincronizador de Abilities  │

└──────────────────────────────────────────────────────────┘



\[15:31:59] \[INF] Caldera path : /home/user/caldera

\[15:31:59] \[INF] Output dir   : /home/user/caldera/data/abilities/atomic

\[15:31:59] \[INF] Plataformas  : todas (con soporte en Caldera)



\[>>>] Repositorio Atomic Red Team

\[15:32:01] \[INF] Clonando https://github.com/redcanaryco/atomic-red-team.git

\[15:34:22] \[OK]  Repositorio clonado exitosamente



\[>>>] Cargando abilities existentes en Caldera

\[15:34:22] \[INF] Escaneando 312 archivos YAML en data/abilities

\[15:34:23] \[OK]  Abilities cargadas: 312  |  Errores: 0

\[15:34:23] \[INF] IDs de técnicas MITRE presentes: 87



\[>>>] Leyendo Atomic Red Team tests

\[15:34:23] \[INF] Técnicas encontradas en ART: 298

\[15:34:25] \[OK]  Total atomic tests leídos: 1423  |  Errores: 2



\[>>>] Comparando contra abilities existentes en Caldera

\[15:34:25] \[INF]   Ya cubiertos en Caldera : 347

\[15:34:25] \[INF]   Saltados (plataforma)   : 201

\[15:34:25] \[INF]   Saltados (executor)     : 89

\[15:34:25] \[OK]    Faltantes a generar     : 786



\[>>>] Generando archivos YAML para Caldera

\[15:34:25] \[INF]   Procesados: 50/786  |  Creados: 49

...



┌─────────────────┐

│  REPORTE FINAL  │

└─────────────────┘



&#x20; Abilities GENERADOS    : 786

&#x20; Sin comando (saltados) : 12

&#x20; Errores                : 0



&#x20; Por táctica:

&#x20;   defense-evasion                ████████████████████████████ 187

&#x20;   discovery                      █████████████████ 114

&#x20;   execution                      ███████████████ 98

&#x20;   persistence                    ████████████ 82

&#x20;   credential-access              ██████████ 71

&#x20;   lateral-movement               ████████ 54

&#x20;   collection                     ███████ 48

&#x20;   command-and-control            ████ 31

&#x20;   privilege-escalation           ████ 28

&#x20;   impact                         ███ 21

&#x20;   exfiltration                   ██ 19

&#x20;   initial-access                 ██ 17

&#x20;   ...

```



\---



\## Casos de uso comunes



\*\*Ejercicio de red team completo:\*\*

```bash

\# Generar todas las TTPs para Windows y Linux, con debug

python3 caldera\_atomic\_sync.py \\

&#x20; --caldera-path \~/caldera \\

&#x20; --platforms windows,linux \\

&#x20; --verbose

```



\*\*Enfocarse en credential access para un engagement:\*\*

```bash

python3 caldera\_atomic\_sync.py \\

&#x20; --caldera-path \~/caldera \\

&#x20; --tactics T1003 T1110 T1552 T1555 T1558 \\

&#x20; --platforms windows

```



\*\*Pipeline CI/CD para mantener Caldera actualizado:\*\*

```bash

\#!/bin/bash

\# Ejecutar semanalmente

python3 caldera\_atomic\_sync.py \\

&#x20; --caldera-path $CALDERA\_PATH \\

&#x20; --temp-dir /opt/art-cache \\

&#x20; --skip-clone \\   # ART ya actualizado por separado

&#x20; --dry-run | tee sync\_report\_$(date +%Y%m%d).txt

```



\---



\## Limitaciones conocidas



\- Los atomic tests con variables de entrada (`input\_arguments`) se importan con los placeholders `#{variable}` tal como están en ART. Caldera puede resolver estas variables si se definen como facts en los agentes.

\- Técnicas que requieren herramientas externas (Mimikatz, ProcDump, etc.) necesitan que esas herramientas estén presentes en el agente objetivo.

\- El mapeo de táctica se hace por technique ID. Sub-técnicas (ej. `T1059.001`) heredan la táctica del parent.

\- Atomic tests con executor `manual` se importan pero requieren ejecución humana — Caldera los mostrará como ability de tipo manual.



\---



\## Contribuir



Pull requests bienvenidos. Áreas donde se puede mejorar:



\- Soporte para cargar abilities directamente vía API REST de Caldera

\- Resolución automática de `input\_arguments` usando facts existentes de Caldera

\- Modo `--update` para actualizar abilities existentes cuando ART las modifique

\- Soporte para containers/Docker via executor personalizado



\---



\## Licencia



MIT — libre para uso en entornos de red team, blue team y ejercicios de seguridad ofensiva.



\---



\## Referencias



\- \[MITRE Caldera](https://github.com/mitre/caldera) — Framework de adversary emulation

\- \[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — Librería de tests atómicos por Red Canary

\- \[MITRE ATT\&CK](https://attack.mitre.org) — Framework de tácticas y técnicas de adversarios

\- \[Caldera Ability Format](https://caldera.readthedocs.io/en/latest/Abilities.html) — Documentación del formato de abilities



