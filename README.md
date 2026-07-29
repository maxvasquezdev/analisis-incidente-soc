Análisis de Incidente Simulado: Fuerza Bruta y Kerberoasting en Active Directory
TL;DR: Analicé un dataset real de Windows Event Logs y reconstruí un ataque completo contra un entorno de Active Directory: fuerza bruta fallida contra 7 cuentas, seguida de un Kerberoasting exitoso (5 tickets robados), enumeración de recursos y movimiento lateral — todo en una ventana de ~14 segundos. El análisis se hizo con Python y pandas, mapeando cada fase a técnicas de MITRE ATT&CK.
Descripción
Este proyecto documenta el análisis de un incidente simulado de seguridad en un entorno de Active Directory, usando un dataset real de la comunidad de seguridad (Security Datasets / OTRF). El objetivo fue practicar el flujo de trabajo de un analista SOC nivel 1-2: desde la carga y exploración de logs hasta la redacción de un informe de incidente profesional.
Objetivo
Analizar logs reales de Windows (Event Logs) usando Python y pandas
Identificar un ataque de fuerza bruta (T1110.003) y un ataque de robo de tickets Kerberos (T1558.003, Kerberoasting)
Reconstruir el timeline completo del ataque a partir de los timestamps de los eventos
Documentar los hallazgos en un informe de incidente con formato profesional
Herramientas utilizadas
Análisis de datos: Python 3, pandas
Dataset: PurpleSharp Active Directory Playbook I (Security Datasets / OTRF)
Entorno: Arch Linux (terminal)
Formato de logs: JSON (Windows Event Logs — canal Security y Sysmon)
Técnicas MITRE ATT&CK identificadas
ID
Técnica
Táctica
T1110.003
Brute Force: Password Spraying
Credential Access
T1558.003
Steal or Forge Kerberos Tickets: Kerberoasting
Credential Access
T1135
Network Share Discovery
Discovery
T1021.006
Remote Services: Windows Remote Management
Lateral Movement
Metodología
Se descargó el dataset público (logs de Windows en formato JSON) generado con la herramienta PurpleSharp
Se cargaron los logs en un DataFrame de pandas y se exploraron por canal (Channel) y tipo de evento (EventID)
Se filtraron los eventos de autenticación fallida (Event ID 4625) y exitosa (Event ID 4624) del canal Security
Se identificaron 7 cuentas objetivo de un ataque de fuerza bruta, todas fallidas en una ventana de 12 milisegundos
Se cruzaron los resultados con el log original del atacante para confirmar el robo de tickets Kerberos, enumeración de recursos y movimiento lateral
Se documentaron los hallazgos en un informe de incidente completo
Evidencia
Capturas de pantalla del análisis paso a paso disponibles en screenshots/:
DataFrame filtrado por Event ID 4625 (intentos fallidos)
Cruce de datos con el log del atacante confirmando Kerberoasting
Timeline final reconstruido del ataque
Hallazgos principales
El atacante, ya autenticado como pgustavo, ejecutó fuerza bruta contra 7 cuentas del dominio (incluyendo su propia cuenta) — las 7 autenticaciones fallaron. Una hipótesis razonable es que el intento contra su propia cuenta buscaba validar el comportamiento del ataque (confirmar que el spray generaba el evento esperado) antes de lanzarlo contra el resto, o bien es un artefacto de cómo PurpleSharp construye la lista de cuentas objetivo.
El ataque completo (fuerza bruta + robo de tickets + enumeración + movimiento lateral) duró aproximadamente 14 segundos
Aunque el brute force falló, el atacante robó exitosamente 5 tickets de servicio Kerberos, lo que representa una amenaza latente si esas contraseñas son débiles
Impacto y recomendaciones
Rotar credenciales de las cuentas de servicio asociadas a los tickets robados, priorizando las que usan contraseñas antiguas o débiles
Monitorear solicitudes TGS inusuales (Event ID 4769) con tipo de cifrado RC4, indicador clásico de Kerberoasting
Alertar sobre ráfagas de Event ID 4625 en ventanas de milisegundos/segundos contra múltiples cuentas — patrón claro de spraying automatizado
Revisar políticas de contraseñas de cuentas de servicio (idealmente usar Managed Service Accounts para eliminar el riesgo de Kerberoasting)
Informe completo
El informe de incidente detallado (timeline completo, IOCs, análisis técnico, impacto y recomendaciones) está disponible acá: 👉 informe-incidente.md
Lecciones aprendidas
Aprendí a diferenciar Event ID 4624 (login exitoso) de 4625 (login fallido), y por qué son la base de la detección de fuerza bruta
Entendí que un login exitoso de una cuenta no siempre significa que esa cuenta fue comprometida — hay que verificar el contexto (¿ya estaba logueada antes del ataque?)
Aprendí qué es Kerberoasting y por qué es peligroso aunque no genere eventos de fallo
Practiqué el uso de pandas para filtrar, ordenar y cruzar datos de logs a gran escala
🔗 Referencias
Security Datasets (OTRF)
PurpleSharp (herramienta de simulación)
MITRE ATT&CK
Autor: Max Vásquez (@maxvasquezdev)