# Informe de Incidente: Fuerza Bruta y Kerberoasting en Active Directory

**Analista:** Max Vásquez (maxvasquezdev)
**Fecha del análisis:** Julio 2026
**Fecha del incidente (dataset):** 22 de octubre de 2020
**Dataset:** [PurpleSharp Active Directory Playbook I](https://securitydatasets.com/notebooks/atomic/windows/credential_access/SDWIN-201022042947.html) (Security Datasets / OTRF)

---

## 1. Resumen ejecutivo

El 22 de octubre de 2020, una cuenta de dominio (`pgustavo`) ya autenticada en la red ejecutó una herramienta de simulación de ataque (PurpleSharp) que llevó a cabo cuatro acciones maliciosas en menos de 15 segundos: fuerza bruta contra 7 cuentas de usuario, robo de tickets Kerberos de 5 cuentas de servicio, enumeración de recursos compartidos de red, y movimiento lateral vía WinRM hacia 4 equipos del dominio.

El intento de fuerza bruta **falló en su totalidad** (0 de 7 cuentas comprometidas). Sin embargo, el robo de tickets Kerberos **sí se completó con éxito**, representando una amenaza latente: si el atacante logra crackear offline alguna de las contraseñas asociadas, podría obtener acceso legítimo sin generar alertas de login fallido.

## 2. Técnica(s) MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1110.003 | Brute Force: Password Spraying | Credential Access |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Credential Access |
| T1135 | Network Share Discovery | Discovery |
| T1021.006 | Remote Services: Windows Remote Management | Lateral Movement |

## 3. Timeline

| Hora (UTC) | Evento | Detalle |
|---|---|---|
| 08:29:53.908Z | Login legítimo | Primera sesión exitosa de `pgustavo` (Event ID 4624) — punto de partida del análisis |
| 08:29:55.210Z | Intento fallido | Fuerza bruta contra `pgustavo` (su propia cuenta) — Event ID 4625 |
| 08:29:55.211Z | Intento fallido | Fuerza bruta contra `lrodriguez` — Event ID 4625 |
| 08:29:55.214Z | Intento fallido | Fuerza bruta contra `sysmonsvc` — Event ID 4625 |
| 08:29:55.215Z | Intento fallido | Fuerza bruta contra `sbeavers` — Event ID 4625 |
| 08:29:55.217Z | Intento fallido | Fuerza bruta contra `mscott` — Event ID 4625 |
| 08:29:55.219Z | Intento fallido | Fuerza bruta contra `pbeesly` — Event ID 4625 |
| 08:29:55.222Z | Intento fallido | Fuerza bruta contra `nxlogsvc` — Event ID 4625 (fin del brute force, 12ms totales) |
| ~08:29:57Z | Robo de tickets | Kerberoasting exitoso contra 5 SPN (sysmonsvc, nxlogsvc, defensesvc, otrsvc, mordorsvc) |
| ~08:29:57–58Z | Enumeración | Descubrimiento de recursos compartidos en 4 equipos del dominio (WEC, WORKSTATION6, WORKSTATION7, MORDORDC) |
| ~08:29:58–08:30:01Z | Movimiento lateral | Ejecución remota vía WinRM en los 4 equipos enumerados |
| 08:30:08.163Z | Última sesión | Último login exitoso registrado de `pgustavo` (fin de la ventana de actividad) |

**Duración total del ataque:** ~14 segundos.

## 4. Indicadores de Compromiso (IOCs)

| Tipo | Valor | Contexto |
|---|---|---|
| Usuario origen | `pgustavo` | Cuenta desde la que se ejecutó el ataque |
| Herramienta | PurpleSharp.exe | Ejecutada desde `c:\Users\pgustavo\Downloads\` |
| Cuentas objetivo (brute force) | lrodriguez, pgustavo, sysmonsvc, sbeavers, mscott, pbeesly, nxlogsvc | 7 cuentas, 0 comprometidas |
| SPN objetivo (Kerberoasting) | Sysmon, Nxlog, Defense, OTR, Ring | 5 tickets de servicio robados |
| Equipos afectados | WEC, WORKSTATION6, WORKSTATION7, MORDORDC | Enumerados y con ejecución remota vía WinRM |
| Event IDs relevantes | 4624 (login exitoso), 4625 (login fallido) | Canal: Security |

## 5. Análisis técnico

El patrón de tiempos entre los 7 intentos de autenticación fallidos (todos dentro de una ventana de 12 milisegundos) descarta la posibilidad de error humano y confirma el uso de una herramienta automatizada. La API utilizada (`LogonUser` de Win32, vía NTLM) es consistente con un ataque de fuerza bruta local, no remoto — de hecho, el campo `IpAddress` aparece vacío ("-") en estos eventos, lo cual es esperable dado que el ataque se originó desde la propia estación de trabajo del atacante (WORKSTATION5), no a través de la red.

A diferencia del brute force, el robo de tickets Kerberos no depende de adivinar contraseñas: aprovecha que cualquier usuario autenticado en el dominio puede solicitar tickets de servicio (TGS) para cualquier cuenta con un SPN registrado. Esto significa que, aunque el atacante no tenía privilegios elevados, pudo obtener material cifrado de 5 cuentas de servicio sin generar ninguna alerta de fallo — la solicitud de tickets es una operación legítima y esperada en cualquier entorno de Active Directory.

## 6. Impacto

- **Fuerza bruta:** impacto nulo — las 7 cuentas objetivo permanecieron seguras.
- **Kerberoasting:** impacto potencial alto — si las contraseñas de las cuentas de servicio comprometidas (sysmonsvc, nxlogsvc, defensesvc, otrsvc, mordorsvc) son débiles o antiguas, el atacante podría crackearlas offline y obtener acceso legítimo sin dejar rastro adicional en los logs de autenticación fallida.
- **Movimiento lateral:** el atacante confirmó acceso administrativo o de red hacia 4 equipos del dominio, ampliando la superficie de ataque más allá de su estación original.

## 7. Recomendaciones

1. **Rotar las contraseñas** de las cuentas de servicio afectadas (sysmonsvc, nxlogsvc, defensesvc, otrsvc, mordorsvc), priorizando contraseñas largas y aleatorias — las cuentas de servicio son el objetivo típico de Kerberoasting precisamente porque suelen tener contraseñas estáticas y poco robustas.
2. **Implementar detección de Kerberoasting** mediante reglas SIEM que alerten ante solicitudes masivas o inusuales de tickets TGS (Event ID 4769) en una ventana corta de tiempo.
3. **Habilitar bloqueo de cuenta (account lockout policy)** tras un número reducido de intentos fallidos consecutivos, lo que habría frenado el brute force observado.
4. **Monitorear ejecuciones de WinRM** hacia múltiples equipos en ventanas de tiempo cortas, como indicador de movimiento lateral automatizado.
5. **Revisar el uso de cuentas gMSA (Group Managed Service Accounts)** para las cuentas de servicio, que rotan sus contraseñas automáticamente y son resistentes a Kerberoasting.

## 8. Referencias

- [PurpleSharp Active Directory Playbook I — Security Datasets](https://securitydatasets.com/notebooks/atomic/windows/credential_access/SDWIN-201022042947.html)
- [MITRE ATT&CK — T1110.003](https://attack.mitre.org/techniques/T1110/003)
- [MITRE ATT&CK — T1558.003](https://attack.mitre.org/techniques/T1558/003)
- [PurpleSharp (herramienta de simulación)](https://github.com/mvelazc0/PurpleSharp)
