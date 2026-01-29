# Crik0AntiNukeBOT
Sistema de protección anti-nuke de nivel avanzado para Discord, diseñado para detectar, mitigar y revertir ataques destructivos modernos, incluyendo nukes distribuidos, lentos, automatizados y evasivos.  Este bot no se limita a reaccionar: correlaciona, anticipa y neutraliza.

Filosofía del proyecto

Este proyecto existe porque:

Los nukes modernos ya no son simples

La mayoría de anti-nukes reaccionan tarde

La seguridad real requiere anticipación y engaño

Licencia

Uso educativo y defensivo.
El autor no se hace responsable del mal uso o configuraciones negligentes.

¿Que hace este Bot? Detecta ataques coordinados y persistentes, actúa de forma visible o silenciosa, y restaura el servidor de manera transaccional y verificada.

Arquitectura y funcionamiento

El bot se basa en múltiples capas de defensa, todas activas en paralelo:

1. Detección en tiempo real (memoria pura)

Uso de estructuras en memoria (deque)

Ventanas temporales cortas y largas

Latencia mínima (sin depender siempre de audit logs)

2. Correlación multi-executor

Detecta ataques repartidos entre varios usuarios

No depende de thresholds por usuario individual

Ideal contra tools que distribuyen acciones

3. Fingerprinting de ataques

Genera huellas únicas de secuencias de eventos

Identifica patrones repetidos de herramientas de nuking

Permite reconocer ataques aunque cambien de cuentas

4. Detección de slow-nuke

Identifica destrucción gradual (no burst)

Ventanas de 30s, 2min y 5min

Pensado contra atacantes pacientes

5. Modelado de intención acumulada

Guarda historial de comportamientos peligrosos

El riesgo no desaparece instantáneamente

Penaliza escaladas progresivas de poder

6. Shadow mitigation (mitigación silenciosa)

Quita permisos sin ban inmediato

Aplica restricciones invisibles

Rompe herramientas que dependen de feedback visual

7. Cadena de confianza (trust chain)

Rastrea quién dio permisos a quién

Si alguien ataca, se pueden sancionar cómplices

Diseñado contra infiltración interna

8. Protección contra audit-log poisoning

Detecta anomalías en el orden y ritmo de logs

No confía ciegamente en Discord

9. Snapshots y rollback transaccional

Backups completos con hash de integridad

Restauración por fases (roles → categorías → canales)

Abortado si la integridad falla

10. Decisiones probabilísticas

Umbrales con jitter

Acciones no deterministas

Dificulta ingeniería inversa


Requisitos

Python 3.10+

discord.py (última versión estable)

Bot con intents completos

Permisos altos (Manage Roles, Channels, Ban Members)

pip install -U discord.py

TOKEN = "TU_TOKEN_AQUÍ"

Uso recomendado

Invita el bot con permisos completos

Déjalo correr antes de cualquier ataque

No toques los thresholds sin entenderlos

Usa /snapshot tras cambios importantes

Usa /whitelist solo para usuarios de extrema confianza

Comandos principales

/security → Estado del sistema

/snapshot → Crear snapshot manual

/restore → Restaurar último snapshot válido

/whitelist <user> → Usuario ignorado por detecciones

/trustchain <user> → Ver cadena de permisos

Advertencias importantes

Este bot es agresivo por diseño

Falsos positivos son raros, pero posibles si das permisos sin control

No está pensado para servidores pequeños sin moderación

No es un bot “plug and play casual”
