# DNSGuard

App nativa de macOS (SwiftUI, macOS 13+) que **escanea tu LAN en busca de Pi-hole y AdGuard Home**, se conecta a ellos con tus credenciales, **revisa su configuración y aplica optimizaciones** con copia de seguridad previa.

## Compilar y ejecutar

```bash
./build_app.sh          # genera build/DNSGuard.app (firma ad-hoc)
open build/DNSGuard.app
```

Requiere Xcode Command Line Tools / Swift 5.9+. La primera ejecución pide permiso de **red local**.

El icono se regenera con `swift tools/make_icon.swift` (ver `Resources/`).

## Uso

1. Al abrir se escanea la red; también con **⌘R** o el botón *Escanear*. Si falta un servidor, *Añadir IP* (`192.168.1.2` o `192.168.1.2:3000`).
2. Selecciona un servidor → **Conectar…** (AdGuard: usuario + contraseña; Pi-hole: solo contraseña). Opción de guardar en el Llavero.
3. Revisa los hallazgos (verde correcto · azul mejora · naranja aviso · rojo crítico).
4. Marca/desmarca cambios y pulsa **Optimizar (n)**. Antes se guarda una copia en `~/Library/Application Support/DNSGuard/backups/`.

La ayuda completa está dentro de la app: menú **Ayuda › Ayuda de DNSGuard** (⌘?).

## Qué se revisa

| | Pi-hole v6 | AdGuard Home |
|---|---|---|
| Estado | bloqueo activo | protección y filtrado activos |
| Listas | ≥1–2 activas (HaGeZi Pro), gravity < 14 días | ≥1–2 activas (AdGuard DNS filter, HaGeZi Pro), actualización ≤ 24 h |
| Upstreams | ninguno / único / router-ISP | sin cifrar → DoH (Quad9 + Cloudflare), bootstrap, modo paralelo |
| Rendimiento | caché ≥ 10000 | caché ≥ 4 MiB, caché optimista |
| Seguridad / privacidad | rate limit, domainNeeded, bogusPriv, DNSSEC*, modo de escucha (aviso) | rate limit, DNSSEC*, navegación segura*, clientes permitidos (aviso) |

\* Opcionales: vienen desmarcados porque pueden cambiar el comportamiento de la red.

## Estructura

```
Sources/DNSGuard/
  DNSGuardApp.swift       entrada, menús (Ayuda, Archivo)
  ContentView.swift       barra lateral, añadir IP manual
  ServerDetailView.swift  conexión, informe, hallazgos
  HelpView.swift          ventana de ayuda
  AppState.swift          estado global y sesión por servidor
  NetworkScanner.swift    escaneo TCP/53 + identificación HTTP
  PiholeClient.swift      API Pi-hole v6
  AdGuardClient.swift     API AdGuard Home
  HTTP.swift, Keychain.swift, Models.swift
```

## Limitaciones

- Pi-hole v5 se detecta pero no se gestiona.
- No hay restauración automática: las copias se restauran manualmente (Teleporter en Pi-hole; JSON en AdGuard).
- Se aceptan certificados HTTPS autofirmados para los servidores elegidos.
- Las URLs de listas recomendadas deben verificarse antes de aplicarse.

## Autor y licencia

© 2026 Miguel Gonzalez Oreiro ([@mgoreiro](https://github.com/mgoreiro)).

Este programa es software libre: puedes redistribuirlo y/o modificarlo bajo los términos de la **GNU General Public License v3.0** o posterior. Se distribuye sin ninguna garantía. Consulta [LICENSE](LICENSE).

DNSGuard no está afiliado a Pi-hole ni a AdGuard.
