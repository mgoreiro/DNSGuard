// DNSGuard — Copyright (C) 2026 Miguel Gonzalez Oreiro
// Licensed under the GNU General Public License v3.0 or later. See LICENSE.

import SwiftUI

private struct HelpTopic: Identifiable {
    let id: String
    let title: String
    let icon: String
    let body: [(String, String)]   // (subtítulo, texto)
}

private let topics: [HelpTopic] = [
    HelpTopic(id: "start", title: "Primeros pasos", icon: "play.circle", body: [
        ("Qué es DNSGuard", "DNSGuard encuentra servidores Pi-hole y AdGuard Home en tu red local, se conecta a ellos, revisa su configuración y aplica mejoras de forma segura."),
        ("Flujo básico", "1. Al abrir la app se escanea la red automáticamente.\n2. Elige un servidor en la barra lateral.\n3. Pulsa «Conectar…» e introduce las credenciales.\n4. Revisa los hallazgos, marca los cambios que quieras y pulsa «Optimizar»."),
        ("Permiso de red local", "La primera vez macOS pide permiso para acceder a la red local. Debes aceptarlo; si lo denegaste, actívalo en Ajustes del Sistema › Privacidad y seguridad › Red local.")
    ]),
    HelpTopic(id: "scan", title: "Escaneo de la red", icon: "dot.radiowaves.left.and.right", body: [
        ("Cómo funciona", "Se calculan las subredes de tus interfaces de red (Wi-Fi/Ethernet) y se prueba el puerto 53 (DNS) en cada dirección. En los equipos que responden se identifica si son Pi-hole (v5/v6) o AdGuard Home probando los puertos web 80, 3000, 8080, 8081, 443 y 8443."),
        ("Escanear", "Botón «Escanear» de la barra lateral, o Archivo › Escanear la red (⌘R). Los servidores ya encontrados se conservan."),
        ("Añadir IP", "Si un servidor no aparece (otra VLAN, puerto 53 filtrado…), usa «Añadir IP». Acepta una IP o nombre con puerto opcional, p. ej. 192.168.1.2 o 192.168.1.2:3000."),
        ("Límites", "Las redes mayores de /22 se limitan a la /24 donde está tu Mac. Las IPs de otras redes se añaden manualmente.")
    ]),
    HelpTopic(id: "login", title: "Conexión y credenciales", icon: "key", body: [
        ("Pi-hole", "Solo requiere la contraseña del panel web (el campo de usuario no existe). Solo se admite Pi-hole v6 o superior; las instancias v5 se detectan pero no se gestionan."),
        ("AdGuard Home", "Requiere el usuario y la contraseña del panel web (autenticación básica)."),
        ("Recordar en el llavero", "Si lo marcas, la contraseña se guarda en el Llavero de macOS y el usuario en las preferencias de la app; se rellenarán la próxima vez. Si lo desmarcas, se borra la contraseña guardada."),
        ("Desconectar", "Cierra la sesión (en Pi-hole invalida el token) y vuelve a la pantalla de conexión."),
        ("Certificados", "Los servidores de LAN suelen usar certificados autofirmados, por lo que DNSGuard acepta cualquier certificado HTTPS en las conexiones a los servidores que eliges.")
    ]),
    HelpTopic(id: "audit", title: "Revisión de configuración", icon: "checklist", body: [
        ("Resumen", "Versión, estado del bloqueo, listas activas, estadísticas, upstreams y otros datos clave del servidor."),
        ("Hallazgos", "Cada comprobación aparece con un icono: verde = correcto, azul = información/mejora opcional, naranja = advertencia, rojo = crítico. Si tiene arreglo automático, verás la acción que se aplicaría y un interruptor."),
        ("Reanalizar", "Vuelve a leer la configuración del servidor y reinicia la selección de cambios."),
        ("Opcional", "Los cambios que pueden alterar el comportamiento de tu red vienen desmarcados y con un aviso naranja. Márcalos solo si los quieres.")
    ]),
    HelpTopic(id: "pihole", title: "Comprobaciones Pi-hole", icon: "shield.lefthalf.filled", body: [
        ("Bloqueo", "Detecta si el bloqueo está desactivado y lo reactiva."),
        ("Listas de bloqueo", "Sin listas activas añade HaGeZi Pro y actualiza gravity. Con una sola, sugiere añadir otra."),
        ("Gravity", "Si lleva 14 días o más sin actualizarse, lo actualiza."),
        ("Upstreams", "Avisa si no hay ninguno, si hay uno solo (añade uno de respaldo) o si todos son el router/ISP (sugiere Quad9; opcional). Si usas un resolvedor local como unbound o cloudflared (127.x) no se toca."),
        ("DNSSEC", "Opcional: puede romper la resolución con upstreams no compatibles."),
        ("Caché", "Sube la caché a 10000 entradas si es menor."),
        ("domainNeeded / bogusPriv", "Evitan que nombres sin dominio y búsquedas inversas privadas salgan a Internet."),
        ("Rate limit", "Si está a 0 lo fija en 1000 consultas / 60 s por cliente."),
        ("Solo aviso", "Modo de escucha «ALL» (resolvedor abierto) y registro de consultas desactivado: se informa pero no se cambia.")
    ]),
    HelpTopic(id: "adguard", title: "Comprobaciones AdGuard Home", icon: "shield.checkered", body: [
        ("Protección y filtrado", "Reactiva la protección o el filtrado por listas si están desactivados."),
        ("Listas", "Sin listas añade «AdGuard DNS filter» y HaGeZi Pro; con una sola, sugiere HaGeZi Pro."),
        ("Actualización de listas", "Si es manual (0) o superior a 72 h, la fija en 24 h."),
        ("Upstreams cifrados", "Si hay DNS públicos sin cifrar (p. ej. 8.8.8.8) propone DNS sobre HTTPS (Quad9 + Cloudflare) y configura el bootstrap. Conserva reglas por dominio y upstreams privados."),
        ("Modo paralelo", "Con varios upstreams, consulta a todos a la vez para menor latencia."),
        ("Caché", "Sube la caché a 4 MiB si es menor y activa la caché optimista."),
        ("Rate limit", "Si está a 0, lo fija en 20 consultas/s por cliente."),
        ("Opcionales", "DNSSEC y navegación segura (envía prefijos de hash a AdGuard)."),
        ("Solo aviso", "Lista de clientes permitidos vacía: se informa pero no se cambia.")
    ]),
    HelpTopic(id: "bench", title: "Prueba de rendimiento", icon: "speedometer", body: [
        ("Qué hace", "Mide la latencia DNS de tus servidores enviando consultas reales por UDP/53 desde este Mac, y la compara con Cloudflare (1.1.1.1), Google (8.8.8.8) y Quad9 (9.9.9.9). No necesita credenciales."),
        ("Cómo se lanza", "Botón «Rendimiento» en la cabecera de un servidor (solo ese) o en la barra lateral (todos los encontrados). «Repetir» vuelve a medir."),
        ("En caché", "Mediana del tiempo de respuesta de 10 dominios populares ya resueltos (20 muestras). Mide la red hasta el servidor: en LAN debería estar por debajo de 5 ms."),
        ("Sin caché", "Mediana de 10 consultas a nombres inexistentes únicos, que obligan al servidor a preguntar a su upstream. Mide la velocidad real de tus upstreams."),
        ("Pérdida", "Porcentaje de consultas sin respuesta en 2 s. Si es alto, revisa la red o los límites de tasa."),
        ("Bloqueo", "Cuántos de 3 dominios publicitarios conocidos bloquea el servidor (NXDOMAIN, 0.0.0.0, REFUSED o su propia IP)."),
        ("Conclusiones", "Debajo de la tabla se indican problemas y sugerencias, p. ej. si tus upstreams son claramente más lentos que los públicos."),
        ("Mejoras sugeridas", "Tras medir, la revisión del servidor añade mejoras según los resultados: cambiar a los upstreams más rápidos medidos (DoH + modo paralelo en AdGuard; IPs públicas en Pi-hole), subir la caché a 16 MiB, fijar un TTL mínimo de 300 s (opcional), subir el límite de tasa si hay pérdidas y avisar de latencia alta hasta el servidor (Wi-Fi). Si ya estás conectado, la revisión se actualiza sola al terminar la prueba; si no, aparecerán al conectar. Después de aplicarlas, repite la prueba para medir la mejora."),
        ("Nota", "Las consultas se espacian 60 ms para no activar el límite de tasa de AdGuard (20/s por cliente), por eso cada servidor tarda unos 5 s. La medición incluye tu Wi-Fi.")
    ]),
    HelpTopic(id: "apply", title: "Optimizar y copias", icon: "wand.and.stars", body: [
        ("Optimizar", "El botón «Optimizar (n)» aplica los n cambios marcados tras pedir confirmación. Después de aplicar se vuelve a analizar el servidor."),
        ("Copia de seguridad", "Antes de cambiar nada se guarda una copia en ~/Library/Application Support/DNSGuard/backups/. Pi-hole: exportación Teleporter (o JSON de configuración). AdGuard: JSON con su configuración. Si la copia falla, no se aplica ningún cambio."),
        ("Restaurar", "DNSGuard no restaura automáticamente. Para volver atrás en Pi-hole usa Ajustes › Teleporter › Importar; en AdGuard, reintroduce los valores del JSON."),
        ("Registro", "Cada acción queda anotada con ✓ (correcta) o ✗ (fallida, con el motivo). Si algo falla, el resto de cambios continúa."),
        ("Carpeta de copias", "Archivo › Abrir carpeta de copias de seguridad.")
    ]),
    HelpTopic(id: "shortcuts", title: "Atajos y menús", icon: "command", body: [
        ("⌘R", "Escanear la red."),
        ("⌘?", "Abrir esta ayuda."),
        ("Archivo", "Escanear la red · Abrir carpeta de copias de seguridad."),
        ("Ayuda", "Ayuda de DNSGuard.")
    ]),
    HelpTopic(id: "trouble", title: "Solución de problemas", icon: "lifepreserver", body: [
        ("No encuentra mi servidor", "Comprueba el permiso de red local y que estés en la misma red. Prueba «Añadir IP». El servidor debe escuchar DNS en el puerto 53 para el escaneo automático."),
        ("Credenciales incorrectas", "Usa las del panel web. Pi-hole: solo contraseña. Si usas 2FA o contraseña de aplicación en Pi-hole v6, utiliza esta última."),
        ("Pi-hole v5", "No está soportado: actualiza a v6."),
        ("Un cambio falla", "Mira el mensaje en el Registro. AdGuard valida los upstreams antes de aplicarlos y rechaza los que no responden."),
        ("Privacidad", "DNSGuard solo habla con los servidores de tu LAN que eliges. No envía datos a terceros.")
    ])
]

struct HelpView: View {
    @State private var selection: String? = "start"

    var body: some View {
        NavigationSplitView {
            List(topics, selection: $selection) { t in
                Label(t.title, systemImage: t.icon).tag(t.id)
            }.navigationSplitViewColumnWidth(min: 200, ideal: 220)
        } detail: {
            if let t = topics.first(where: { $0.id == selection }) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        Text(t.title).font(.largeTitle.bold())
                        ForEach(Array(t.body.enumerated()), id: \.offset) { _, item in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(item.0).font(.headline)
                                Text(item.1).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }.padding(24).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                }
            }
        }
    }
}
