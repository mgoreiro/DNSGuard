// DNSGuard — Copyright (C) 2026 Miguel Gonzalez Oreiro
// Licensed under the GNU General Public License v3.0 or later. See LICENSE.

import Foundation

final class AdGuardClient: DNSClient {
    let server: DNSServer
    private var authHeader: String?

    init(server: DNSServer) { self.server = server }

    private func url(_ path: String) -> URL {
        URL(string: server.baseURL.absoluteString + "/control" + path)!
    }

    @discardableResult
    private func call(_ path: String, method: String = "GET", body: Any? = nil,
                      timeout: TimeInterval = 30) async throws -> Any? {
        var h: [String: String] = [:]
        if let authHeader { h["Authorization"] = authHeader }
        let (d, c) = try await HTTP.send(url(path), method: method, headers: h, body: body, timeout: timeout)
        if c == 401 || c == 403 { throw DNSError.badCredentials }
        guard (200..<300).contains(c) else { throw DNSError.http(c, HTTP.errorMessage(d)) }
        return HTTP.json(d)
    }

    func login(user: String, password: String) async throws {
        authHeader = "Basic " + Data("\(user):\(password)".utf8).base64EncodedString()
        do { try await call("/status") } catch { authHeader = nil; throw error }
    }

    func logout() async { authHeader = nil }

    func backup() async throws -> (Data, String) {
        var bundle: [String: Any] = [:]
        for (key, path) in [("status", "/status"), ("dns_info", "/dns_info"), ("filtering", "/filtering/status"),
                            ("access", "/access/list"), ("safebrowsing", "/safebrowsing/status"),
                            ("parental", "/parental/status"), ("safesearch", "/safesearch/status"),
                            ("clients", "/clients"), ("rewrites", "/rewrite/list"), ("dhcp", "/dhcp/status")] {
            if let v = try? await call(path) { bundle[key] = v }
        }
        return (try JSONSerialization.data(withJSONObject: bundle, options: [.prettyPrinted, .sortedKeys]), "json")
    }

    // MARK: Auditoría

    private static let recommendedFilters: [(name: String, url: String)] = [
        ("AdGuard DNS filter", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"),
        ("HaGeZi Pro", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt")
    ]
    private static let recommendedUpstreams = ["https://dns.quad9.net/dns-query", "https://cloudflare-dns.com/dns-query"]
    private static let recommendedBootstrap = ["9.9.9.10", "149.112.112.10"]

    private func upstreamHost(_ u: String) -> String {
        var s = u
        if s.hasPrefix("[/"), let r = s.range(of: "/]") { s = String(s[r.upperBound...]) }
        if let r = s.range(of: "://") { s = String(s[r.upperBound...]) }
        if let i = s.firstIndex(where: { $0 == "/" || $0 == "#" }) { s = String(s[..<i]) }
        if let c = s.lastIndex(of: ":"), s.filter({ $0 == ":" }).count == 1 { s = String(s[..<c]) }
        return s
    }

    private func isEncrypted(_ u: String) -> Bool {
        ["https://", "tls://", "quic://", "h3://", "sdns://"].contains { u.hasPrefix($0) }
    }

    func audit(bench: BenchContext?) async throws -> AuditReport {
        let status = try await call("/status")
        let dns = (try await call("/dns_info")) as? [String: Any] ?? [:]
        let filt = try? await call("/filtering/status")
        let sb = try? await call("/safebrowsing/status")
        let access = try? await call("/access/list")

        let version = (dig(status, "version") as? String) ?? server.version ?? "—"
        let protection = dig(status, "protection_enabled") as? Bool ?? true
        let filters = (dig(filt, "filters") as? [[String: Any]]) ?? []
        let enabledFilters = filters.filter { ($0["enabled"] as? Bool) == true }
        let rules = enabledFilters.reduce(0) { $0 + Int(num($1["rules_count"]) ?? 0) }
        let upstreams = (dns["upstream_dns"] as? [String]) ?? []
        let bootstrap = (dns["bootstrap_dns"] as? [String]) ?? []
        let cache = Int(num(dns["cache_size"]) ?? 0)
        let preferred = bench?.preferredDoH ?? Self.recommendedUpstreams

        let summary: [SummaryItem] = [
            .init(label: "Versión", value: version),
            .init(label: "Protección", value: protection ? "activa" : "desactivada"),
            .init(label: "Filtros activos", value: "\(enabledFilters.count) de \(filters.count)"),
            .init(label: "Reglas", value: "\(rules)"),
            .init(label: "Upstreams", value: upstreams.isEmpty ? "—" : upstreams.joined(separator: ", ")),
            .init(label: "Modo upstream", value: (dns["upstream_mode"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "load_balance"),
            .init(label: "Caché", value: "\(cache / 1024) KiB")
        ]

        var f: [Finding] = []

        // 1. Protección
        if !protection {
            f.append(Finding(title: "La protección está desactivada", detail: "AdGuard Home no filtra ninguna consulta.",
                             severity: .critical, fixDescription: "Activar la protección",
                             apply: { [self] in try await call("/protection", method: "POST", body: ["enabled": true]) }))
        } else {
            f.append(Finding(title: "Protección activa", detail: "", severity: .ok))
        }

        // 2. Filtrado y listas
        let filteringEnabled = dig(filt, "enabled") as? Bool ?? true
        if !filteringEnabled {
            f.append(Finding(title: "El filtrado por listas está desactivado", detail: "Las listas de bloqueo no se aplican.",
                             severity: .critical, fixDescription: "Activar el filtrado",
                             apply: { [self] in
                                 try await call("/filtering/config", method: "POST",
                                                body: ["enabled": true, "interval": max(1, Int(num(dig(filt, "interval")) ?? 24))])
                             }))
        }
        if enabledFilters.isEmpty {
            let toAdd = Self.recommendedFilters
            f.append(Finding(title: "No hay listas de bloqueo activas", detail: "Sin listas no se bloquea nada.", severity: .critical,
                             fixDescription: "Añadir \(toAdd.map(\.name).joined(separator: ", "))",
                             apply: { [self] in
                                 for l in toAdd {
                                     try await call("/filtering/add_url", method: "POST",
                                                    body: ["name": l.name, "url": l.url, "whitelist": false])
                                 }
                             }))
        } else if enabledFilters.count < 2 {
            let urls = Set(filters.compactMap { $0["url"] as? String })
            let toAdd = Self.recommendedFilters.filter { !urls.contains($0.url) }.prefix(1)
            if !toAdd.isEmpty {
                f.append(Finding(title: "Solo hay una lista de bloqueo", detail: "Una lista adicional mantenida (HaGeZi Pro) amplía la cobertura.",
                                 severity: .info, fixDescription: "Añadir \(toAdd.map(\.name).joined(separator: ", "))",
                                 apply: { [self] in
                                     for l in toAdd {
                                         try await call("/filtering/add_url", method: "POST",
                                                        body: ["name": l.name, "url": l.url, "whitelist": false])
                                     }
                                 }))
            }
        } else {
            f.append(Finding(title: "\(enabledFilters.count) listas de bloqueo activas (\(rules) reglas)", detail: "", severity: .ok))
        }

        // 3. Intervalo de actualización
        if filteringEnabled, let interval = num(dig(filt, "interval")) {
            if interval == 0 || interval > 72 {
                f.append(Finding(title: "Actualización de listas \(interval == 0 ? "desactivada" : "cada \(Int(interval)) h")",
                                 detail: "Se recomienda refrescar las listas cada 24 h.", severity: .warning,
                                 fixDescription: "Actualizar listas cada 24 h",
                                 apply: { [self] in try await call("/filtering/config", method: "POST", body: ["enabled": true, "interval": 24]) }))
            }
        }

        // 4. Upstreams cifrados
        let rulesOnly = upstreams.filter { $0.hasPrefix("[/") }
        let general = upstreams.filter { !$0.hasPrefix("[/") }
        let encrypted = general.filter(isEncrypted)
        let plain = general.filter { !isEncrypted($0) }
        let plainPublic = plain.filter { !isPrivateHost(upstreamHost($0)) }
        let plainPrivate = plain.filter { isPrivateHost(upstreamHost($0)) }

        if upstreams.isEmpty {
            f.append(Finding(title: "No hay upstreams configurados", detail: "AdGuard Home no podrá resolver nada.", severity: .critical,
                             fixDescription: "Usar Quad9 y Cloudflare por DoH",
                             apply: { [self] in
                                 try await call("/dns_config", method: "POST",
                                                body: ["upstream_dns": preferred, "bootstrap_dns": Self.recommendedBootstrap])
                             }))
        } else if !plainPublic.isEmpty {
            let newUpstreams = rulesOnly + encrypted + (encrypted.isEmpty ? preferred : []) + plainPrivate
            let needsBootstrap = bootstrap.isEmpty
            f.append(Finding(title: "DNS upstream sin cifrar",
                             detail: "\(plainPublic.joined(separator: ", ")) viaja en claro: tu operador y cualquiera en la ruta ve cada dominio que consultas.",
                             severity: .warning, preselected: plainPrivate.isEmpty,
                             fixDescription: "Sustituir por DoH (Quad9 + Cloudflare)" + (plainPrivate.isEmpty ? "" : " conservando \(plainPrivate.joined(separator: ", "))"),
                             apply: { [self] in
                                 var body: [String: Any] = ["upstream_dns": newUpstreams]
                                 if needsBootstrap { body["bootstrap_dns"] = Self.recommendedBootstrap }
                                 try await call("/dns_config", method: "POST", body: body)
                             }))
        } else if !plainPrivate.isEmpty && encrypted.isEmpty {
            f.append(Finding(title: "Upstream = router/ISP",
                             detail: "Los upstreams son direcciones privadas (\(plainPrivate.joined(separator: ", "))): el DNS sale sin cifrar a través del router.",
                             severity: .warning, preselected: false, fixDescription: "Usar Quad9 y Cloudflare por DoH",
                             apply: { [self] in
                                 try await call("/dns_config", method: "POST",
                                                body: ["upstream_dns": rulesOnly + preferred,
                                                       "bootstrap_dns": bootstrap.isEmpty ? Self.recommendedBootstrap : bootstrap])
                             }))
        } else {
            if let b = bench, b.slowerThanPublic, let u = b.uncachedMs, let best = b.bestRef {
                let newUp = rulesOnly + preferred + plainPrivate
                f.append(Finding(title: "Upstreams lentos (\(String(format: "%.0f", u)) ms sin caché)",
                                 detail: "Medición: \(best.name) responde en \(String(format: "%.0f", best.ms)) ms desde tu Mac. Se proponen los dos DNS más rápidos medidos (\(b.fastestNames)) por DoH, en modo paralelo.",
                                 severity: .warning, preselected: plainPrivate.isEmpty,
                                 fixDescription: "Usar \(b.fastestNames) por DoH + modo paralelo",
                                 apply: { [self] in
                                     var body: [String: Any] = ["upstream_dns": newUp, "upstream_mode": "parallel"]
                                     if bootstrap.isEmpty { body["bootstrap_dns"] = Self.recommendedBootstrap }
                                     try await call("/dns_config", method: "POST", body: body)
                                 }))
            } else {
                f.append(Finding(title: "Upstreams cifrados", detail: encrypted.joined(separator: ", "), severity: .ok))
            }
        }

        // 5. Modo paralelo
        let mode = (dns["upstream_mode"] as? String) ?? ""
        if general.count > 1 && mode != "parallel" {
            f.append(Finding(title: "Modo de upstream: \(mode.isEmpty ? "load_balance" : mode)",
                             detail: "En modo paralelo se consulta a todos a la vez y gana el más rápido: menor latencia.",
                             severity: .info, fixDescription: "Cambiar a consultas en paralelo",
                             apply: { [self] in try await call("/dns_config", method: "POST", body: ["upstream_mode": "parallel"]) }))
        }

        // 6. Caché
        if cache < 16_777_216 {
            f.append(Finding(title: "Caché DNS pequeña (\(cache / 1024) KiB)",
                             detail: "Más caché = más respuestas inmediatas sin consultar al upstream. 16 MiB cubre de sobra una red doméstica y ocupa poca memoria.",
                             severity: cache < 4_194_304 ? .warning : .info, fixDescription: "Subir la caché a 16 MiB",
                             apply: { [self] in try await call("/dns_config", method: "POST", body: ["cache_size": 16_777_216]) }))
        }
        let ttlMin = Int(num(dns["cache_ttl_min"]) ?? 0)
        if ttlMin == 0 {
            f.append(Finding(title: "Sin TTL mínimo en la caché",
                             detail: "Muchos dominios publican TTL de 30–60 s, lo que fuerza consultas continuas al upstream. Un mínimo de 300 s aumenta los aciertos de caché. Efecto secundario: los cambios de IP en dominios con balanceo rápido tardan hasta 5 min en verse.",
                             severity: .info, preselected: false, fixDescription: "Fijar TTL mínimo de caché en 300 s",
                             apply: { [self] in try await call("/dns_config", method: "POST", body: ["cache_ttl_min": 300]) }))
        }
        if let opt = dns["cache_optimistic"] as? Bool, !opt {
            f.append(Finding(title: "Caché optimista desactivada",
                             detail: "Sirve respuestas caducadas al instante y las refresca en segundo plano: navegación más ágil.",
                             severity: .info, fixDescription: "Activar caché optimista",
                             apply: { [self] in try await call("/dns_config", method: "POST", body: ["cache_optimistic": true]) }))
        }

        // 7. DNSSEC
        if let dnssec = dns["dnssec_enabled"] as? Bool, !dnssec {
            f.append(Finding(title: "DNSSEC desactivado",
                             detail: "Valida la autenticidad de las respuestas. Algunos upstreams/redes lo rompen, por eso es opcional.",
                             severity: .info, preselected: false, fixDescription: "Activar DNSSEC",
                             apply: { [self] in try await call("/dns_config", method: "POST", body: ["dnssec_enabled": true]) }))
        }

        // 8. Rate limit
        if let rl = num(dns["ratelimit"]), rl == 0 {
            f.append(Finding(title: "Sin límite de consultas por cliente", detail: "Un cliente defectuoso puede saturar el servidor.",
                             severity: .warning, fixDescription: "Limitar a 20 consultas/s por cliente",
                             apply: { [self] in try await call("/dns_config", method: "POST", body: ["ratelimit": 20]) }))
        }

        // Hallazgos según la prueba de rendimiento
        if let b = bench {
            if let rl = num(dns["ratelimit"]), rl > 0, rl < 100, b.lossPct > 2 {
                f.append(Finding(title: "Pérdida de consultas (\(String(format: "%.0f", b.lossPct))%) con límite de \(Int(rl))/s",
                                 detail: "El límite de tasa por cliente puede estar descartando consultas legítimas.",
                                 severity: .warning, fixDescription: "Subir el límite a 100 consultas/s por cliente",
                                 apply: { [self] in try await call("/dns_config", method: "POST", body: ["ratelimit": 100]) }))
            }
            if let c = b.cachedMs, c > 10 {
                f.append(Finding(title: "Latencia alta hasta AdGuard (\(String(format: "%.0f", c)) ms en caché)",
                                 detail: "En una LAN suele ser < 5 ms. Suele deberse al Wi-Fi: conecta por cable (el servidor y, si puedes, este equipo) o acerca el punto de acceso. No se puede arreglar desde la configuración del servidor.",
                                 severity: .info))
            }
        }

        // 9. Navegación segura
        if let enabled = dig(sb, "enabled") as? Bool, !enabled {
            f.append(Finding(title: "Navegación segura desactivada",
                             detail: "Bloquea phishing/malware conocido, pero envía prefijos de hash de los dominios a AdGuard (compromiso de privacidad).",
                             severity: .info, preselected: false, fixDescription: "Activar navegación segura",
                             apply: { [self] in try await call("/safebrowsing/enable", method: "POST") }))
        }

        // 10. Control de acceso
        let allowed = (dig(access, "allowed_clients") as? [String]) ?? []
        if allowed.isEmpty {
            f.append(Finding(title: "Sin lista de clientes permitidos",
                             detail: "Cualquier dispositivo que alcance el puerto 53 puede usar este servidor. Si no está expuesto fuera de tu LAN no es grave; restringirlo requiere conocer tus subredes, así que no se cambia automáticamente.",
                             severity: .info))
        }

        return AuditReport(summary: summary, findings: f)
    }
}
