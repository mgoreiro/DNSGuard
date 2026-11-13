// DNSGuard — Copyright (C) 2026 Miguel Gonzalez Oreiro
// Licensed under the GNU General Public License v3.0 or later. See LICENSE.

import Foundation

final class PiholeClient: DNSClient {
    let server: DNSServer
    private var sid: String?

    init(server: DNSServer) { self.server = server }

    private func url(_ path: String) -> URL {
        URL(string: server.baseURL.absoluteString + "/api" + path)!
    }

    @discardableResult
    private func call(_ path: String, method: String = "GET", body: Any? = nil,
                      timeout: TimeInterval = 20) async throws -> Any? {
        var h: [String: String] = [:]
        if let sid { h["sid"] = sid }
        let (d, c) = try await HTTP.send(url(path), method: method, headers: h, body: body, timeout: timeout)
        if c == 401 { throw DNSError.badCredentials }
        guard (200..<300).contains(c) else { throw DNSError.http(c, HTTP.errorMessage(d)) }
        return HTTP.json(d)
    }

    private func patch(_ cfg: [String: Any]) async throws {
        try await call("/config", method: "PATCH", body: ["config": cfg])
    }

    func login(user: String, password: String) async throws {
        guard server.apiVersion >= 6 else {
            throw DNSError.unsupported("Este Pi-hole usa la API v5 (obsoleta). Actualiza a Pi-hole v6 para poder gestionarlo desde DNSGuard.")
        }
        let (d, c) = try await HTTP.send(url("/auth"), method: "POST", body: ["password": password])
        if c == 401 || c == 403 { throw DNSError.badCredentials }
        guard c == 200 else { throw DNSError.http(c, HTTP.errorMessage(d)) }
        let j = HTTP.json(d)
        guard dig(j, "session", "valid") as? Bool == true else { throw DNSError.badCredentials }
        sid = dig(j, "session", "sid") as? String
    }

    func logout() async {
        if sid != nil { _ = try? await call("/auth", method: "DELETE") }
        sid = nil
    }

    func backup() async throws -> (Data, String) {
        var h: [String: String] = [:]
        if let sid { h["sid"] = sid }
        if let (d, c) = try? await HTTP.send(url("/teleporter"), headers: h, timeout: 60), c == 200, d.count > 4 {
            if d.starts(with: [0x50, 0x4B]) { return (d, "zip") }
            if d.starts(with: [0x1F, 0x8B]) { return (d, "tar.gz") }
        }
        let cfg = try await call("/config")
        return (try JSONSerialization.data(withJSONObject: cfg ?? [:], options: [.prettyPrinted]), "json")
    }

    // MARK: Auditoría

    private static let recommendedLists: [(name: String, url: String)] = [
        ("HaGeZi Pro", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt")
    ]

    func audit(bench: BenchContext?) async throws -> AuditReport {
        let cfg = dig(try await call("/config"), "config")
        let verAny = try? await call("/info/version")
        let blockAny = try? await call("/dns/blocking")
        let listsAny = try? await call("/lists")
        let statsAny = try? await call("/stats/summary")

        let version = (dig(verAny, "version", "core", "local", "version") as? String) ?? "6.x"
        let blocking = dig(blockAny, "blocking") as? String
        let lists = (dig(listsAny, "lists") as? [[String: Any]]) ?? []
        let enabledBlock = lists.filter { ($0["enabled"] as? Bool) == true && (($0["type"] as? String) ?? "block") == "block" }
        let domains = num(dig(statsAny, "gravity", "domains_being_blocked"))
        let lastUpdate = num(dig(statsAny, "gravity", "last_update"))
        let total = num(dig(statsAny, "queries", "total"))
        let blocked = num(dig(statsAny, "queries", "blocked"))
        let pct = num(dig(statsAny, "queries", "percent_blocked"))
        let upstreams = (dig(cfg, "dns", "upstreams") as? [String]) ?? []
        let preferred = bench?.preferredPlain ?? ["9.9.9.9", "149.112.112.112"]
        let preferredText = preferred.joined(separator: ", ")

        var summary: [SummaryItem] = [
            .init(label: "Versión", value: version),
            .init(label: "Bloqueo", value: blocking ?? "desconocido"),
            .init(label: "Listas activas", value: "\(enabledBlock.count) de \(lists.count)"),
            .init(label: "Dominios bloqueados", value: domains.map { String(Int($0)) } ?? "—"),
            .init(label: "Consultas", value: total.map { String(Int($0)) } ?? "—"),
            .init(label: "Bloqueadas", value: (blocked.map { String(Int($0)) } ?? "—") + (pct.map { String(format: " (%.1f%%)", $0) } ?? "")),
            .init(label: "Upstreams", value: upstreams.isEmpty ? "—" : upstreams.joined(separator: ", "))
        ]
        if let mode = dig(cfg, "dns", "listeningMode") as? String { summary.append(.init(label: "Escucha", value: mode)) }

        var f: [Finding] = []

        // 1. Bloqueo activo
        if let b = blocking, b != "enabled" {
            f.append(Finding(title: "El bloqueo está desactivado", detail: "Pi-hole no está filtrando ninguna consulta.",
                             severity: .critical, fixDescription: "Activar el bloqueo",
                             apply: { [self] in try await call("/dns/blocking", method: "POST", body: ["blocking": true]) }))
        } else if blocking != nil {
            f.append(Finding(title: "Bloqueo activo", detail: "Pi-hole está filtrando consultas.", severity: .ok))
        }

        // 2. Listas de bloqueo
        if enabledBlock.isEmpty {
            let missing = Self.recommendedLists
            f.append(Finding(title: "No hay listas de bloqueo activas",
                             detail: "Sin listas, Pi-hole no bloquea nada.", severity: .critical,
                             fixDescription: "Añadir \(missing.map(\.name).joined(separator: ", ")) y actualizar gravity",
                             apply: { [self] in
                                 for l in missing {
                                     try await call("/lists?type=block", method: "POST",
                                                    body: ["address": l.url, "comment": "\(l.name) · añadida por DNSGuard", "enabled": true])
                                 }
                                 try await call("/action/gravity", method: "POST", timeout: 600)
                             }))
        } else if enabledBlock.count < 2 {
            let addresses = Set(lists.compactMap { $0["address"] as? String })
            let missing = Self.recommendedLists.filter { !addresses.contains($0.url) }
            if !missing.isEmpty {
                f.append(Finding(title: "Solo hay una lista de bloqueo",
                                 detail: "Una lista adicional mantenida activamente (p. ej. HaGeZi Pro) mejora la cobertura con pocos falsos positivos.",
                                 severity: .info, fixDescription: "Añadir \(missing.map(\.name).joined(separator: ", ")) y actualizar gravity",
                                 apply: { [self] in
                                     for l in missing {
                                         try await call("/lists?type=block", method: "POST",
                                                        body: ["address": l.url, "comment": "\(l.name) · añadida por DNSGuard", "enabled": true])
                                     }
                                     try await call("/action/gravity", method: "POST", timeout: 600)
                                 }))
            }
        } else {
            f.append(Finding(title: "\(enabledBlock.count) listas de bloqueo activas", detail: "Cobertura adecuada.", severity: .ok))
        }

        // 3. Antigüedad de gravity
        if let lu = lastUpdate, lu > 0 {
            let days = Int((Date().timeIntervalSince1970 - lu) / 86400)
            if days >= 14 {
                f.append(Finding(title: "Listas sin actualizar hace \(days) días",
                                 detail: "Gravity debería actualizarse al menos cada semana.", severity: .warning,
                                 fixDescription: "Actualizar gravity ahora",
                                 apply: { [self] in try await call("/action/gravity", method: "POST", timeout: 600) }))
            } else {
                f.append(Finding(title: "Listas actualizadas hace \(days) día(s)", detail: "", severity: .ok))
            }
        }

        // 4. Upstreams
        if upstreams.isEmpty {
            f.append(Finding(title: "No hay servidores DNS upstream", detail: "Pi-hole no podrá resolver nada.", severity: .critical,
                             fixDescription: "Usar \(preferredText)",
                             apply: { [self] in try await patch(["dns": ["upstreams": preferred]]) }))
        } else {
            let hostOf: (String) -> String = { $0.split(separator: "#").first.map(String.init) ?? $0 }
            let usesLocalResolver = upstreams.contains { hostOf($0).hasPrefix("127.") || hostOf($0) == "::1" }
            let allPrivate = upstreams.allSatisfy { isPrivateHost(hostOf($0)) }
            if usesLocalResolver {
                f.append(Finding(title: "Upstream local (unbound/cloudflared)", detail: "Resolución recursiva o cifrada local: no se toca.", severity: .ok))
            } else if allPrivate {
                f.append(Finding(title: "Upstream = router/ISP", detail: "Todos los upstreams son direcciones privadas (\(upstreams.joined(separator: ", "))). Normalmente el router reenvía al DNS del operador, con peor privacidad y sin DNSSEC. Cámbialo solo si no dependes de nombres locales del router.",
                                 severity: .warning, preselected: false,
                                 fixDescription: "Usar \(preferredText)",
                                 apply: { [self] in try await patch(["dns": ["upstreams": preferred]]) }))
            } else if upstreams.count < 2 {
                let extra = upstreams.contains(where: { $0.hasPrefix("9.9.9.9") }) ? "149.112.112.112" : "9.9.9.9"
                f.append(Finding(title: "Un único upstream", detail: "Si cae, se pierde la resolución. Añade uno de respaldo.",
                                 severity: .warning, fixDescription: "Añadir \(extra) como upstream secundario",
                                 apply: { [self] in try await patch(["dns": ["upstreams": upstreams + [extra]]]) }))
            } else {
                if let b = bench, b.slowerThanPublic, let u = b.uncachedMs, let best = b.bestRef {
                    f.append(Finding(title: "Upstreams lentos (\(String(format: "%.0f", u)) ms sin caché)",
                                     detail: "Medición: \(best.name) responde en \(String(format: "%.0f", best.ms)) ms desde tu Mac. Se proponen los dos DNS públicos más rápidos medidos (\(b.fastestNames)). Usan DNS sin cifrar; para cifrado usa cloudflared/unbound.",
                                     severity: .warning, preselected: upstreams.allSatisfy { !isPrivateHost($0.split(separator: "#").first.map(String.init) ?? $0) },
                                     fixDescription: "Usar \(preferredText) como upstreams",
                                     apply: { [self] in try await patch(["dns": ["upstreams": preferred]]) }))
                } else {
                    f.append(Finding(title: "Upstreams redundantes", detail: upstreams.joined(separator: ", "), severity: .ok))
                }
            }
        }

        // 5. DNSSEC
        if let dnssec = dig(cfg, "dns", "dnssec") as? Bool {
            if dnssec {
                f.append(Finding(title: "DNSSEC activado", detail: "", severity: .ok))
            } else {
                f.append(Finding(title: "DNSSEC desactivado",
                                 detail: "Valida firmas de dominios. Requiere upstreams compatibles (Quad9, Cloudflare, Google) y puede romper la resolución si no lo son, por eso es opcional.",
                                 severity: .info, preselected: false, fixDescription: "Activar DNSSEC",
                                 apply: { [self] in try await patch(["dns": ["dnssec": true]]) }))
            }
        }

        // 6. Caché
        if let size = num(dig(cfg, "dns", "cache", "size")) {
            if size < 10000 {
                f.append(Finding(title: "Caché DNS pequeña (\(Int(size)) entradas)", detail: "El valor por defecto es 10000.",
                                 severity: .warning, fixDescription: "Subir la caché a 10000 entradas",
                                 apply: { [self] in try await patch(["dns": ["cache": ["size": 10000]]]) }))
            } else {
                f.append(Finding(title: "Caché DNS: \(Int(size)) entradas", detail: "", severity: .ok))
            }
        }

        // 7. Fugas de consultas privadas
        if let dn = dig(cfg, "dns", "domainNeeded") as? Bool, !dn {
            f.append(Finding(title: "Se reenvían nombres sin dominio al upstream",
                             detail: "Con «domainNeeded» activo, consultas como «impresora» no salen a Internet.",
                             severity: .info, fixDescription: "Activar domainNeeded",
                             apply: { [self] in try await patch(["dns": ["domainNeeded": true]]) }))
        }
        if let bp = dig(cfg, "dns", "bogusPriv") as? Bool, !bp {
            f.append(Finding(title: "Búsquedas inversas privadas salen a Internet",
                             detail: "Con «bogusPriv» activo, los PTR de 192.168.x.x/10.x.x.x no se reenvían.",
                             severity: .info, fixDescription: "Activar bogusPriv",
                             apply: { [self] in try await patch(["dns": ["bogusPriv": true]]) }))
        }

        // 8. Rate limit
        if let rl = num(dig(cfg, "dns", "rateLimit", "count")) {
            if rl == 0 {
                f.append(Finding(title: "Sin límite de consultas por cliente",
                                 detail: "Un cliente defectuoso o malicioso puede saturar el servidor.", severity: .warning,
                                 fixDescription: "Limitar a 1000 consultas / 60 s por cliente",
                                 apply: { [self] in try await patch(["dns": ["rateLimit": ["count": 1000, "interval": 60]]]) }))
            }
        }

        // 9. Interfaz expuesta
        if let mode = dig(cfg, "dns", "listeningMode") as? String, mode == "ALL" {
            f.append(Finding(title: "Pi-hole acepta consultas desde cualquier interfaz",
                             detail: "Modo «ALL»: si el puerto 53 está expuesto a Internet se puede abusar como resolvedor abierto. Revisa el firewall o usa «LOCAL» (no se cambia automáticamente: puede romper redes Docker/VLAN).",
                             severity: .warning))
        }

        // 10. Registro de consultas
        if let ql = dig(cfg, "dns", "queryLogging") as? Bool, !ql {
            f.append(Finding(title: "Registro de consultas desactivado", detail: "Mejor privacidad, pero no tendrás estadísticas detalladas.", severity: .info))
        }

        // Latencia hasta el servidor (según la prueba de rendimiento)
        if let c = bench?.cachedMs, c > 10 {
            f.append(Finding(title: "Latencia alta hasta Pi-hole (\(String(format: "%.0f", c)) ms en caché)",
                             detail: "En una LAN suele ser < 5 ms. Suele deberse al Wi-Fi: conecta por cable (el servidor y, si puedes, este equipo) o acerca el punto de acceso. No se puede arreglar desde la configuración del servidor.",
                             severity: .info))
        }

        return AuditReport(summary: summary, findings: f)
    }
}
