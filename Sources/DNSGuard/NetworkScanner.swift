// DNSGuard — Copyright (C) 2026 Miguel Gonzalez Oreiro
// Licensed under the GNU General Public License v3.0 or later. See LICENSE.

import Foundation
import Network
import Darwin

private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false
    func fire() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if fired { return false }
        fired = true
        return true
    }
}

enum NetworkScanner {
    struct Subnet { let ip: UInt32; let mask: UInt32 }

    static func localSubnets() -> [Subnet] {
        var result: [Subnet] = []
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let first = ifap else { return [] }
        defer { freeifaddrs(ifap) }
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = p {
            let ifa = cur.pointee
            let flags = Int32(ifa.ifa_flags)
            if let addr = ifa.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET),
               flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0,
               let nm = ifa.ifa_netmask,
               String(cString: ifa.ifa_name).hasPrefix("en") {
                let ip = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
                let mask = nm.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
                if (ip >> 16) != 0xA9FE { result.append(Subnet(ip: ip, mask: mask)) }
            }
            p = ifa.ifa_next
        }
        return result
    }

    static func ipString(_ v: UInt32) -> String {
        "\(v >> 24).\((v >> 16) & 255).\((v >> 8) & 255).\(v & 255)"
    }

    static func hosts(in s: Subnet) -> [String] {
        var mask = s.mask
        if ~mask > 1023 { mask = 0xFFFF_FF00 }   // limita a /24 si la red es enorme
        let net = s.ip & mask
        let bcast = net | ~mask
        guard bcast > net + 1 else { return [] }
        return ((net + 1)..<bcast).map(ipString)
    }

    static func tcpOpen(_ host: String, _ port: UInt16, timeout: TimeInterval) async -> Bool {
        await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            let conn = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
            let once = Once()
            let finish: @Sendable (Bool) -> Void = { ok in
                if once.fire() { conn.cancel(); cont.resume(returning: ok) }
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(true)
                case .failed, .cancelled: finish(false)
                default: break
                }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finish(false) }
        }
    }

    // MARK: Escaneo

    static func scan(progress: @escaping @Sendable (Double, String) -> Void) async -> [DNSServer] {
        let all = Array(Set(localSubnets().flatMap { hosts(in: $0) })).sorted()
        guard !all.isEmpty else { return [] }

        // Fase 1: ¿quién escucha en el puerto 53?
        progress(0, "Buscando servicios DNS en \(all.count) direcciones…")
        var dnsHosts: [String] = []
        var done = 0
        await withTaskGroup(of: (String, Bool).self) { group in
            var it = all.makeIterator()
            for _ in 0..<150 { if let h = it.next() { group.addTask { (h, await tcpOpen(h, 53, timeout: 1.2)) } } }
            while let (h, ok) = await group.next() {
                done += 1
                if ok { dnsHosts.append(h) }
                if done % 8 == 0 { progress(Double(done) / Double(all.count) * 0.8, "Explorando red… \(done)/\(all.count)") }
                if let n = it.next() { group.addTask { (n, await tcpOpen(n, 53, timeout: 1.2)) } }
            }
        }

        // Fase 2: identificar Pi-hole / AdGuard en esos hosts
        progress(0.8, "Identificando \(dnsHosts.count) servidores DNS…")
        var found: [DNSServer] = []
        await withTaskGroup(of: [DNSServer].self) { group in
            for h in dnsHosts { group.addTask { await probe(host: h) } }
            for await list in group { found += list }
        }
        progress(1, "Listo")
        return found.sorted { ($0.host, $0.kind.rawValue) < ($1.host, $1.kind.rawValue) }
    }

    private static let endpoints: [(https: Bool, port: Int)] =
        [(false, 80), (false, 3000), (false, 8080), (false, 8081), (true, 443), (true, 8443)]

    /// `host` puede incluir puerto ("192.168.1.2:3000"); entonces solo se prueba ese.
    static func probe(host raw: String) async -> [DNSServer] {
        var host = raw.trimmingCharacters(in: .whitespaces)
        var eps = endpoints
        if let r = host.range(of: "://") { host = String(host[r.upperBound...]) }
        if let slash = host.firstIndex(of: "/") { host = String(host[..<slash]) }
        if let colon = host.lastIndex(of: ":"), let port = Int(host[host.index(after: colon)...]) {
            host = String(host[..<colon])
            eps = [(false, port), (true, port)]
        }
        guard !host.isEmpty else { return [] }
        let h = host
        let list = eps
        return await withTaskGroup(of: (Int, DNSServer?).self) { group in
            for (i, e) in list.enumerated() {
                group.addTask { (i, await identify(host: h, https: e.https, port: e.port)) }
            }
            var found: [(Int, DNSServer)] = []
            for await (i, s) in group { if let s { found.append((i, s)) } }
            var seen = Set<ServerKind>()
            var out: [DNSServer] = []
            for (_, s) in found.sorted(by: { $0.0 < $1.0 }) where seen.insert(s.kind).inserted { out.append(s) }
            return out
        }
    }

    static func identify(host: String, https: Bool, port: Int) async -> DNSServer? {
        guard await tcpOpen(host, UInt16(port), timeout: 1.5) else { return nil }
        let base = "\(https ? "https" : "http")://\(host):\(port)"

        func get(_ path: String) async -> (Data, Int)? {
            guard let u = URL(string: base + path) else { return nil }
            return try? await HTTP.send(u, timeout: 4)
        }

        // Pi-hole v6
        if let (d, c) = await get("/api/info/login"), c == 200 || c == 401,
           let j = HTTP.json(d) as? [String: Any], j["dns"] != nil {
            return DNSServer(host: host, port: port, https: https, kind: .pihole, version: "6.x", apiVersion: 6)
        }
        // Pi-hole v5
        if let (d, c) = await get("/admin/api.php?version"), c == 200,
           let j = HTTP.json(d) as? [String: Any], let v = j["version"] {
            return DNSServer(host: host, port: port, https: https, kind: .pihole, version: "\(v).x", apiVersion: 5)
        }
        // AdGuard Home
        if let (d, c) = await get("/control/status"), c == 200,
           let j = HTTP.json(d) as? [String: Any], j["dns_port"] != nil {
            return DNSServer(host: host, port: port, https: https, kind: .adguard,
                             version: j["version"] as? String, apiVersion: 1)
        }
        // Con autenticación activa, /control/status responde 401 (404 en cualquier otro software)
        if let (_, c) = await get("/control/status"), c == 401 {
            return DNSServer(host: host, port: port, https: https, kind: .adguard, version: nil, apiVersion: 1)
        }
        if let (d, _) = await get("/"), let s = String(data: d, encoding: .utf8), s.lowercased().contains("adguard") {
            return DNSServer(host: host, port: port, https: https, kind: .adguard, version: nil, apiVersion: 1)
        }
        return nil
    }
}
