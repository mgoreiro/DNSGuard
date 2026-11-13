// DNSGuard — Copyright (C) 2026 Miguel Gonzalez Oreiro
// Licensed under the GNU General Public License v3.0 or later. See LICENSE.

import Foundation
import Darwin

/// Cliente DNS mínimo sobre UDP (solo registros A) para medir latencias.
enum DNSProbe {
    struct Reply { let ms: Double; let rcode: Int; let answers: Int; let firstA: String? }

    static func resolveIPv4(_ host: String) -> in_addr? {
        var a = in_addr()
        if inet_pton(AF_INET, host, &a) == 1 { return a }
        var hints = addrinfo(); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let r = res else { return nil }
        defer { freeaddrinfo(res) }
        return r.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
    }

    static func ipString(_ a: in_addr) -> String {
        var a = a; var buf = [CChar](repeating: 0, count: 16)
        inet_ntop(AF_INET, &a, &buf, 16)
        return String(cString: buf)
    }

    private static func packet(id: UInt16, name: String) -> [UInt8] {
        var p: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") { p.append(UInt8(label.utf8.count)); p += Array(label.utf8) }
        p += [0, 0, 1, 0, 1]
        return p
    }

    /// Bloqueante: llamar desde un hilo en segundo plano.
    static func query(_ addr: in_addr, name: String, timeout: Double = 2.0) -> Reply? {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var sa = sockaddr_in()
        sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port = UInt16(53).bigEndian
        sa.sin_addr = addr
        let pkt = packet(id: UInt16.random(in: 0...UInt16.max), name: name)
        var tv = timeval(tv_sec: Int(timeout), tv_usec: Int32((timeout - timeout.rounded(.down)) * 1_000_000))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let start = DispatchTime.now().uptimeNanoseconds
        let sent = withUnsafePointer(to: &sa) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                sendto(fd, pkt, pkt.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard sent == pkt.count else { return nil }
        var buf = [UInt8](repeating: 0, count: 1500)
        while true {
            let n = recv(fd, &buf, buf.count, 0)
            if n < 12 { return nil }
            if buf[0] == pkt[0] && buf[1] == pkt[1] {
                let ms = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
                return parse(buf, n, ms)
            }
        }
    }

    private static func skipName(_ b: [UInt8], _ o: Int, _ n: Int) -> Int? {
        var o = o
        while o < n {
            let l = Int(b[o])
            if l == 0 { return o + 1 }
            if l & 0xC0 == 0xC0 { return o + 2 }
            o += 1 + l
        }
        return nil
    }

    private static func parse(_ b: [UInt8], _ n: Int, _ ms: Double) -> Reply {
        let rcode = Int(b[3] & 0x0F)
        let qd = Int(b[4]) << 8 | Int(b[5])
        let an = Int(b[6]) << 8 | Int(b[7])
        var o = 12
        for _ in 0..<qd { guard let x = skipName(b, o, n) else { return Reply(ms: ms, rcode: rcode, answers: an, firstA: nil) }; o = x + 4 }
        var firstA: String?
        for _ in 0..<an {
            guard let x = skipName(b, o, n), x + 10 <= n else { break }
            let type = Int(b[x]) << 8 | Int(b[x + 1])
            let rdlen = Int(b[x + 8]) << 8 | Int(b[x + 9])
            if type == 1, rdlen == 4, x + 14 <= n { firstA = "\(b[x + 10]).\(b[x + 11]).\(b[x + 12]).\(b[x + 13])"; break }
            o = x + 10 + rdlen
        }
        return Reply(ms: ms, rcode: rcode, answers: an, firstA: firstA)
    }
}

struct BenchTarget: Hashable {
    let name: String
    let host: String
    let reference: Bool
}

struct BenchResult: Identifiable {
    let id = UUID()
    let target: BenchTarget
    var unreachable = false
    var cachedMs: Double?
    var uncachedMs: Double?
    var lossPct = 0.0
    var blocked = 0
    var blockedTotal = 0
}

/// Resultado de la última prueba de rendimiento de un servidor, usado por la revisión.
struct BenchContext {
    let id = UUID()
    let cachedMs: Double?
    let uncachedMs: Double?
    let lossPct: Double
    let blocked: Int
    let refs: [(name: String, host: String, ms: Double)]

    static let doh = ["1.1.1.1": "https://cloudflare-dns.com/dns-query",
                      "8.8.8.8": "https://dns.google/dns-query",
                      "9.9.9.9": "https://dns.quad9.net/dns-query"]

    var fastest: [(name: String, host: String, ms: Double)] { refs.sorted { $0.ms < $1.ms } }
    var bestRef: (name: String, host: String, ms: Double)? { fastest.first }
    /// El servidor tarda claramente más que los DNS públicos (descontando el salto a la LAN).
    var slowerThanPublic: Bool {
        guard let u = uncachedMs, let b = bestRef else { return false }
        return u > b.ms + 30 && u > 60
    }
    var preferredPlain: [String]? { fastest.count >= 2 ? fastest.prefix(2).map(\.host) : nil }
    var preferredDoH: [String]? {
        let d = fastest.prefix(2).compactMap { Self.doh[$0.host] }
        return d.count == 2 ? d : nil
    }
    var fastestNames: String { fastest.prefix(2).map(\.name).joined(separator: " y ") }
}

enum Benchmark {
    static let references = [
        BenchTarget(name: "Cloudflare 1.1.1.1", host: "1.1.1.1", reference: true),
        BenchTarget(name: "Google 8.8.8.8", host: "8.8.8.8", reference: true),
        BenchTarget(name: "Quad9 9.9.9.9", host: "9.9.9.9", reference: true)
    ]
    private static let popular = ["google.com", "apple.com", "wikipedia.org", "github.com", "amazon.com",
                                  "youtube.com", "microsoft.com", "cloudflare.com", "netflix.com", "reddit.com"]
    private static let adDomains = ["doubleclick.net", "googleadservices.com", "adservice.google.com"]
    /// Pausa entre consultas para no activar límites de tasa (AdGuard: 20/s por cliente).
    private static let gapMicros: UInt32 = 60_000

    static func run(_ t: BenchTarget) async -> BenchResult {
        await Task.detached(priority: .userInitiated) { runSync(t) }.value
    }

    private static func median(_ v: [Double]) -> Double? {
        guard !v.isEmpty else { return nil }
        let s = v.sorted()
        return s.count % 2 == 1 ? s[s.count / 2] : (s[s.count / 2 - 1] + s[s.count / 2]) / 2
    }

    private static func runSync(_ t: BenchTarget) -> BenchResult {
        var res = BenchResult(target: t)
        guard let addr = DNSProbe.resolveIPv4(t.host) else { res.unreachable = true; return res }
        let serverIP = DNSProbe.ipString(addr)
        var sent = 0, lost = 0

        func q(_ name: String) -> DNSProbe.Reply? {
            usleep(gapMicros); sent += 1
            let r = DNSProbe.query(addr, name: name)
            if r == nil { lost += 1 }
            return r
        }

        if q("apple.com") == nil && q("apple.com") == nil { res.unreachable = true; return res }
        sent = 0; lost = 0

        for d in popular { _ = q(d) }                       // calienta la caché
        var warm: [Double] = []
        for d in popular { for _ in 0..<2 { if let r = q(d), r.rcode == 0 { warm.append(r.ms) } } }
        var cold: [Double] = []
        for d in popular {
            let rnd = String((0..<8).map { _ in "abcdefghijklmnopqrstuvwxyz0123456789".randomElement()! })
            if let r = q("dnsguard-\(rnd).\(d)") { cold.append(r.ms) }
        }
        res.blockedTotal = adDomains.count
        for d in adDomains {
            if let r = q(d), r.rcode == 3 || r.rcode == 5
                || (r.rcode == 0 && (r.answers == 0 || r.firstA == "0.0.0.0" || r.firstA == serverIP)) {
                res.blocked += 1
            }
        }
        res.cachedMs = median(warm)
        res.uncachedMs = median(cold)
        res.lossPct = sent == 0 ? 0 : Double(lost) / Double(sent) * 100
        return res
    }
}
