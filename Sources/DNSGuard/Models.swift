// DNSGuard — Copyright (C) 2026 Miguel Gonzalez Oreiro
// Licensed under the GNU General Public License v3.0 or later. See LICENSE.

import Foundation

enum ServerKind: String, Hashable {
    case pihole = "Pi-hole"
    case adguard = "AdGuard Home"
}

struct DNSServer: Identifiable, Hashable {
    let host: String
    let port: Int
    let https: Bool
    let kind: ServerKind
    var version: String?
    var apiVersion: Int = 0

    var id: String { "\(kind.rawValue)@\(host):\(port)" }
    var baseURL: URL { URL(string: "\(https ? "https" : "http")://\(host):\(port)")! }
}

enum Severity { case ok, info, warning, critical }

struct Finding: Identifiable {
    let id = UUID()
    let title: String
    let detail: String
    let severity: Severity
    var preselected = true
    var fixDescription: String? = nil
    var apply: (() async throws -> Void)? = nil
}

struct SummaryItem: Identifiable {
    let id = UUID()
    let label: String
    let value: String
}

struct AuditReport {
    var summary: [SummaryItem]
    var findings: [Finding]
}

enum DNSError: LocalizedError {
    case badCredentials
    case http(Int, String)
    case unsupported(String)
    case invalid(String)

    var errorDescription: String? {
        switch self {
        case .badCredentials: return "Usuario o contraseña incorrectos."
        case .http(let c, let m): return "HTTP \(c)" + (m.isEmpty ? "" : ": \(m)")
        case .unsupported(let m), .invalid(let m): return m
        }
    }
}

protocol DNSClient: AnyObject {
    func login(user: String, password: String) async throws
    func audit() async throws -> AuditReport
    /// Devuelve los datos de la copia de seguridad y su extensión.
    func backup() async throws -> (Data, String)
    func logout() async
}

// MARK: - Utilidades

func dig(_ any: Any?, _ keys: String...) -> Any? {
    var cur = any
    for k in keys { cur = (cur as? [String: Any])?[k] }
    return cur
}

func num(_ a: Any?) -> Double? { (a as? NSNumber)?.doubleValue }

func isPrivateHost(_ h: String) -> Bool {
    let s = h.lowercased()
    if s == "localhost" || s.hasPrefix("127.") || s.hasPrefix("10.") || s.hasPrefix("192.168.")
        || s.hasPrefix("169.254.") || s.hasPrefix("fc") || s.hasPrefix("fd") || s == "::1" { return true }
    if s.hasPrefix("172."), let second = s.split(separator: ".").dropFirst().first.flatMap({ Int($0) }) {
        return (16...31).contains(second)
    }
    return false
}
