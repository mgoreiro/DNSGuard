// DNSGuard — Copyright (C) 2026 Miguel Gonzalez Oreiro
// Licensed under the GNU General Public License v3.0 or later. See LICENSE.

import Foundation
import SwiftUI

@MainActor
final class AppState: ObservableObject {
    @Published var servers: [DNSServer] = []
    @Published var scanning = false
    @Published var progress = 0.0
    @Published var scanStatus = ""
    @Published var selectedID: String?
    @Published var scanMessage: String?
    private var sessions: [String: ServerSession] = [:]

    func session(for s: DNSServer) -> ServerSession {
        if let x = sessions[s.id] { return x }
        let n = ServerSession(server: s)
        sessions[s.id] = n
        return n
    }

    func scan() async {
        guard !scanning else { return }
        scanning = true; progress = 0; scanMessage = nil
        let found = await NetworkScanner.scan { [weak self] p, msg in
            Task { @MainActor in self?.progress = p; self?.scanStatus = msg }
        }
        merge(found)
        scanning = false
        scanMessage = found.isEmpty ? "No se encontró ningún Pi-hole ni AdGuard Home. Puedes añadir uno manualmente por IP." : nil
    }

    func addManual(_ text: String) async -> Bool {
        let found = await NetworkScanner.probe(host: text)
        merge(found)
        if let first = found.first { selectedID = first.id }
        return !found.isEmpty
    }

    private func merge(_ found: [DNSServer]) {
        for s in found where !servers.contains(where: { $0.id == s.id }) { servers.append(s) }
        servers.sort { ($0.host, $0.kind.rawValue) < ($1.host, $1.kind.rawValue) }
    }
}

@MainActor
final class ServerSession: ObservableObject {
    enum Phase { case disconnected, connecting, analyzing, ready, applying }

    let server: DNSServer
    @Published var phase = Phase.disconnected
    @Published var report: AuditReport?
    @Published var selected = Set<UUID>()
    @Published var error: String?
    @Published var log: [String] = []
    @Published var lastBackup: URL?
    private var client: DNSClient?

    init(server: DNSServer) { self.server = server }

    var savedUser: String {
        UserDefaults.standard.string(forKey: "user.\(server.id)") ?? (server.kind == .adguard ? "admin" : "")
    }
    var savedPassword: String? { Keychain.load(account: server.id) }

    private func makeClient() -> DNSClient {
        server.kind == .pihole ? PiholeClient(server: server) : AdGuardClient(server: server)
    }

    func connect(user: String, password: String, remember: Bool) async {
        error = nil; phase = .connecting
        let c = makeClient()
        do {
            try await c.login(user: user, password: password)
            client = c
            if remember {
                UserDefaults.standard.set(user, forKey: "user.\(server.id)")
                Keychain.save(password, account: server.id)
            } else {
                Keychain.delete(account: server.id)
            }
            addLog("Conectado a \(server.kind.rawValue) en \(server.host)")
            await analyze()
        } catch {
            self.error = error.localizedDescription
            phase = .disconnected
        }
    }

    func analyze() async {
        guard let client else { return }
        phase = .analyzing; error = nil
        do {
            let r = try await client.audit()
            report = r
            selected = Set(r.findings.filter { $0.apply != nil && $0.preselected }.map(\.id))
            phase = .ready
        } catch {
            self.error = error.localizedDescription
            phase = report == nil ? .disconnected : .ready
        }
    }

    func applySelected() async {
        guard let client, let report else { return }
        let todo = report.findings.filter { selected.contains($0.id) && $0.apply != nil }
        guard !todo.isEmpty else { return }
        phase = .applying; error = nil
        do {
            let (data, ext) = try await client.backup()
            let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("DNSGuard/backups", isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
            let file = dir.appendingPathComponent("\(server.kind.rawValue.replacingOccurrences(of: " ", with: ""))-\(server.host)-\(stamp).\(ext)")
            try data.write(to: file)
            lastBackup = file
            addLog("Copia de seguridad guardada: \(file.lastPathComponent)")
        } catch {
            self.error = "No se aplicó nada: falló la copia de seguridad (\(error.localizedDescription))."
            phase = .ready
            return
        }
        var failed = 0
        for f in todo {
            do {
                try await f.apply?()
                addLog("✓ \(f.fixDescription ?? f.title)")
            } catch {
                failed += 1
                addLog("✗ \(f.fixDescription ?? f.title): \(error.localizedDescription)")
            }
        }
        if failed > 0 { self.error = "\(failed) cambio(s) fallaron. Revisa el registro." }
        await analyze()
    }

    func disconnect() async {
        await client?.logout()
        client = nil; report = nil; selected = []; phase = .disconnected
    }

    private func addLog(_ s: String) {
        let t = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        log.append("\(t)  \(s)")
    }
}
