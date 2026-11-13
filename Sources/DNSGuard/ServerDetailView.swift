// DNSGuard — Copyright (C) 2026 Miguel Gonzalez Oreiro
// Licensed under the GNU General Public License v3.0 or later. See LICENSE.

import SwiftUI

struct ServerDetailView: View {
    @ObservedObject var session: ServerSession
    @State private var showLogin = false
    @State private var confirm = false
    @State private var showBench = false

    private var server: DNSServer { session.server }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            content
        }
        .sheet(isPresented: $showLogin) { LoginSheet(session: session) }
        .onChange(of: session.bench?.id) { _ in Task { await session.refreshIfBenchChanged() } }
        .onAppear { Task { await session.refreshIfBenchChanged() } }
        .sheet(isPresented: $showBench) { BenchmarkSheet(servers: [server]) }
        .confirmationDialog("¿Aplicar \(session.selected.count) cambio(s) a \(server.host)?",
                            isPresented: $confirm, titleVisibility: .visible) {
            Button("Aplicar") { Task { await session.applySelected() } }
            Button("Cancelar", role: .cancel) {}
        } message: {
            Text("Antes de modificar nada se guarda una copia de seguridad de la configuración actual.")
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: server.kind == .pihole ? "shield.lefthalf.filled" : "shield.checkered")
                .font(.largeTitle).foregroundStyle(server.kind == .pihole ? .red : .green)
            VStack(alignment: .leading) {
                Text(server.kind.rawValue).font(.title2.bold())
                Text(server.baseURL.absoluteString).font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            Button { showBench = true } label: { Label("Rendimiento", systemImage: "speedometer") }
            if session.phase == .ready || session.phase == .applying {
                Button("Reanalizar") { Task { await session.analyze() } }.disabled(session.phase == .applying)
                Button("Desconectar") { Task { await session.disconnect() } }.disabled(session.phase == .applying)
            }
        }.padding()
    }

    @ViewBuilder private var content: some View {
        switch session.phase {
        case .disconnected:
            VStack(spacing: 12) {
                Spacer()
                if server.kind == .pihole && server.apiVersion < 6 {
                    Label("Pi-hole v5 detectado. DNSGuard solo gestiona Pi-hole v6 o superior.", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                } else {
                    Text("Conéctate para revisar y optimizar este servidor.").foregroundStyle(.secondary)
                    Button("Conectar…") { showLogin = true }.buttonStyle(.borderedProminent).controlSize(.large)
                }
                if let e = session.error { Text(e).foregroundStyle(.red).multilineTextAlignment(.center) }
                Spacer()
            }.frame(maxWidth: .infinity).padding()
        case .connecting, .analyzing, .applying:
            VStack { Spacer(); ProgressView(label: {
                Text(session.phase == .connecting ? "Conectando…" : session.phase == .analyzing ? "Analizando configuración…" : "Aplicando cambios…")
            }); Spacer() }.frame(maxWidth: .infinity)
        case .ready:
            reportView
        }
    }

    private var reportView: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if let e = session.error { Text(e).foregroundStyle(.red) }
                if let r = session.report {
                    GroupBox("Resumen") {
                        Grid(alignment: .leading, horizontalSpacing: 20, verticalSpacing: 4) {
                            ForEach(r.summary) { item in
                                GridRow {
                                    Text(item.label).foregroundStyle(.secondary)
                                    Text(item.value).textSelection(.enabled)
                                }
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(6)
                    }

                    let actionable = r.findings.filter { $0.apply != nil }
                    HStack {
                        Text("Revisión").font(.headline)
                        Spacer()
                        Button("Optimizar (\(session.selected.count))") { confirm = true }
                            .buttonStyle(.borderedProminent).disabled(session.selected.isEmpty)
                    }
                    if actionable.isEmpty {
                        Label("No hay nada que optimizar: la configuración está en buen estado.", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                    }
                    ForEach(r.findings) { f in FindingRow(finding: f, session: session) }

                    if !session.log.isEmpty {
                        GroupBox("Registro") {
                            VStack(alignment: .leading, spacing: 2) {
                                ForEach(Array(session.log.enumerated()), id: \.offset) { _, l in
                                    Text(l).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                                }
                                if let b = session.lastBackup {
                                    Button("Mostrar última copia en Finder") { NSWorkspace.shared.activateFileViewerSelecting([b]) }
                                        .buttonStyle(.link).padding(.top, 4)
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading).padding(6)
                        }
                    }
                }
            }.padding()
        }
    }
}

struct FindingRow: View {
    let finding: Finding
    @ObservedObject var session: ServerSession

    private var icon: (String, Color) {
        switch finding.severity {
        case .ok: return ("checkmark.circle.fill", .green)
        case .info: return ("info.circle.fill", .blue)
        case .warning: return ("exclamationmark.triangle.fill", .orange)
        case .critical: return ("xmark.octagon.fill", .red)
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon.0).foregroundStyle(icon.1).frame(width: 22).padding(.top, 2)
            VStack(alignment: .leading, spacing: 3) {
                Text(finding.title).fontWeight(.medium)
                if !finding.detail.isEmpty { Text(finding.detail).font(.callout).foregroundStyle(.secondary) }
                if let fix = finding.fixDescription {
                    Label(fix, systemImage: "wand.and.stars").font(.callout)
                    if !finding.preselected { Text("Opcional: no se marca por defecto porque puede cambiar el comportamiento de tu red.").font(.caption).foregroundStyle(.orange) }
                }
            }
            Spacer()
            if finding.apply != nil {
                Toggle("", isOn: Binding(
                    get: { session.selected.contains(finding.id) },
                    set: { on in if on { session.selected.insert(finding.id) } else { session.selected.remove(finding.id) } }
                )).labelsHidden()
            }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .controlBackgroundColor)))
    }
}

struct LoginSheet: View {
    @ObservedObject var session: ServerSession
    @Environment(\.dismiss) var dismiss
    @State private var user = ""
    @State private var password = ""
    @State private var remember = true

    private var needsUser: Bool { session.server.kind == .adguard }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Conectar a \(session.server.kind.rawValue)").font(.headline)
            Text(session.server.baseURL.absoluteString).font(.callout).foregroundStyle(.secondary)
            if needsUser {
                TextField("Usuario", text: $user).textFieldStyle(.roundedBorder)
            } else {
                Text("Pi-hole solo usa contraseña (la del panel web).").font(.callout).foregroundStyle(.secondary)
            }
            SecureField("Contraseña", text: $password).textFieldStyle(.roundedBorder)
            Toggle("Recordar en el llavero de macOS", isOn: $remember)
            HStack {
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Conectar") {
                    let u = user, p = password, r = remember
                    dismiss()
                    Task { await session.connect(user: u, password: p, remember: r) }
                }.keyboardShortcut(.defaultAction).disabled(needsUser && user.isEmpty)
            }
        }
        .padding(20).frame(width: 380)
        .onAppear {
            user = session.savedUser
            password = session.savedPassword ?? ""
        }
    }
}
