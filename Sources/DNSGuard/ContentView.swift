// DNSGuard — Copyright (C) 2026 Miguel Gonzalez Oreiro
// Licensed under the GNU General Public License v3.0 or later. See LICENSE.

import SwiftUI

struct ContentView: View {
    @EnvironmentObject var app: AppState
    @State private var showManual = false

    var body: some View {
        NavigationSplitView {
            SidebarView(showManual: $showManual)
                .navigationSplitViewColumnWidth(min: 240, ideal: 270)
        } detail: {
            if let id = app.selectedID, let s = app.servers.first(where: { $0.id == id }) {
                ServerDetailView(session: app.session(for: s)).id(s.id)
            } else {
                VStack(spacing: 12) {
                    Image(systemName: "network.badge.shield.half.filled").font(.system(size: 54)).foregroundStyle(.secondary)
                    Text("Busca servidores DNS en tu red").font(.title2)
                    Text("DNSGuard encuentra instancias de Pi-hole y AdGuard Home, revisa su configuración y aplica mejoras.")
                        .foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 420)
                    Button("Escanear la red") { Task { await app.scan() } }
                        .buttonStyle(.borderedProminent).disabled(app.scanning)
                }
            }
        }
        .sheet(isPresented: $showManual) { ManualAddSheet() }
        .task { await app.scan() }
    }
}

struct SidebarView: View {
    @EnvironmentObject var app: AppState
    @Binding var showManual: Bool

    var body: some View {
        VStack(spacing: 0) {
            List(selection: $app.selectedID) {
                Section("Servidores") {
                    ForEach(app.servers) { s in
                        HStack {
                            Image(systemName: s.kind == .pihole ? "shield.lefthalf.filled" : "shield.checkered")
                                .foregroundStyle(s.kind == .pihole ? .red : .green)
                            VStack(alignment: .leading) {
                                Text(s.kind.rawValue)
                                Text("\(s.host):\(s.port)").font(.caption).foregroundStyle(.secondary)
                            }
                        }.tag(s.id)
                    }
                    if app.servers.isEmpty && !app.scanning {
                        Text(app.scanMessage ?? "Sin resultados").font(.callout).foregroundStyle(.secondary)
                    }
                }
            }
            Divider()
            VStack(alignment: .leading, spacing: 8) {
                if app.scanning {
                    ProgressView(value: app.progress)
                    Text(app.scanStatus).font(.caption).foregroundStyle(.secondary)
                }
                HStack {
                    Button { Task { await app.scan() } } label: { Label("Escanear", systemImage: "dot.radiowaves.left.and.right") }
                        .disabled(app.scanning)
                    Spacer()
                    Button { showManual = true } label: { Label("Añadir IP", systemImage: "plus") }
                }
            }.padding(10)
        }
    }
}

struct ManualAddSheet: View {
    @EnvironmentObject var app: AppState
    @Environment(\.dismiss) var dismiss
    @State private var host = ""
    @State private var busy = false
    @State private var failed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Añadir servidor manualmente").font(.headline)
            Text("IP o nombre, con puerto opcional (p. ej. 192.168.1.2 o 192.168.1.2:3000).").font(.callout).foregroundStyle(.secondary)
            TextField("192.168.1.2", text: $host).textFieldStyle(.roundedBorder)
            if failed { Text("No se detectó Pi-hole ni AdGuard Home en esa dirección.").foregroundStyle(.red).font(.callout) }
            HStack {
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction)
                Button {
                    busy = true; failed = false
                    Task {
                        let ok = await app.addManual(host)
                        busy = false
                        if ok { dismiss() } else { failed = true }
                    }
                } label: { busy ? AnyView(ProgressView().controlSize(.small)) : AnyView(Text("Buscar")) }
                .keyboardShortcut(.defaultAction).disabled(host.isEmpty || busy)
            }
        }.padding(20).frame(width: 400)
    }
}
