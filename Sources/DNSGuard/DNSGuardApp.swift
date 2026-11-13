// DNSGuard — Copyright (C) 2026 Miguel Gonzalez Oreiro
// Licensed under the GNU General Public License v3.0 or later. See LICENSE.

import SwiftUI

@main
struct DNSGuardApp: App {
    @StateObject private var app = AppState()

    var body: some Scene {
        WindowGroup("DNSGuard") {
            ContentView()
                .environmentObject(app)
                .frame(minWidth: 920, minHeight: 600)
                .onAppear { NSApp.activate(ignoringOtherApps: true) }
        }
        .commands { HelpCommands(); ScanCommands(app: app) }

        Window("Ayuda de DNSGuard", id: "help") {
            HelpView().frame(minWidth: 760, minHeight: 520)
        }
    }
}

struct HelpCommands: Commands {
    @Environment(\.openWindow) private var openWindow
    var body: some Commands {
        CommandGroup(replacing: .help) {
            Button("Ayuda de DNSGuard") { openWindow(id: "help") }.keyboardShortcut("?", modifiers: .command)
        }
    }
}

struct ScanCommands: Commands {
    let app: AppState
    var body: some Commands {
        CommandGroup(after: .newItem) {
            Button("Escanear la red") { Task { await app.scan() } }.keyboardShortcut("r", modifiers: .command)
            Button("Abrir carpeta de copias de seguridad") {
                let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                    .appendingPathComponent("DNSGuard/backups", isDirectory: true)
                try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                NSWorkspace.shared.open(dir)
            }
        }
    }
}
