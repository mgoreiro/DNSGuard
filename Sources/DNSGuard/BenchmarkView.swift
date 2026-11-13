// DNSGuard — Copyright (C) 2026 Miguel Gonzalez Oreiro
// Licensed under the GNU General Public License v3.0 or later. See LICENSE.

import SwiftUI

@MainActor
final class BenchmarkModel: ObservableObject {
    @Published var running = false
    @Published var results: [BenchResult] = []
    @Published var total = 0

    func run(servers: [DNSServer]) async {
        guard !running else { return }
        running = true; results = []
        let targets = servers.map { BenchTarget(name: "\($0.kind.rawValue) \($0.host)", host: $0.host, reference: false) } + Benchmark.references
        total = targets.count
        await withTaskGroup(of: BenchResult.self) { g in
            for t in targets { g.addTask { await Benchmark.run(t) } }
            for await r in g {
                results.append(r)
                results.sort { a, b in
                    let ia = targets.firstIndex(of: a.target) ?? 0, ib = targets.firstIndex(of: b.target) ?? 0
                    return ia < ib
                }
            }
        }
        running = false
    }

    var verdicts: [(Severity, String)] {
        var out: [(Severity, String)] = []
        let refs = results.filter { $0.target.reference && !$0.unreachable }
        let bestRef = refs.compactMap { r in r.uncachedMs.map { (r.target.name, $0) } }.min { $0.1 < $1.1 }
        for r in results where !r.target.reference {
            let n = r.target.name
            if r.unreachable { out.append((.critical, "\(n): no responde a consultas DNS por UDP/53.")); continue }
            if let c = r.cachedMs {
                out.append((c <= 5 ? .ok : c <= 20 ? .info : .warning,
                            "\(n): respuestas en caché en \(fmt(c)) ms" + (c <= 5 ? " (excelente)." : c <= 20 ? " (correcto)." : ": lento para una caché local; revisa el Wi-Fi o la carga del equipo.")))
            }
            if let u = r.uncachedMs {
                var s = "\(n): consultas sin caché en \(fmt(u)) ms"
                var sev: Severity = u <= 60 ? .ok : u <= 120 ? .info : .warning
                if let b = bestRef, u > b.1 + 30 {
                    s += ". Es \(fmt(u - b.1)) ms más lento que \(b.0) (\(fmt(b.1)) ms): prueba otros upstreams o el modo paralelo."
                    sev = .warning
                } else { s += "." }
                out.append((sev, s))
            }
            if r.lossPct > 2 {
                out.append((.warning, "\(n): se perdió el \(fmt(r.lossPct))% de las consultas. Puede ser red inestable o un límite de tasa del servidor."))
            }
            if r.blocked == 0 {
                out.append((.warning, "\(n): no bloquea ninguno de los \(r.blockedTotal) dominios publicitarios de prueba. Revisa listas y protección."))
            } else if r.blocked < r.blockedTotal {
                out.append((.info, "\(n): bloquea \(r.blocked) de \(r.blockedTotal) dominios publicitarios de prueba."))
            } else {
                out.append((.ok, "\(n): bloquea los \(r.blockedTotal) dominios publicitarios de prueba."))
            }
        }
        return out
    }
}

private func fmt(_ v: Double) -> String { String(format: "%.1f", v) }

struct BenchmarkSheet: View {
    let servers: [DNSServer]
    @StateObject private var model = BenchmarkModel()
    @Environment(\.dismiss) var dismiss
    @EnvironmentObject var app: AppState

    private var maxUncached: Double { max(model.results.compactMap(\.uncachedMs).max() ?? 1, 1) }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Prueba de rendimiento").font(.title2.bold())
            Text("Mide, desde este Mac, la latencia de cada servidor con consultas DNS reales y la compara con Cloudflare, Google y Quad9. No necesita credenciales.")
                .font(.callout).foregroundStyle(.secondary)

            if model.running {
                ProgressView(value: Double(model.results.count), total: Double(max(model.total, 1)))
                Text("Midiendo… \(model.results.count)/\(model.total) (≈ 5 s por servidor)").font(.caption).foregroundStyle(.secondary)
            }

            if !model.results.isEmpty {
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
                    GridRow {
                        Text("Servidor").bold(); Text("En caché").bold(); Text("Sin caché").bold()
                        Text("Pérdida").bold(); Text("Bloqueo").bold(); Text("")
                    }.font(.callout).foregroundStyle(.secondary)
                    Divider().gridCellColumns(6)
                    ForEach(model.results) { r in
                        GridRow {
                            HStack(spacing: 6) {
                                Image(systemName: r.target.reference ? "globe" : "server.rack").foregroundStyle(.secondary)
                                Text(r.target.name).fontWeight(r.target.reference ? .regular : .semibold)
                            }
                            if r.unreachable {
                                Text("sin respuesta").foregroundStyle(.red).gridCellColumns(4)
                                Text("")
                            } else {
                                Text(r.cachedMs.map { fmt($0) + " ms" } ?? "—")
                                Text(r.uncachedMs.map { fmt($0) + " ms" } ?? "—")
                                Text(fmt(r.lossPct) + "%").foregroundStyle(r.lossPct > 2 ? .orange : .primary)
                                Text("\(r.blocked)/\(r.blockedTotal)")
                                if let u = r.uncachedMs {
                                    RoundedRectangle(cornerRadius: 3)
                                        .fill(r.target.reference ? Color.gray.opacity(0.5) : Color.accentColor)
                                        .frame(width: max(4, 150 * u / maxUncached), height: 10)
                                        .frame(width: 150, alignment: .leading)
                                } else { Text("") }
                            }
                        }.font(.callout.monospacedDigit())
                    }
                }
                if !model.running {
                    Divider()
                    ForEach(Array(model.verdicts.enumerated()), id: \.offset) { _, v in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: icon(v.0).0).foregroundStyle(icon(v.0).1)
                            Text(v.1).font(.callout).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    Text("Los resultados se usan en la revisión del servidor: si detectan upstreams lentos, caché insuficiente o límites de tasa, aparecerán como mejoras sugeridas (conéctate o pulsa «Reanalizar»). «En caché»: mediana de dominios populares ya resueltos. «Sin caché»: nombres inexistentes únicos, que obligan al servidor a consultar a su upstream. «Bloqueo»: dominios publicitarios conocidos que el servidor debería bloquear.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
            HStack {
                Spacer()
                Button("Repetir") { Task { await runAndPublish() } }.disabled(model.running)
                Button("Cerrar") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(22).frame(width: 760, height: 560)
        .task { await runAndPublish() }
    }

    /// Guarda los resultados en la sesión de cada servidor para que la revisión los use.
    private func runAndPublish() async {
        await model.run(servers: servers)
        let refs = model.results.filter { $0.target.reference && !$0.unreachable }
            .compactMap { r in r.uncachedMs.map { (name: r.target.name, host: r.target.host, ms: $0) } }
        for r in model.results where !r.target.reference && !r.unreachable {
            let ctx = BenchContext(cachedMs: r.cachedMs, uncachedMs: r.uncachedMs, lossPct: r.lossPct, blocked: r.blocked, refs: refs)
            for s in servers where s.host == r.target.host { app.session(for: s).bench = ctx }
        }
    }

    private func icon(_ s: Severity) -> (String, Color) {
        switch s {
        case .ok: return ("checkmark.circle.fill", .green)
        case .info: return ("info.circle.fill", .blue)
        case .warning: return ("exclamationmark.triangle.fill", .orange)
        case .critical: return ("xmark.octagon.fill", .red)
        }
    }
}
