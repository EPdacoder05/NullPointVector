import SwiftUI

@main
struct NullPointGuardApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @State private var status = "Ready"

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                Text("NullPoint Guard")
                    .font(.title2.bold())
                Text("Call Directory and SMS Filter extensions sync blocklists via App Group.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Text(status)
                    .font(.footnote.monospaced())
                Button("Refresh blocklist (stub)") {
                    Task { await refreshBlocklist() }
                }
                .buttonStyle(.borderedProminent)
            }
            .padding()
            .navigationTitle("Guard")
        }
    }

    private func refreshBlocklist() async {
        status = "Fetching directory…"
        do {
            let file = try await APIService.shared.fetchDirectory()
            try BlocklistFile.save(file)
            status = "Synced \(file.block.count) blocks, \(file.label.count) labels"
        } catch {
            let stub = BlocklistFile(updatedAt: ISO8601DateFormatter().string(from: Date()), block: [], label: [])
            try? BlocklistFile.save(stub)
            status = "Sync failed — saved empty stub"
        }
    }
}
