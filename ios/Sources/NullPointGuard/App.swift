import SwiftUI
import CallKit

// Brand tokens — Signal Deck forest + brass (no purple, no emoji).
private enum NP {
    static let ink = Color(red: 0.043, green: 0.063, blue: 0.055)
    static let panel = Color(red: 0.078, green: 0.110, blue: 0.090)
    static let panel2 = Color(red: 0.102, green: 0.141, blue: 0.118)
    static let line = Color(red: 0.18, green: 0.28, blue: 0.22)
    static let brass = Color(red: 0.769, green: 0.647, blue: 0.455)
    static let brassDim = Color(red: 0.604, green: 0.490, blue: 0.322)
    static let signal = Color(red: 0.18, green: 0.65, blue: 0.42)
    static let danger = Color(red: 0.82, green: 0.32, blue: 0.28)
    static let text = Color(red: 0.92, green: 0.93, blue: 0.90)
    static let muted = Color(red: 0.62, green: 0.68, blue: 0.64)
}

private enum GuardPrefs {
    static let autoModeKey = "np.guard.autoMode"
}

@main
struct NullPointGuardApp: App {
    init() {
        _ = KeychainTokenStore.deleteBaseURL()
        _ = APIService.shared.setBaseURL(APIService.preferredBaseURLString())
        if !APIService.isRunningOnMac {
            APIService.shared.loadFromInfoPlist()
        }
        if let token = KeychainTokenStore.loadToken(), !token.isEmpty {
            APIService.shared.setAccessToken(token)
        }
        if let refresh = KeychainTokenStore.loadRefreshToken(), !refresh.isEmpty {
            APIService.shared.setRefreshToken(refresh)
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .preferredColorScheme(.dark)
        }
    }
}

struct ContentView: View {
    @AppStorage(GuardPrefs.autoModeKey) private var autoMode = true
    @State private var protected = false
    @State private var busy = false
    @State private var scanning = false
    @State private var checking = false
    @State private var lastError: String?
    @State private var scanSummary = "Not scanned yet"
    @State private var blockCount = 0
    @State private var labelCount = 0
    @State private var blocks: [String] = []
    @State private var labelEntries: [BlocklistEntry] = []
    @State private var events: [APIService.ScreenEvent] = []
    @State private var checkNumber = ""
    @State private var checkResult: String?
    @State private var showAutoInfo = false
    @State private var showSetup = false
    @State private var autoTick: Timer?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    brand
                    autoModeRow
                    scanButton
                    activeRecon
                    proRow(
                        title: "Credit reporting · SSN alerts",
                        body: "Pro · Array / Plaid soft signals. Consent-gated, fail-open. Vendor keys unlock live checks — no DIY bureau.",
                        status: "Coming Pro"
                    )
                    proRow(
                        title: "Dark web monitoring",
                        body: "Pro · Licensed breach intel (IPQS / SpyCloud-class). Scheduled scans when keys are set — we never scrape dark web ourselves.",
                        status: "Coming Pro"
                    )
                    setupFooter
                }
                .padding(20)
            }
            .background(NP.ink.ignoresSafeArea())
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .principal) {
                    Text("Guard")
                        .font(.headline.weight(.semibold))
                        .foregroundStyle(NP.brass)
                }
            }
            .task {
                if autoMode {
                    await scanThreats()
                }
                startAutoTimerIfNeeded()
            }
            .onChange(of: autoMode) { on in
                if on {
                    startAutoTimerIfNeeded()
                    Task { await scanThreats() }
                } else {
                    autoTick?.invalidate()
                    autoTick = nil
                }
            }
            .onDisappear {
                autoTick?.invalidate()
                autoTick = nil
            }
            .alert("Auto-mode", isPresented: $showAutoInfo) {
                Button("OK", role: .cancel) {}
            } message: {
                Text("When on, Guard keeps Call Directory + SMS filter lists fresh (sync + reload). Apple still only blocks from that list before the ring — it does not stream live calls into the app.")
            }
        }
    }

    private var brand: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("NULLPOINT")
                .font(.system(size: 12, weight: .bold, design: .rounded))
                .tracking(3)
                .foregroundStyle(NP.brass)
            Text("Guard")
                .font(.system(size: 32, weight: .bold, design: .serif))
                .foregroundStyle(NP.text)
            HStack(spacing: 8) {
                Circle()
                    .fill(protected ? NP.signal : NP.danger)
                    .frame(width: 8, height: 8)
                Text(protected ? "Protected" : "Offline")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(protected ? NP.signal : NP.danger)
                Text("·")
                    .foregroundStyle(NP.muted)
                Text(scanSummary)
                    .font(.caption)
                    .foregroundStyle(NP.muted)
                    .lineLimit(1)
            }
            if let lastError {
                Text(lastError)
                    .font(.caption)
                    .foregroundStyle(NP.danger)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.bottom, 4)
    }

    private var autoModeRow: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text("Auto-mode")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(NP.text)
                    Button {
                        showAutoInfo = true
                    } label: {
                        Image(systemName: "info.circle")
                            .font(.body)
                            .foregroundStyle(NP.brassDim)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("About auto-mode")
                }
                Text("Keeps blocklists synced in the background.")
                    .font(.caption)
                    .foregroundStyle(NP.muted)
            }
            Spacer()
            Toggle("", isOn: $autoMode)
                .labelsHidden()
                .tint(NP.signal)
        }
        .padding(16)
        .background(NP.panel)
        .overlay(Rectangle().stroke(NP.line, lineWidth: 1))
    }

    private var scanButton: some View {
        Button {
            Task { await scanThreats() }
        } label: {
            HStack {
                if scanning || busy {
                    ProgressView().tint(NP.ink)
                }
                Text(scanning || busy ? "Scanning…" : "Scan for threats")
                    .font(.headline.weight(.semibold))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 16)
            .background(NP.brass)
            .foregroundStyle(NP.ink)
        }
        .disabled(scanning || busy)
        .accessibilityHint("Sync Call Directory and Message Filter lists from NullPoint")
    }

    private var activeRecon: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("Active recon")
            Text("Screen a number now. Confirmed threats feed the directory on the next scan.")
                .font(.caption)
                .foregroundStyle(NP.muted)

            HStack(spacing: 8) {
                TextField("+1…", text: $checkNumber)
                    .keyboardType(.phonePad)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .padding(12)
                    .background(NP.panel2)
                    .foregroundStyle(NP.text)
                    .overlay(Rectangle().stroke(NP.line, lineWidth: 1))

                Button {
                    Task { await runCheck() }
                } label: {
                    if checking {
                        ProgressView().tint(NP.ink)
                    } else {
                        Text("Screen")
                            .fontWeight(.semibold)
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .background(NP.brass)
                .foregroundStyle(NP.ink)
                .disabled(checking || checkNumber.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            if let checkResult {
                Text(checkResult)
                    .font(.footnote)
                    .foregroundStyle(NP.text)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack(spacing: 10) {
                miniStat("\(blockCount)", "Blocked")
                miniStat("\(labelCount)", "Labeled")
                miniStat("\(events.count)", "Screens")
            }

            if !blocks.isEmpty || !labelEntries.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(blocks.prefix(6), id: \.self) { n in
                        reconLine(kind: "BLOCK", text: n)
                    }
                    ForEach(labelEntries.prefix(4), id: \.number) { e in
                        reconLine(kind: "LABEL", text: e.number)
                    }
                }
            }

            if !events.isEmpty {
                Divider().overlay(NP.line)
                ForEach(events.prefix(4)) { ev in
                    HStack {
                        Text(ev.caller_id.isEmpty ? "unknown" : ev.caller_id)
                            .font(.caption.monospaced())
                            .foregroundStyle(NP.text)
                            .lineLimit(1)
                        Spacer()
                        Text(ev.action.uppercased())
                            .font(.system(size: 10, weight: .bold, design: .rounded))
                            .foregroundStyle(ev.is_threat ? NP.danger : NP.signal)
                    }
                }
            }
        }
        .padding(16)
        .background(NP.panel)
        .overlay(Rectangle().stroke(NP.line, lineWidth: 1))
    }

    private func proRow(title: String, body: String, status: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(NP.text)
                Spacer()
                Text(status.uppercased())
                    .font(.system(size: 10, weight: .bold, design: .rounded))
                    .tracking(0.6)
                    .foregroundStyle(NP.brassDim)
            }
            Text(body)
                .font(.caption)
                .foregroundStyle(NP.muted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
        .background(NP.panel)
        .overlay(Rectangle().stroke(NP.line, lineWidth: 1))
        .opacity(0.92)
    }

    private func miniStat(_ value: String, _ title: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value)
                .font(.system(size: 18, weight: .semibold, design: .rounded))
                .foregroundStyle(NP.brass)
            Text(title.uppercased())
                .font(.system(size: 9, weight: .semibold, design: .rounded))
                .foregroundStyle(NP.muted)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(NP.panel2)
    }

    private func reconLine(kind: String, text: String) -> some View {
        HStack(spacing: 8) {
            Text(kind)
                .font(.system(size: 10, weight: .bold, design: .rounded))
                .foregroundStyle(kind == "BLOCK" ? NP.danger : NP.brass)
                .frame(width: 44, alignment: .leading)
            Text(text)
                .font(.caption.monospaced())
                .foregroundStyle(NP.text)
            Spacer()
        }
    }

    private var setupFooter: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                showSetup.toggle()
            } label: {
                HStack {
                    Text("iPhone setup")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(NP.brass)
                    Spacer()
                    Image(systemName: showSetup ? "chevron.up" : "chevron.down")
                        .foregroundStyle(NP.brassDim)
                }
            }
            if showSetup {
                Text("""
                Settings → Phone → Call Blocking → enable Directory.
                Messages → Unknown & Spam → enable SMS Filter.
                Force-quit Phone + Messages after toggling.
                """)
                .font(.caption)
                .foregroundStyle(NP.muted)
            }
        }
        .padding(.top, 4)
    }

    private func sectionTitle(_ text: String) -> some View {
        Text(text.uppercased())
            .font(.system(size: 11, weight: .bold, design: .rounded))
            .tracking(1.1)
            .foregroundStyle(NP.brass)
    }

    private func startAutoTimerIfNeeded() {
        autoTick?.invalidate()
        guard autoMode else { return }
        // Background refresh while app is foregrounded (Call Directory cannot wake us).
        autoTick = Timer.scheduledTimer(withTimeInterval: 15 * 60, repeats: true) { _ in
            Task { await scanThreats() }
        }
    }

    private func scanThreats() async {
        scanning = true
        busy = true
        defer {
            scanning = false
            busy = false
        }
        lastError = nil
        do {
            try await APIService.shared.pilotConnect()
            let file = try await APIService.shared.fetchDirectory()
            try BlocklistFile.save(file)
            await reloadCallDirectory()
            blocks = file.block
            labelEntries = file.label
            blockCount = file.block.count
            labelCount = file.label.count
            protected = true
            if let fetched = try? await APIService.shared.fetchScreens(limit: 40) {
                events = fetched
            }
            scanSummary = "\(blockCount) blocks · \(labelCount) labels"
        } catch {
            protected = false
            lastError = error.localizedDescription
            scanSummary = "Scan failed"
        }
    }

    private func runCheck() async {
        let raw = checkNumber.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return }
        checking = true
        defer { checking = false }
        checkResult = nil
        do {
            if !protected {
                try await APIService.shared.pilotConnect()
            }
            let result = try await APIService.shared.screenCall(
                callerId: raw,
                transcript: nil,
                contactKnown: false
            )
            let reason = result.reasons?.first ?? result.verdict ?? ""
            checkResult = "\(result.action.uppercased()) · risk \(Int(result.risk * 100))%\n\(reason)"
            await scanThreats()
        } catch {
            checkResult = "Screen failed: \(error.localizedDescription)"
        }
    }

    private func reloadCallDirectory() async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            CXCallDirectoryManager.sharedInstance.reloadExtension(
                withIdentifier: "com.nullpoint.guard.directory"
            ) { _ in
                cont.resume()
            }
        }
    }
}
