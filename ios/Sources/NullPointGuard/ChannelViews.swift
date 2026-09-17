import SwiftUI

/// SMS channel home — Message Filter is the real RTI path; this screen explains + paste-check.
struct SmishGuardView: View {
    @State private var pasteText = ""
    @State private var verdict: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                channelBrand(
                    title: "SmishGuard",
                    tagline: "SMS protection that stops smishing before it bites."
                )

                statusCard(
                    title: "SMS Filter on this iPhone",
                    body: "Settings → Messages → Unknown & Spam → enable NullPoint SMS Filter. Apple only runs the filter for senders not in Contacts."
                )

                Button {
                    // Opens system Settings; user enables the extension there.
                    if let url = URL(string: UIApplication.openSettingsURLString) {
                        UIApplication.shared.open(url)
                    }
                } label: {
                    Text("Open Messages settings")
                        .font(.headline.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 16)
                        .background(NP.brass)
                        .foregroundStyle(NP.ink)
                }

                VStack(alignment: .leading, spacing: 10) {
                    Text("Paste suspicious text")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(NP.text)
                    Text("Granny path when Filter did not catch it — paste, then we score locally + sync directory on next Guard scan.")
                        .font(.caption)
                        .foregroundStyle(NP.muted)
                    TextEditor(text: $pasteText)
                        .frame(minHeight: 90)
                        .padding(8)
                        .scrollContentBackground(.hidden)
                        .background(NP.panel2)
                        .foregroundStyle(NP.text)
                        .overlay(Rectangle().stroke(NP.line, lineWidth: 1))
                    Button {
                        verdict = localSmishHint(pasteText)
                    } label: {
                        Text("Paste & Scan")
                            .fontWeight(.semibold)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 12)
                            .background(NP.brass)
                            .foregroundStyle(NP.ink)
                    }
                    .disabled(pasteText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    if let verdict {
                        Text(verdict)
                            .font(.footnote)
                            .foregroundStyle(NP.text)
                    }
                }
                .padding(16)
                .background(NP.panel)
                .overlay(Rectangle().stroke(NP.line, lineWidth: 1))

                tipCard(
                    "Unknown Senders only. Contacts bypass the filter. Full SmishGuard model on-device is later — Filter uses campaign phrases + blocklist synced from Guard."
                )
            }
            .padding(20)
        }
        .background(NP.ink.ignoresSafeArea())
    }

    private func localSmishHint(_ raw: String) -> String {
        let t = raw.lowercased()
        let hits = ["irs", "gift card", "verify now", "http://", "https://", "tax resolution", "press 1"]
            .filter { t.contains($0) }.count
        if hits >= 2 { return "BLOCK lean — looks like a known lure. Report in Signal Deck if this landed in Messages." }
        if hits == 1 { return "REVIEW — one risk cue. Do not tap links. Enable SMS Filter if off." }
        return "CLEAR lean — no strong lure phrases. Filter still watches unknown senders."
    }
}

/// Voice / Call Directory channel.
struct VishGuardView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                channelBrand(
                    title: "VishGuard",
                    tagline: "Pre-ring Call Directory + share voicemail when it rings."
                )
                statusCard(
                    title: "Call Blocking & Identification",
                    body: "Settings → Phone → Call Blocking & Identification → enable Guard Directory. Force-quit Phone after sync."
                )
                tipCard(
                    "Ring-time unknown numbers fail-open unless they are on the synced list or you screen them. Share Extension: Phone Voicemail → Share → NullPoint Guard (sign in once first). Menu → Active Recon to screen a number now."
                )
                tipCard(
                    "After Scan succeeds: force-quit Phone so Call Directory reloads the tax-campaign pack."
                )
            }
            .padding(20)
        }
        .background(NP.ink.ignoresSafeArea())
    }
}

/// Email channel — points at Signal Deck (IMAP is not scraped from the phone).
struct PhishGuardView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                channelBrand(
                    title: "PhishGuard",
                    tagline: "Email threats quarantine in Signal Deck — not a second Gmail."
                )
                statusCard(
                    title: "Hands-off path",
                    body: "Connect mailbox once in Signal Deck → Connectors. Monitor polls Inbox; high-confidence mail goes to Quarantine. You grade only the queue — granny taps Report this when unsure."
                )
                tipCard(
                    "Admin never needs your raw Yahoo password after Connectors. Operator sees fleet reports + quarantine counts — not every user’s full inbox body on the KPI path."
                )
                Link(destination: URL(string: "http://127.0.0.1:8088/app/quarantine")!) {
                    Text("Open Quarantine in Signal Deck")
                        .font(.headline.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 16)
                        .background(NP.brass)
                        .foregroundStyle(NP.ink)
                }
                tipCard(
                    "On device, open the same path on your Funnel https host: /app/quarantine — after Connectors + monitor are running."
                )
            }
            .padding(20)
        }
        .background(NP.ink.ignoresSafeArea())
    }
}

struct SetupGuideView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                channelBrand(title: "Setup", tagline: "One-time iPhone switches.")
                step("1", "Open Guard → Sign in (Settings) → Scan for threats")
                step("2", "Settings → Phone → Call Blocking → enable Guard Directory")
                step("3", "Settings → Messages → Unknown & Spam → enable SMS Filter")
                step("4", "Force-quit Phone + Messages")
                step("5", "Voicemail → Share → NullPoint Guard")
            }
            .padding(20)
        }
        .background(NP.ink.ignoresSafeArea())
    }

    private func step(_ n: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(n)
                .font(.caption.weight(.bold))
                .foregroundStyle(NP.ink)
                .frame(width: 22, height: 22)
                .background(NP.brass)
            Text(text)
                .font(.subheadline)
                .foregroundStyle(NP.text)
        }
    }
}

struct GuardSettingsView: View {
    @State private var baseURL = APIService.shared.baseURL?.absoluteString ?? ""
    @State private var status = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                channelBrand(title: "Settings", tagline: "API host must be HTTPS on a physical iPhone.")
                Text("API base URL")
                    .font(.caption)
                    .foregroundStyle(NP.muted)
                TextField("https://your-host…", text: $baseURL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .padding(12)
                    .background(NP.panel2)
                    .foregroundStyle(NP.text)
                    .overlay(Rectangle().stroke(NP.line, lineWidth: 1))
                Button {
#if DEBUG
                    if APIService.shared.setBaseURL(baseURL) {
                        status = "Saved. Scan again from Guard."
                    } else {
                        status = "Invalid URL. Use http://127.0.0.1:8088 on Simulator or https:// on device."
                    }
#else
                    if APIService.shared.loadFromInfoPlist() {
                        status = "Release builds use Info.plist API_BASE_URL only."
                    } else {
                        status = "Release has no API_BASE_URL — bake HTTPS in project.yml before Archive."
                    }
#endif
                } label: {
                    Text("Save host")
                        .font(.headline.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(NP.brass)
                        .foregroundStyle(NP.ink)
                }
                if !status.isEmpty {
                    Text(status).font(.footnote).foregroundStyle(NP.text)
                }
                tipCard(
                    "TLS error on device = http:// localhost or missing Funnel HTTPS. Tailscale Funnel → set API_BASE_URL to https://….ts.net — never http on a phone."
                )
            }
            .padding(20)
        }
        .background(NP.ink.ignoresSafeArea())
    }
}

// MARK: - shared chrome

func channelBrand(title: String, tagline: String) -> some View {
    VStack(alignment: .leading, spacing: 4) {
        Text("NULLPOINT")
            .font(.system(size: 12, weight: .bold, design: .rounded))
            .tracking(3)
            .foregroundStyle(NP.brass)
        Text(title)
            .font(.system(size: 32, weight: .bold, design: .serif))
            .foregroundStyle(NP.text)
        Text(tagline)
            .font(.subheadline)
            .foregroundStyle(NP.muted)
    }
}

func statusCard(title: String, body: String) -> some View {
    VStack(alignment: .leading, spacing: 8) {
        Text(title)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(NP.signal)
        Text(body)
            .font(.caption)
            .foregroundStyle(NP.muted)
            .fixedSize(horizontal: false, vertical: true)
    }
    .padding(16)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(NP.panel)
    .overlay(Rectangle().stroke(NP.line, lineWidth: 1))
}

func tipCard(_ text: String) -> some View {
    Text(text)
        .font(.caption)
        .foregroundStyle(NP.muted)
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(NP.panel2)
        .overlay(Rectangle().stroke(NP.line, lineWidth: 1))
}
