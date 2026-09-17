import UIKit
import UniformTypeIdentifiers

/// Share target for Phone Voicemail / Voice Memos / Files.
/// User taps Share → NullPoint Guard. We extract a number + transcript and
/// POST /api/v1/vish/screen so campaign fingerprints can block origin + TFNs.
final class ShareViewController: UIViewController {
    private let status = UILabel()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(red: 0.043, green: 0.063, blue: 0.055, alpha: 1)
        status.numberOfLines = 0
        status.textColor = UIColor(red: 0.92, green: 0.93, blue: 0.90, alpha: 1)
        status.font = UIFont.preferredFont(forTextStyle: .body)
        status.text = "Sending to NullPoint…"
        status.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(status)
        NSLayoutConstraint.activate([
            status.leadingAnchor.constraint(equalTo: view.layoutMarginsGuide.leadingAnchor),
            status.trailingAnchor.constraint(equalTo: view.layoutMarginsGuide.trailingAnchor),
            status.centerYAnchor.constraint(equalTo: view.centerYAnchor),
        ])
        Task { await runShare() }
    }

    private func runShare() async {
        let items = await collectedText()
        let text = items.joined(separator: "\n")
        let number = firstPhone(in: text) ?? "+10000000000"
        guard let session = GuardSession.load(),
              let base = URL(string: session.baseURL) else {
            finish("Open NullPoint Guard and sign in once, then share again.")
            return
        }
        var req = URLRequest(url: base.appendingPathComponent("api/v1/vish/screen"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Bearer \(session.accessToken)", forHTTPHeaderField: "Authorization")
        let body: [String: Any] = [
            "caller_id": number,
            "phase": "voicemail",
            "transcript": String(text.prefix(20_000)),
            "contact_known": false,
        ]
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            if code == 401 {
                finish("Session expired. Open Guard, sign in, share again.")
                return
            }
            guard (200..<300).contains(code),
                  let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                finish("Screen failed (\(code)). Try Signal Deck paste.")
                return
            }
            let action = String(obj["action"] as? String ?? "unknown").uppercased()
            let threat = obj["is_threat"] as? Bool ?? false
            finish(threat ? "Blocked as \(action)." : "Screened: \(action).")
        } catch {
            finish("Network error. Check Guard API host.")
        }
    }

    private func collectedText() async -> [String] {
        var out: [String] = []
        guard let items = extensionContext?.inputItems as? [NSExtensionItem] else { return out }
        for item in items {
            for provider in item.attachments ?? [] {
                if provider.hasItemConformingToTypeIdentifier(UTType.plainText.identifier) {
                    if let text = try? await provider.loadItem(
                        forTypeIdentifier: UTType.plainText.identifier
                    ) as? String {
                        out.append(text)
                    }
                } else if provider.hasItemConformingToTypeIdentifier(UTType.url.identifier) {
                    if let url = try? await provider.loadItem(
                        forTypeIdentifier: UTType.url.identifier
                    ) as? URL {
                        out.append(url.absoluteString)
                    }
                }
            }
            if let title = item.attributedContentText?.string, !title.isEmpty {
                out.append(title)
            }
        }
        return out
    }

    private func firstPhone(in text: String) -> String? {
        let pattern = #"(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        guard let match = regex.firstMatch(in: text, range: range),
              let swift = Range(match.range, in: text) else { return nil }
        let digits = text[swift].filter(\.isNumber)
        if digits.count == 10 { return "+1" + digits }
        if digits.count == 11, digits.hasPrefix("1") { return "+" + digits }
        return nil
    }

    private func finish(_ message: String) {
        DispatchQueue.main.async {
            self.status.text = message
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) {
                self.extensionContext?.completeRequest(returningItems: nil)
            }
        }
    }
}
