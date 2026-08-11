import Foundation

/// Minimal API client for VishGuard hybrid screening.
/// Auth: Bearer JWT with analyst role (issued by POST /api/v1/token).
final class APIService {
    static let shared = APIService()

    /// Override in scheme environment or Info.plist for dev/staging.
    var baseURL = URL(string: "https://api.nullpoint.local")!
    var accessToken: String?

    struct ScreenRequest: Encodable {
        let caller_id: String
        let phase: String
        let transcript: String?
        let contact_known: Bool
    }

    struct ScreenResponse: Decodable {
        let action: String
        let is_threat: Bool
        let risk: Double
        let label: String?
    }

    func screenCall(callerId: String, transcript: String?, contactKnown: Bool) async throws -> ScreenResponse {
        var req = URLRequest(url: baseURL.appendingPathComponent("/api/v1/vish/screen"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token = accessToken {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        let body = ScreenRequest(
            caller_id: callerId,
            phase: transcript == nil ? "incoming" : "voicemail",
            transcript: transcript,
            contact_known: contactKnown
        )
        req.httpBody = try JSONEncoder().encode(body)
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw URLError(.badServerResponse)
        }
        return try JSONDecoder().decode(ScreenResponse.self, from: data)
    }

    /// Sync block/label lists from GET /api/v1/vish/directory (analyst JWT).
    func fetchDirectory() async throws -> BlocklistFile {
        var req = URLRequest(url: baseURL.appendingPathComponent("/api/v1/vish/directory"))
        if let token = accessToken {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw URLError(.badServerResponse)
        }
        return try JSONDecoder().decode(BlocklistFile.self, from: data)
    }
}
