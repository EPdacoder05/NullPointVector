import Foundation

/// API client for Call Directory / Message Filter sync.
final class APIService {
    static let shared = APIService()

    /// Default API host (overridden at app startup via PilotSecrets/Info.plist).
    var baseURL = URL(string: "http://127.0.0.1:8088")!

    var accessToken: String? = nil
    var refreshToken: String? = nil

    init() {}

    static var isRunningOnMac: Bool {
        ProcessInfo.processInfo.isiOSAppOnMac
    }

    /// Prefer localhost on Mac; on phone try Funnel host (works with or without Tailscale app).
    static func preferredBaseURLString() -> String {
        if isRunningOnMac {
            return "http://127.0.0.1:8088"
        }
        let custom = PilotSecrets.apiBaseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        if !custom.isEmpty { return custom }
        return "http://127.0.0.1:8088"
    }

    /// Alternate hosts if the preferred one fails (Funnel vs tailnet).
    static func candidateBaseURLs() -> [String] {
        var urls = ["http://127.0.0.1:8088", "http://localhost:8088"]
        let custom = PilotSecrets.apiBaseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        if !custom.isEmpty { urls.insert(custom, at: 0) }
        return urls
    }

    @discardableResult
    func setBaseURL(_ urlString: String) -> Bool {
        let trimmed = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let url = URL(string: trimmed), let scheme = url.scheme?.lowercased(), let host = url.host else {
            return false
        }
        let local = host == "localhost" || host == "127.0.0.1"
        if scheme == "https" || (scheme == "http" && local) {
            self.baseURL = url
            return true
        }
        return false
    }

    func setAccessToken(_ token: String?) { accessToken = token }
    func setRefreshToken(_ token: String?) { refreshToken = token }

    func loadFromInfoPlist() {
        let info = Bundle.main.infoDictionary
        if let base = info?["API_BASE_URL"] as? String,
           !base.isEmpty,
           !base.hasPrefix("$(") {
            _ = setBaseURL(base)
        }
    }

    private func endpoint(_ path: String) -> URL {
        let clean = path.hasPrefix("/") ? path : "/" + path
        return URL(string: clean, relativeTo: baseURL)!.absoluteURL
    }

    struct TokenResponse: Decodable {
        let access_token: String
        let refresh_token: String?
        let token_type: String?
    }

    enum APIError: LocalizedError {
        case httpStatus(Int, String)
        case message(String)

        var errorDescription: String? {
            switch self {
            case .httpStatus(let code, let body):
                return "HTTP \(code) \(body.prefix(120))"
            case .message(let m):
                return m
            }
        }
    }

    /// Pilot: username/password from PilotSecrets — no UI typing.
    func login(username: String, password: String) async throws {
        var req = URLRequest(url: endpoint("/api/v1/token"))
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&+=?")
        let u = username.addingPercentEncoding(withAllowedCharacters: allowed) ?? username
        let p = password.addingPercentEncoding(withAllowedCharacters: allowed) ?? password
        req.httpBody = "username=\(u)&password=\(p)".data(using: .utf8)
        req.timeoutInterval = 30

        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw APIError.message("No HTTP response") }
        guard (200..<300).contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw APIError.httpStatus(http.statusCode, body)
        }
        let tok = try JSONDecoder().decode(TokenResponse.self, from: data)
        applySession(access: tok.access_token, refresh: tok.refresh_token)
    }

    /// Auto-connect — requires PilotSecrets (or env-backed) credentials. No baked password.
    func pilotConnect() async throws {
        let user = PilotSecrets.username.trimmingCharacters(in: .whitespacesAndNewlines)
        let pass = PilotSecrets.password.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !user.isEmpty, !pass.isEmpty else {
            throw APIError.message("PilotSecrets username/password not set")
        }

        var lastError: Error?
        for base in Self.candidateBaseURLs() {
            _ = setBaseURL(base)
            do {
                try await login(username: user, password: pass)
                return
            } catch {
                lastError = error
            }
        }
        if let token = PilotSecrets.accessToken, !token.isEmpty {
            applySession(access: token, refresh: nil)
            return
        }
        throw lastError ?? APIError.message("Could not reach API as \(user)")
    }

    @discardableResult
    func refreshAccessTokenIfNeeded() async throws -> Bool {
        guard let refresh = refreshToken ?? KeychainTokenStore.loadRefreshToken(), !refresh.isEmpty else {
            return false
        }
        var req = URLRequest(url: endpoint("/api/v1/token/refresh"))
        req.httpMethod = "POST"
        req.setValue(refresh, forHTTPHeaderField: "X-Refresh-Token")
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            return false
        }
        let tok = try JSONDecoder().decode(TokenResponse.self, from: data)
        applySession(access: tok.access_token, refresh: tok.refresh_token ?? refresh)
        return true
    }

    func signOut() {
        accessToken = nil
        refreshToken = nil
        KeychainTokenStore.clearSession()
    }

    private func applySession(access: String, refresh: String?) {
        accessToken = access
        _ = KeychainTokenStore.saveToken(access)
        if let refresh, !refresh.isEmpty {
            refreshToken = refresh
            _ = KeychainTokenStore.saveRefreshToken(refresh)
        }
    }

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
        let verdict: String?
        let reasons: [String]?
    }

    struct ScreenEvent: Decodable, Identifiable {
        let id: String
        let ts: String
        let caller_id: String
        let action: String
        let risk: Double?
        let verdict: String?
        let is_threat: Bool
        let reasons: [String]?
        let label: String?
    }

    struct ScreensResponse: Decodable {
        let events: [ScreenEvent]
    }

    func screenCall(callerId: String, transcript: String?, contactKnown: Bool) async throws -> ScreenResponse {
        try await authorizedJSON(
            path: "/api/v1/vish/screen",
            method: "POST",
            body: ScreenRequest(
                caller_id: callerId,
                phase: transcript == nil ? "incoming" : "voicemail",
                transcript: transcript,
                contact_known: contactKnown
            )
        )
    }

    func fetchDirectory() async throws -> BlocklistFile {
        try await authorizedRequest(path: "/api/v1/vish/directory", method: "GET", jsonBody: nil)
    }

    func fetchScreens(limit: Int = 40) async throws -> [ScreenEvent] {
        let out: ScreensResponse = try await authorizedRequest(
            path: "/api/v1/vish/screens?limit=\(limit)",
            method: "GET",
            jsonBody: nil
        )
        return out.events
    }

    private func authorizedJSON<Body: Encodable, Out: Decodable>(
        path: String,
        method: String,
        body: Body
    ) async throws -> Out {
        try await authorizedRequest(path: path, method: method, jsonBody: try JSONEncoder().encode(body))
    }

    private func authorizedRequest<Out: Decodable>(
        path: String,
        method: String,
        jsonBody: Data?
    ) async throws -> Out {
        func makeRequest(token: String?) -> URLRequest {
            var req = URLRequest(url: endpoint(path))
            req.httpMethod = method
            req.timeoutInterval = 30
            if let token, !token.isEmpty {
                req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            }
            if let jsonBody {
                req.setValue("application/json", forHTTPHeaderField: "Content-Type")
                req.httpBody = jsonBody
            }
            return req
        }

        var req = makeRequest(token: accessToken)
        var (data, resp) = try await URLSession.shared.data(for: req)
        if let http = resp as? HTTPURLResponse, http.statusCode == 401 {
            // Re-login via pilot secrets if refresh fails
            if !(try await refreshAccessTokenIfNeeded()) {
                try await pilotConnect()
            }
            req = makeRequest(token: accessToken)
            (data, resp) = try await URLSession.shared.data(for: req)
        }
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
            let body = String(data: data, encoding: .utf8) ?? ""
            throw APIError.httpStatus(code, body)
        }
        return try JSONDecoder().decode(Out.self, from: data)
    }
}
