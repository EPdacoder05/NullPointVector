import Foundation

/// API client for Call Directory / Message Filter sync.
final class APIService {
    static let shared = APIService()

    /// Release starts unconfigured and accepts one HTTPS URL from Info.plist.
    /// Debug retains an explicit localhost default for local pilot work.
    private(set) var baseURL: URL?

    var accessToken: String? = nil
    var refreshToken: String? = nil

    init() {
#if DEBUG
        baseURL = URL(string: "http://127.0.0.1:8088")
#endif
    }

    static var isRunningOnMac: Bool {
        ProcessInfo.processInfo.isiOSAppOnMac
    }

#if DEBUG
    /// Debug-only pilot host selection. Release is configured from Info.plist.
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
        guard let url = Self.validatedBaseURL(urlString, allowLocalHTTP: true) else { return false }
        baseURL = url
        return true
    }
#endif

    func setAccessToken(_ token: String?) { accessToken = token }
    func setRefreshToken(_ token: String?) { refreshToken = token }

    @discardableResult
    func loadFromInfoPlist() -> Bool {
#if !DEBUG
        // A Release process cannot switch API origins after launch.
        if baseURL != nil { return true }
#endif
        guard let base = Bundle.main.infoDictionary?["API_BASE_URL"] as? String,
              !base.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !base.hasPrefix("$(") else {
            return false
        }

#if DEBUG
        return setBaseURL(base)
#else
        guard let url = Self.validatedBaseURL(base, allowLocalHTTP: false) else { return false }
        baseURL = url
        return true
#endif
    }

    private static func validatedBaseURL(_ urlString: String, allowLocalHTTP: Bool) -> URL? {
        let trimmed = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let url = URL(string: trimmed),
              let scheme = url.scheme?.lowercased(),
              let host = url.host?.lowercased(),
              url.user == nil,
              url.password == nil,
              url.query == nil,
              url.fragment == nil,
              url.path.isEmpty || url.path == "/" else {
            return nil
        }

        let local = host == "localhost"
            || host == "127.0.0.1"
            || host == "0.0.0.0"
            || host == "::1"
            || host == "::"
        if allowLocalHTTP && local && scheme == "http" {
            return url
        }

        let placeholder = host == "example.com"
            || host.hasSuffix(".example.com")
            || host.hasSuffix(".example")
            || host.hasSuffix(".invalid")
            || host.hasSuffix(".localhost")
            || host.hasSuffix(".test")
        guard scheme == "https", !local, !placeholder else { return nil }
        return url
    }

    private func endpoint(_ path: String) throws -> URL {
        guard let baseURL else { throw APIError.configurationUnavailable }
        let clean = path.hasPrefix("/") ? path : "/" + path
        guard let url = URL(string: clean, relativeTo: baseURL)?.absoluteURL else {
            throw APIError.configurationUnavailable
        }
        return url
    }

    struct TokenResponse: Decodable {
        let access_token: String
        let refresh_token: String?
        let token_type: String?
    }

    enum APIError: LocalizedError {
        case configurationUnavailable
        case authenticationRequired
        case httpStatus(Int)
        case message(String)

        var errorDescription: String? {
            switch self {
            case .configurationUnavailable:
                return "The service is not configured for this build."
            case .authenticationRequired:
                return "Account sign-in is required before protection can sync."
            case .httpStatus(let code):
                switch code {
                case 401:
                    return "Your session expired. Sign in again."
                case 403:
                    return "This account does not have access to that request."
                case 429:
                    return "Too many requests. Try again shortly."
                case 500...599:
                    return "The service is temporarily unavailable. Try again later."
                default:
                    return "The request failed (HTTP \(code))."
                }
            case .message(let m):
                return m
            }
        }
    }

    /// Exchanges explicit user-provided credentials for a token.
    func login(username: String, password: String) async throws {
        var req = URLRequest(url: try endpoint("/api/v1/token"))
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
            throw APIError.httpStatus(http.statusCode)
        }
        let tok = try JSONDecoder().decode(TokenResponse.self, from: data)
        applySession(access: tok.access_token, refresh: tok.refresh_token)
    }

#if DEBUG
    /// Debug-only auto-connect for local pilot builds.
    func pilotConnect() async throws {
        let user = PilotSecrets.username.trimmingCharacters(in: .whitespacesAndNewlines)
        let pass = PilotSecrets.password.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !user.isEmpty, !pass.isEmpty else {
            throw APIError.message("Pilot access is not configured.")
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
        throw lastError ?? APIError.message("Could not connect to the service.")
    }
#endif

    func ensureAuthenticatedSession() async throws {
        guard baseURL != nil else { throw APIError.configurationUnavailable }
        if accessToken?.isEmpty == false { return }
#if DEBUG
        try await pilotConnect()
#else
        throw APIError.authenticationRequired
#endif
    }

    @discardableResult
    func refreshAccessTokenIfNeeded() async throws -> Bool {
#if DEBUG
        let storedRefresh = KeychainTokenStore.loadRefreshToken()
#else
        let storedRefresh: String? = nil
#endif
        guard let refresh = refreshToken ?? storedRefresh, !refresh.isEmpty else {
            return false
        }
        var req = URLRequest(url: try endpoint("/api/v1/token/refresh"))
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
        func makeRequest(token: String?) throws -> URLRequest {
            var req = URLRequest(url: try endpoint(path))
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

        var req = try makeRequest(token: accessToken)
        var (data, resp) = try await URLSession.shared.data(for: req)
        if let http = resp as? HTTPURLResponse, http.statusCode == 401 {
            // Debug may reconnect the pilot; Release fails authentication closed.
            if !(try await refreshAccessTokenIfNeeded()) {
#if DEBUG
                try await pilotConnect()
#else
                signOut()
                throw APIError.authenticationRequired
#endif
            }
            req = try makeRequest(token: accessToken)
            (data, resp) = try await URLSession.shared.data(for: req)
        }
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
            throw APIError.httpStatus(code)
        }
        return try JSONDecoder().decode(Out.self, from: data)
    }
}
