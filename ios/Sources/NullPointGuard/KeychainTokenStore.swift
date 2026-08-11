import Foundation
import Security

struct KeychainTokenStore {
    private static let service = "com.nullpoint.guard.auth"
    private static let accessAccount = "access.jwt"
    private static let refreshAccount = "refresh.jwt"
    private static let baseURLAccount = "api.baseurl"
    /// Legacy account from early pilot builds.
    private static let legacyAccessAccount = "analyst.jwt"

    // Optional App Group keychain access group later, e.g. "TEAMID.group.com.nullpoint.guard"
    static var accessGroup: String? = nil

    @discardableResult
    static func saveToken(_ token: String) -> Bool {
        save(account: accessAccount, value: token)
    }

    static func loadToken() -> String? {
        if let t = load(account: accessAccount), !t.isEmpty { return t }
        // Migrate old pilot keychain entry once.
        if let legacy = load(account: legacyAccessAccount), !legacy.isEmpty {
            _ = saveToken(legacy)
            _ = delete(account: legacyAccessAccount)
            return legacy
        }
        return nil
    }

    @discardableResult
    static func deleteToken() -> Bool {
        let a = delete(account: accessAccount)
        let b = delete(account: legacyAccessAccount)
        return a && b
    }

    @discardableResult
    static func saveRefreshToken(_ token: String) -> Bool {
        save(account: refreshAccount, value: token)
    }

    static func loadRefreshToken() -> String? {
        load(account: refreshAccount)
    }

    @discardableResult
    static func deleteRefreshToken() -> Bool {
        delete(account: refreshAccount)
    }

    @discardableResult
    static func saveBaseURL(_ urlString: String) -> Bool {
        save(account: baseURLAccount, value: urlString)
    }

    static func loadBaseURL() -> String? {
        load(account: baseURLAccount)
    }

    @discardableResult
    static func deleteBaseURL() -> Bool {
        delete(account: baseURLAccount)
    }

    static func clearSession() {
        _ = deleteToken()
        _ = deleteRefreshToken()
    }

    private static func save(account: String, value: String) -> Bool {
        guard let data = value.data(using: .utf8) else { return false }
        _ = delete(account: account)
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }

    private static func load(account: String) -> String? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func delete(account: String) -> Bool {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
