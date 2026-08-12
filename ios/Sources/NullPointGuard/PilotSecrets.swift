import Foundation

/// Local pilot credentials. Keep empty in git. Copy values from
/// `ios/PilotSecrets.example.swift` on your machine — never commit real passwords.
enum PilotSecrets {
    static let username: String = ""
    static let password: String = ""
    static let accessToken: String? = nil
    /// Optional Funnel / public API host (https://…). Empty → localhost.
    static let apiBaseURL: String = ""
}
