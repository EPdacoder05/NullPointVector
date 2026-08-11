import Foundation

/// Pilot credentials — committed on purpose for Internal TestFlight.
/// Rotate / remove before public App Store. No Sign-in UI.
enum PilotSecrets {
    static let username: String = "noadmin"
    static let password: String = "thepasswordispoo"
    static let accessToken: String? = nil
}
