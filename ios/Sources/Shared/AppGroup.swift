import Foundation

enum AppGroup {
    static let id = "group.com.nullpoint.guard"

    /// Writable shared container. Release builds and extensions fail closed
    /// when the signed App Group capability is missing or unavailable.
    static var containerURL: URL? {
        if let group = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: id),
           isWritableDirectory(group) {
            return group
        }

#if DEBUG
        // Keep local app development usable without disguising a broken
        // extension configuration: each extension must use the App Group.
        if !isAppExtension {
            return localSupportURL()
        }
#endif
        return nil
    }

    private static var isAppExtension: Bool {
        Bundle.main.bundleURL.pathExtension == "appex"
    }

    private static func localSupportURL() -> URL {
        let fm = FileManager.default
        let base = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? fm.temporaryDirectory
        let dir = base.appendingPathComponent("NullPointGuard", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private static func isWritableDirectory(_ url: URL) -> Bool {
        let fm = FileManager.default
        do {
            try fm.createDirectory(at: url, withIntermediateDirectories: true)
            let probe = url.appendingPathComponent(".np_write_probe")
            try Data("ok".utf8).write(to: probe, options: .atomic)
            try fm.removeItem(at: probe)
            return true
        } catch {
            return false
        }
    }

    static var blocklistURL: URL? {
        containerURL?.appendingPathComponent("blocklist.json")
    }

    static var labelsURL: URL? {
        containerURL?.appendingPathComponent("labels.json")
    }

    static var sessionURL: URL? {
        containerURL?.appendingPathComponent("session.json")
    }

    static var campaignPhrasesURL: URL? {
        containerURL?.appendingPathComponent("campaign_phrases.json")
    }
}

struct GuardSession: Codable {
    var accessToken: String
    var baseURL: String
}

extension GuardSession {
    static func load() -> GuardSession? {
        guard let url = AppGroup.sessionURL,
              let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(GuardSession.self, from: data)
    }

    static func save(_ session: GuardSession) throws {
        guard let url = AppGroup.sessionURL else {
            throw NSError(
                domain: "NullPointGuard",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "No writable session path"]
            )
        }
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        try JSONEncoder().encode(session).write(to: url, options: .atomic)
    }

    static func clear() {
        guard let url = AppGroup.sessionURL else { return }
        try? FileManager.default.removeItem(at: url)
    }
}

struct BlocklistEntry: Codable {
    let number: String
    let label: String?
}

struct BlocklistFile: Codable {
    let updatedAt: String
    let block: [String]
    let label: [BlocklistEntry]
    let phrases: [String]?
}

extension BlocklistFile {
    static func load() -> BlocklistFile? {
        guard let url = AppGroup.blocklistURL,
              let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(BlocklistFile.self, from: data)
    }

    static func save(_ file: BlocklistFile) throws {
        guard let url = AppGroup.blocklistURL else {
            throw NSError(
                domain: "NullPointGuard",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "No writable blocklist path"]
            )
        }
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(file)
        try data.write(to: url, options: .atomic)
    }
}
