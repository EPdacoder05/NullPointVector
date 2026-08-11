import Foundation

enum AppGroup {
    static let id = "group.com.nullpoint.guard"

    static var containerURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: id)
    }

    static var blocklistURL: URL? {
        containerURL?.appendingPathComponent("blocklist.json")
    }

    static var labelsURL: URL? {
        containerURL?.appendingPathComponent("labels.json")
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
}

extension BlocklistFile {
    static func load() -> BlocklistFile? {
        guard let url = AppGroup.blocklistURL,
              let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(BlocklistFile.self, from: data)
    }

    static func save(_ file: BlocklistFile) throws {
        guard let url = AppGroup.blocklistURL else { return }
        let data = try JSONEncoder().encode(file)
        try data.write(to: url, options: .atomic)
    }
}
