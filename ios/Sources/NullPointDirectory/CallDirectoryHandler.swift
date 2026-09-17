import Foundation
import CallKit

/// Call Directory extension — loads block/label lists from the shared App Group.
final class CallDirectoryHandler: CXCallDirectoryProvider {
    override func beginRequest(with context: CXCallDirectoryExtensionContext) {
        context.delegate = self
        guard let file = BlocklistFile.load() else {
            context.completeRequest()
            return
        }

        let sortedBlocks = Set(file.block.compactMap { CXCallDirectoryPhoneNumber($0) }).sorted()
        for num in sortedBlocks {
            context.addBlockingEntry(withNextSequentialPhoneNumber: num)
        }

        let sortedLabels = Dictionary(file.label.compactMap { entry -> (CXCallDirectoryPhoneNumber, String)? in
            guard let n = CXCallDirectoryPhoneNumber(entry.number) else { return nil }
            return (n, entry.label ?? "Spam")
        }, uniquingKeysWith: { first, _ in first })
            .sorted { $0.key < $1.key }

        for (num, label) in sortedLabels {
            context.addIdentificationEntry(withNextSequentialPhoneNumber: num, label: label)
        }

        context.completeRequest()
    }
}

extension CallDirectoryHandler: CXCallDirectoryExtensionContextDelegate {
    func requestFailed(for extensionContext: CXCallDirectoryExtensionContext, withError error: Error) {
        // Log locally; never crash the extension.
        NSLog("NullPointDirectory failed: \(error.localizedDescription)")
    }
}

private extension CXCallDirectoryPhoneNumber {
    init?(_ e164: String) {
        let digits = e164.filter { $0 >= "0" && $0 <= "9" }
        guard !digits.isEmpty, let value = Int64(digits) else { return nil }
        self = CXCallDirectoryPhoneNumber(value)
    }
}
