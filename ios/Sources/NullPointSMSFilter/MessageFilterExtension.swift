import IdentityLookup

/// SMS / Message Filter extension.
/// Apple only invokes this for messages from senders not in Contacts.
final class MessageFilterExtension: ILMessageFilterExtension {}

extension MessageFilterExtension: ILMessageFilterQueryHandling {
    func handle(
        _ queryRequest: ILMessageFilterQueryRequest,
        context: ILMessageFilterExtensionContext,
        completion: @escaping (ILMessageFilterQueryResponse) -> Void
    ) {
        let response = ILMessageFilterQueryResponse()
        response.action = .none

        let body = (queryRequest.messageBody ?? "").lowercased()
        let sender = digits(queryRequest.sender ?? "")
        let file = BlocklistFile.load()
        let blocked = Set((file?.block ?? []).map(digits).filter { $0.count >= 10 })
        let phrases = (file?.phrases ?? []) + loadPhrases()

        if sender.count >= 10, blocked.contains(where: { sender.hasSuffix($0.suffix(10)) }) {
            response.action = .junk
            completion(response)
            return
        }

        let phraseHits = phrases.filter { !$0.isEmpty && body.contains($0.lowercased()) }.count
        let lure =
            phraseHits >= 2
            || body.contains("irs")
            || body.contains("verify now")
            || body.contains("gift card")
            || body.contains("http://")
            || body.contains("https://")

        if lure {
            response.action = .junk
        }
        completion(response)
    }

    private func digits(_ raw: String) -> String {
        raw.filter(\.isNumber)
    }

    private func loadPhrases() -> [String] {
        guard let url = AppGroup.campaignPhrasesURL,
              let data = try? Data(contentsOf: url),
              let list = try? JSONDecoder().decode([String].self, from: data) else {
            return []
        }
        return list
    }
}
