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
        // Default: defer to system (do not over-filter).
        response.action = .none

        let body = (queryRequest.messageBody ?? "").lowercased()
        // Pilot heuristic only — production posts to backend with JWT.
        let lure =
            body.contains("irs")
            || body.contains("verify now")
            || body.contains("gift card")
            || body.contains("http://")
            || body.contains("https://")

        if lure {
            // ILMessageFilterAction cases: .none, .allow, .junk, .filter,
            // .promotion, .transactional (iOS 16+). NOT "IMessageFilterAction".
            response.action = .junk
        }

        completion(response)
    }
}
