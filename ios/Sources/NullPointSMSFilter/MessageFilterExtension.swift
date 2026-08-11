import IdentityLookup

/// SMS Filter extension stub — forwards unknown-sender bodies to the backend for classification.
/// Apple only invokes this for messages from numbers not in the user's contacts.
final class MessageFilterExtension: ILMessageFilterExtension {}

final class MessageFilterQueryHandling: NSObject, ILMessageFilterQueryHandling {
    func handle(_ queryRequest: ILMessageFilterQueryRequest,
                context: ILMessageFilterExtensionContext,
                completion: @escaping (ILMessageFilterQueryResponse) -> Void) {
        let response = ILMessageFilterQueryResponse()
        response.action = .none

        // Production path: POST body hash + sender to a dedicated smish endpoint with JWT.
        // For pilot stub, defer to system default (no offline ML in extension).
        let body = queryRequest.messageBody ?? ""
        if body.lowercased().contains("irs") || body.contains("http") {
            response.action = .filter
            response.subAction = .transactionalOthers
        }

        completion(response)
    }
}
