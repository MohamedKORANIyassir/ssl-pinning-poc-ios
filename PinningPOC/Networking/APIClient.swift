import Foundation

struct User: Decodable, Sendable {
    let login: String
}

struct PinningError: LocalizedError {
    var errorDescription: String? { "Secure connection failed. Check your network or update the app." }
}

/// All calls to our backend go through here: pinning only protects requests made with a pinning delegate.
enum APIClient {
    /// `PinningDelegate()` pins the hash (default). Use `PublicKeyPinningDelegate()` to pin the key itself.
    static func makeDelegate() -> URLSessionDelegate { PinningDelegate() }

    static func getUsers() async throws -> [User] {
        // Demo: a new session per call, so every call does a full handshake and the pin check always runs.
        let session = URLSession(configuration: .ephemeral, delegate: makeDelegate(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        do {
            let (data, _) = try await session.data(from: URL(string: "https://\(Pinning.host)/users")!)
            return try JSONDecoder().decode([User].self, from: data)
        } catch URLError.cancelled {
            throw PinningError() // the delegate rejected the server. Never retry without pinning.
        }
    }
}
