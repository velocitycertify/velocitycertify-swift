import Foundation

// MARK: - MockURLProtocol
//
// A URLProtocol subclass for intercepting URLSession requests in tests.
//
// Usage:
//
//   // 1. Register per-URL handlers before the test runs
//   MockURLProtocol.register(url: ManifestCache.manifestURL) { _ in
//       .success(data: myManifestData, statusCode: 200)
//   }
//
//   // 2. Build a URLSession backed by MockURLProtocol
//   let session = MockURLProtocol.makeSession()
//
//   // 3. Inject that session into ManifestCache / any network client
//   let cache = ManifestCache(session: session, pubkeyPEM: myTestPEM)
//
//   // 4. In tearDown, clear all handlers
//   MockURLProtocol.reset()
//
// The handler closure receives the URLRequest and returns a MockResponse.
// Returning .failure throws the given error to the URLSession task.
// Returning .success returns the data and HTTP status code synchronously.
//
// Thread safety: handlers are protected by a lock; safe to call from any thread.

public final class MockURLProtocol: URLProtocol {

    // MARK: - Response type

    public enum MockResponse {
        case success(data: Data, statusCode: Int = 200,
                     headers: [String: String] = [:])
        case failure(Error)
    }

    public typealias Handler = (URLRequest) -> MockResponse

    // MARK: - Handler registry

    private static var lock     = NSLock()
    private static var handlers = [URL: Handler]()

    /// Register a handler for a specific URL.
    public static func register(url: URL, handler: @escaping Handler) {
        lock.withLock { handlers[url] = handler }
    }

    /// Register a fixed success response for a URL (no request inspection needed).
    public static func stub(url: URL, data: Data, statusCode: Int = 200) {
        register(url: url) { _ in .success(data: data, statusCode: statusCode) }
    }

    /// Register a fixed network error for a URL.
    public static func stub(url: URL, error: Error) {
        register(url: url) { _ in .failure(error) }
    }

    /// Remove all registered handlers. Call this in tearDown.
    public static func reset() {
        lock.withLock { handlers.removeAll() }
    }

    /// Build a URLSession whose configuration registers MockURLProtocol.
    /// IMPORTANT: the session must be created AFTER the handlers are registered
    /// (or at least before the task fires).
    public static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        // Disable caching so every request hits the handler
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return URLSession(configuration: config)
    }

    // MARK: - URLProtocol overrides

    override public class func canInit(with request: URLRequest) -> Bool {
        guard let url = request.url else { return false }
        return lock.withLock { handlers[url] != nil }
    }

    override public class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }

    override public func startLoading() {
        guard let url = request.url else {
            client?.urlProtocol(self, didFailWithError:
                URLError(.badURL, userInfo: [NSURLErrorFailingURLErrorKey: "nil URL"]))
            return
        }

        let handler = MockURLProtocol.lock.withLock {
            MockURLProtocol.handlers[url]
        }
        guard let handler else {
            client?.urlProtocol(self, didFailWithError:
                URLError(.unsupportedURL, userInfo: [NSURLErrorFailingURLErrorKey: url]))
            return
        }

        switch handler(request) {
        case .success(let data, let statusCode, let headers):
            let response = HTTPURLResponse(
                url: url,
                statusCode: statusCode,
                httpVersion: "HTTP/1.1",
                headerFields: headers
            )!
            client?.urlProtocol(self, didReceive: response,
                                cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)

        case .failure(let error):
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override public func stopLoading() {
        // Nothing to cancel — all responses are synchronous in tests.
    }
}

// MARK: - NSLock convenience

private extension NSLock {
    @discardableResult
    func withLock<T>(_ body: () -> T) -> T {
        lock()
        defer { unlock() }
        return body()
    }
}
