import Foundation

extension Data {
    /// Lossy UTF-8 for subprocess and wire output that is displayed, never
    /// parsed: invalid bytes become U+FFFD instead of dropping the message —
    /// which is why this is String(decoding:), not the failable initializer
    /// the optional_data_string_conversion lint prefers.
    var utf8Lossy: String {
        String(decoding: self, as: UTF8.self)
    }
}
