@testable import CCSudo
import Foundation
import Testing

private func originFile(_ contents: String?) throws -> String {
    let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let path = dir.appending(path: "origin-host").path
    if let contents {
        try Data(contents.utf8).write(to: URL(filePath: path))
    }
    return path
}

@Test func installKeepsTheRecordedOrigin() throws {
    let path = try originFile("yasyf@studio.tail.ts.net\n")
    #expect(OriginIdentity.forInstall(requested: nil, path: path) == "yasyf@studio.tail.ts.net")
}

@Test func installPrefersTheRequestedOrigin() throws {
    let path = try originFile("yasyf@studio.tail.ts.net\n")
    #expect(OriginIdentity.forInstall(requested: "yasyf@laptop.tail.ts.net", path: path) == "yasyf@laptop.tail.ts.net")
}

@Test func freshInstallFallsBackToTheShortHostName() throws {
    let missing = try originFile(nil)
    let blank = try originFile("\n")
    #expect(OriginIdentity.forInstall(requested: nil, path: missing) == OriginIdentity.defaultIdentity())
    #expect(OriginIdentity.forInstall(requested: nil, path: blank) == OriginIdentity.defaultIdentity())
}
