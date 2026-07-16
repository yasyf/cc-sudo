@testable import CCSudo
import Foundation
import Testing

private func makeExecutable(named name: String) throws -> (dir: URL, path: URL) {
    let dir = FileManager.default.temporaryDirectory
        .appending(component: "bin-\(UUID().uuidString)", directoryHint: .isDirectory)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let path = dir.appending(component: name)
    try Data("#!/bin/sh\nexit 0\n".utf8).write(to: path)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path.path())
    return (dir, path)
}

@Test func bareNameResolvesToTheAbsolutePATHEntry() throws {
    let (dir, path) = try makeExecutable(named: "mytool")
    let resolved = try PathResolver.resolveExecutable(
        "mytool",
        environment: ["PATH": dir.path()],
        currentDirectory: "/"
    )
    #expect(resolved == path.standardizedFileURL.path())
    #expect(resolved.hasPrefix("/"))
}

@Test func anAlreadyAbsolutePathPassesThroughUnchanged() throws {
    let (_, path) = try makeExecutable(named: "mytool")
    let resolved = try PathResolver.resolveExecutable(
        path.path(),
        environment: ["PATH": "/nonexistent"],
        currentDirectory: "/"
    )
    #expect(resolved == path.standardizedFileURL.path())
}

@Test func anUnresolvableCommandThrows() throws {
    #expect(throws: PathResolver.ResolveError.self) {
        _ = try PathResolver.resolveExecutable(
            "definitely-not-on-path-\(UUID().uuidString)",
            environment: ["PATH": "/nonexistent"],
            currentDirectory: "/"
        )
    }
}

@Test func resolveReplacesArgv0AndKeepsTheRest() throws {
    let (dir, path) = try makeExecutable(named: "mytool")
    let resolved = try PathResolver.resolve(
        argv: ["mytool", "-x", "arg with spaces"],
        environment: ["PATH": dir.path()],
        currentDirectory: "/"
    )
    #expect(resolved == [path.standardizedFileURL.path(), "-x", "arg with spaces"])
}
