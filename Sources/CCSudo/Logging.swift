import Foundation
import os

extension Logger {
    static let verifier = Logger(subsystem: "com.yasyf.cc-sudo", category: "Verifier")
    static let consent = Logger(subsystem: "com.yasyf.cc-sudo", category: "Consent")
    static let synckit = Logger(subsystem: "com.yasyf.cc-sudo", category: "Synckit")
    static let installer = Logger(subsystem: "com.yasyf.cc-sudo", category: "Installer")
    static let trust = Logger(subsystem: "com.yasyf.cc-sudo", category: "Trust")
    static let mcp = Logger(subsystem: "com.yasyf.cc-sudo", category: "MCP")
    static let doctor = Logger(subsystem: "com.yasyf.cc-sudo", category: "Doctor")
}
