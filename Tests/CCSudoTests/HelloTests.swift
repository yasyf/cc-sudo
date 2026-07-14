@testable import CCSudo
import Testing

@Test func greetsByName() {
    #expect(helloMessage(name: "Ada") == "Hello, Ada! This is cc-sudo.")
}

@Test(arguments: ["world", "you"])
func greetingContainsTheName(name: String) {
    #expect(helloMessage(name: name).contains(name))
}
