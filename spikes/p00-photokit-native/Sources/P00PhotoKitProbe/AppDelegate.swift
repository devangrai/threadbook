import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private let viewController: ProbeViewController
    private var window: NSWindow?

    init(viewController: ProbeViewController) {
        self.viewController = viewController
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 460, height: 210),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "PhotoKit Native Probe"
        window.contentViewController = viewController
        window.center()
        window.makeKeyAndOrderFront(nil)
        self.window = window
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}
