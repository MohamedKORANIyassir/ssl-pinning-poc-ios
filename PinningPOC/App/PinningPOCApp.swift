import SwiftUI

@main
struct PinningPOCApp: App {
    var body: some Scene { WindowGroup { ContentView() } }
}

struct ContentView: View {
    @AppStorage("debug_pinning_on") private var debugPinningOn = false
    @AppStorage("remote_pinning_off") private var remoteSwitchOff = false
    @State private var result = ""

    var body: some View {
        Form {
            #if DEBUG
            Toggle("Debug: turn pinning on", isOn: $debugPinningOn)
            Toggle("Remote switch: force pinning off", isOn: $remoteSwitchOff)
            Text(Pinning.isEnabled(remoteSwitchOff: remoteSwitchOff, debugPinningOn: debugPinningOn)
                 ? "Pinning is ON" : "Pinning is OFF").bold()
            #endif
            Button("GET /users") { Task { await load() } }
            Text(result)
        }
    }

    private func load() async {
        do {
            let users = try await APIClient.getUsers()
            result = "✅ \(users.count) users received"
        } catch {
            result = "⛔️ \(error.localizedDescription)"
        }
    }
}
