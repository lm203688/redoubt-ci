import AppIntents
import Foundation

// Redoubt：只做「打开 App」这一条，不带任何数据读取——该产品没有与扩展共享的存储。
@available(iOS 16.0, *)
struct RedoubtOpenIntent: AppIntent {
  static var title: LocalizedStringResource = "Open Redoubt"
  static var description: IntentDescription? = IntentDescription(
    "Opens Redoubt: encrypted offline vault for recovery codes and secrets."
  )
  static var openAppWhenRun: Bool = true

  func perform() async throws -> some IntentResult {
    return .result()
  }
}

@available(iOS 16.0, *)
struct RedoubtShortcuts: AppShortcutsProvider {
  static var appShortcuts: [AppShortcut] {
    AppShortcut(
      intent: RedoubtOpenIntent(),
      phrases: ["Open \(.applicationName)", "Launch \(.applicationName)"],
      shortTitle: "Open Redoubt",
      systemImageName: "shield.lefthalf.filled"
    )
  }
}
