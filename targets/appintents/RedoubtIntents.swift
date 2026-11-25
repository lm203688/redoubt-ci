import AppIntents
import Foundation

// Redoubt：离线加密保险库（恢复码 / 钱包种子 / 密码 / 授权码 / 扫描件）。
// 意图层不读运行时数据库——SQLCipher 库只在主 App 解锁后可读——所以这里做三件
// 真正能在 Siri 里闭环的事：按分区直接进入、抄录恢复码时即时校验、评估口令熵。

@available(iOS 16.0, *)
struct VaultSectionEntity: AppEntity {
  static var typeDisplayRepresentation: TypeDisplayRepresentation = TypeDisplayRepresentation(name: "Vault section")
  static var defaultQuery = VaultSectionQuery()

  let id: String
  let summary: String

  var displayRepresentation: DisplayRepresentation {
    DisplayRepresentation(title: "\(summary)", subtitle: "\(id)")
  }

  static let all: [VaultSectionEntity] = [
    VaultSectionEntity(id: "recovery", summary: "Recovery codes"),
    VaultSectionEntity(id: "seeds", summary: "Wallet seeds"),
    VaultSectionEntity(id: "passwords", summary: "Passwords"),
    VaultSectionEntity(id: "licenses", summary: "Licence keys"),
    VaultSectionEntity(id: "documents", summary: "Scanned documents"),
  ]
}

@available(iOS 16.0, *)
struct VaultSectionQuery: EntityQuery {
  func entities(for identifiers: [String]) async throws -> [VaultSectionEntity] {
    VaultSectionEntity.all.filter { identifiers.contains($0.id) }
  }

  func suggestedEntities() async throws -> [VaultSectionEntity] {
    VaultSectionEntity.all
  }

  func defaultResult() async -> VaultSectionEntity? {
    VaultSectionEntity.all.first
  }
}

@available(iOS 16.0, *)
struct OpenVaultSectionIntent: AppIntent {
  static var title: LocalizedStringResource = "Open a Redoubt section"
  static var description: IntentDescription? = IntentDescription(
    "Opens Redoubt straight to the vault section you name, ready for Face ID unlock."
  )
  static var openAppWhenRun: Bool = true

  @Parameter(title: "Section", requestValueDialog: "Which section of the vault?")
  var section: VaultSectionEntity

  static var parameterSummary: some ParameterSummary {
    Summary("Open \(\.$section) in Redoubt")
  }

  func perform() async throws -> some IntentResult & ProvidesDialog {
    return .result(dialog: "Opening \(section.summary) in Redoubt. Unlock with Face ID to read it.")
  }
}

@available(iOS 16.0, *)
struct RecoveryCodeCheckIntent: AppIntent {
  static var title: LocalizedStringResource = "Check a recovery code"
  static var description: IntentDescription? = IntentDescription(
    "Checks that a two-factor recovery code is well formed base32 and prints it in four-character groups before you store it."
  )
  static var openAppWhenRun: Bool = false

  @Parameter(title: "Recovery code", requestValueDialog: "Paste the recovery code you want to check.")
  var code: String

  static var parameterSummary: some ParameterSummary {
    Summary("Check \(\.$code)")
  }

  func perform() async throws -> some IntentResult & ProvidesDialog {
    let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    var normalised = ""
    var offenders: [String] = []
    for ch in code.uppercased() {
      if ch == " " || ch == "-" || ch == "_" { continue }
      if allowed.contains(ch) {
        normalised.append(ch)
      } else if offenders.count < 4 {
        offenders.append(String(ch))
      }
    }
    if !offenders.isEmpty {
      return .result(
        dialog: "That is not base32: \(offenders.joined(separator: " ")) cannot appear in a recovery code. Digits 0, 1, 8 and 9 are also out."
      )
    }
    if normalised.count < 12 || normalised.count > 32 || normalised.count % 4 != 0 {
      return .result(
        dialog: "It has \(normalised.count) base32 characters, which is the wrong length. Recovery codes are 12 to 32 characters in groups of four."
      )
    }
    var groups: [String] = []
    var index = normalised.startIndex
    while index < normalised.endIndex {
      let next = normalised.index(index, offsetBy: 4, limitedBy: normalised.endIndex) ?? normalised.endIndex
      groups.append(String(normalised[index..<next]))
      index = next
    }
    return .result(
      dialog: "Looks valid: \(groups.count) groups, \(normalised.count) characters — \(groups.joined(separator: " "))."
    )
  }
}

@available(iOS 16.0, *)
struct PassphraseStrengthIntent: AppIntent {
  static var title: LocalizedStringResource = "Passphrase strength"
  static var description: IntentDescription? = IntentDescription(
    "Estimates the entropy of a word-list passphrase so you can pick a length before you write it into the vault."
  )
  static var openAppWhenRun: Bool = false

  @Parameter(title: "Words", default: 6)
  var words: Int

  @Parameter(title: "Word list size", default: 7776)
  var wordListSize: Int

  static var parameterSummary: some ParameterSummary {
    Summary("Strength of a \(\.$words)-word passphrase")
  }

  func perform() async throws -> some IntentResult & ProvidesDialog {
    let count = min(max(words, 1), 24)
    let size = min(max(wordListSize, 64), 1_000_000)
    let bits = Double(count) * log2(Double(size))
    let tier: String
    if bits < 60 {
      tier = "weak for a long-lived vault"
    } else if bits < 80 {
      tier = "fair"
    } else if bits < 100 {
      tier = "strong"
    } else {
      tier = "very strong"
    }
    return .result(
      dialog: "\(count) words from a \(size)-word list is about \(Int(bits.rounded())) bits of entropy — \(tier)."
    )
  }
}

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
      intent: OpenVaultSectionIntent(),
      phrases: [
        "Open my recovery codes in \(.applicationName)",
        "Open the vault in \(.applicationName)",
      ],
      shortTitle: "Open a section",
      systemImageName: "lock.open"
    )
    AppShortcut(
      intent: RecoveryCodeCheckIntent(),
      phrases: [
        "Check a recovery code in \(.applicationName)",
        "Verify my recovery code in \(.applicationName)",
      ],
      shortTitle: "Check a code",
      systemImageName: "checkmark.shield"
    )
    AppShortcut(
      intent: PassphraseStrengthIntent(),
      phrases: [
        "How strong is my passphrase in \(.applicationName)",
        "Rate a passphrase in \(.applicationName)",
      ],
      shortTitle: "Passphrase strength",
      systemImageName: "key.horizontal"
    )
    AppShortcut(
      intent: RedoubtOpenIntent(),
      phrases: ["Open \(.applicationName)", "Launch \(.applicationName)"],
      shortTitle: "Open Redoubt",
      systemImageName: "shield.lefthalf.filled"
    )
  }
}
