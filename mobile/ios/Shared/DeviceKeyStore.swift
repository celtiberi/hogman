import Foundation
import Security

/// Manages the non-cloneable 32-byte per-device state encryption key (DEK) and
/// backup-excluded shared App Group data directory.
public enum DeviceKeyStore {
    public static let appGroupID = "group.network.hogman.mobile"
    private static let keychainService = "network.hogman.mobile.statekey"
    private static let keychainAccount = "hogman_state_dek_v1"
    private static let dekLength = 32
    private static let lock = NSLock()

    /// Returns the backup-excluded directory storing encrypted pen state.
    /// Uses the shared App Group container when provisioned, falling back to
    /// Application Support for unsigned Simulator builds.
    public static func dataDir() throws -> String {
        let fm = FileManager.default
        let baseURL: URL
        if let groupURL = fm.containerURL(forSecurityApplicationGroupIdentifier: appGroupID) {
            baseURL = groupURL
        } else if let appSupport = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            baseURL = appSupport
        } else {
            throw HogmanError.storage("Unable to resolve app storage directory.")
        }

        var dirURL = baseURL.appendingPathComponent("hogman-data", isDirectory: true)
        try fm.createDirectory(at: dirURL, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try dirURL.setResourceValues(values)
        return dirURL.path
    }

    /// Loads (or creates) the 32-byte device-bound DEK, passes a raw pointer to
    /// `body`, and explicitly zeroes the temporary key buffer before returning.
    public static func withStateKey<T>(_ body: (UnsafePointer<UInt8>, Int) throws -> T) throws -> T {
        var key = try loadOrCreateDEK()
        defer {
            for i in key.indices {
                key[i] = 0
            }
        }
        guard key.count == dekLength else {
            throw HogmanError.storage("Invalid device key length \(key.count).")
        }
        return try key.withUnsafeBufferPointer { buf in
            guard let base = buf.baseAddress else {
                throw HogmanError.storage("Empty device key buffer.")
            }
            return try body(base, buf.count)
        }
    }

    private static func loadOrCreateDEK() throws -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }

        if let existing = try queryKeychain() {
            return existing
        }

        var dek = [UInt8](repeating: 0, count: dekLength)
        let rc = SecRandomCopyBytes(kSecRandomDefault, dekLength, &dek)
        guard rc == errSecSuccess else {
            throw HogmanError.keychain(rc)
        }
        do {
            try saveKeychain(dek)
            return dek
        } catch {
            for i in dek.indices { dek[i] = 0 }
            throw error
        }
    }

    private static func baseQuery() -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
        if let accessGroup = Bundle.main.object(forInfoDictionaryKey: "HogmanKeychainAccessGroup") as? String,
           !accessGroup.isEmpty,
           !accessGroup.contains("$(") {
            q[kSecAttrAccessGroup as String] = accessGroup
        }
        return q
    }

    private static func queryKeychain() throws -> [UInt8]? {
        var q = baseQuery()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = item as? Data else {
            throw HogmanError.keychain(status)
        }
        guard data.count == dekLength else {
            throw HogmanError.storage("Corrupted device key length in Keychain.")
        }
        return [UInt8](data)
    }

    private static func saveKeychain(_ dek: [UInt8]) throws {
        var attrs = baseQuery()
        attrs[kSecValueData as String] = Data(dek)
        // Non-cloneable: stays bound to this physical device and never migrates
        // via iCloud Keychain or encrypted device backups.
        attrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let status = SecItemAdd(attrs as CFDictionary, nil)
        if status == errSecDuplicateItem {
            return
        }
        guard status == errSecSuccess else {
            throw HogmanError.keychain(status)
        }
    }
}
