import SwiftUI
import UIKit

extension Color {
    init(hex: UInt32) {
        self.init(
            red: Double((hex >> 16) & 0xFF) / 255.0,
            green: Double((hex >> 8) & 0xFF) / 255.0,
            blue: Double(hex & 0xFF) / 255.0
        )
    }
}

private enum HogmanPalette {
    static let bg = Color(hex: 0x0E080C)
    static let surface = Color(hex: 0x1F131B)
    static let well = Color(hex: 0x140C11)
    static let border = Color(hex: 0x3A2A33)
    static let ink = Color(hex: 0xF3E6D3)
    static let muted = Color(hex: 0xB9A79A)
    static let accent = Color(hex: 0xFFC233)
    static let accentHot = Color(hex: 0xFF6A1A)
    static let ok = Color(hex: 0x8FD16A)
    static let danger = Color(hex: 0xFF7A7A)
    static let dangerBg = Color(hex: 0x311319)
}

struct ContentView: View {
    @StateObject private var manager = TunnelManager()
    @Environment(\.openURL) private var openURL

    @State private var showJoinSheet = false
    @State private var leaveTarget: PenMeta?

    var body: some View {
        NavigationStack {
            ZStack {
                HogmanPalette.bg.ignoresSafeArea()

                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        HStack(spacing: 8) {
                            Text("HOGMAN")
                                .font(.title2.weight(.black))
                                .foregroundColor(HogmanPalette.ink)
                            Text("MOBILE")
                                .font(.caption2.bold())
                                .foregroundColor(HogmanPalette.accent)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(HogmanPalette.surface)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 4)
                                        .stroke(HogmanPalette.border, lineWidth: 1)
                                )
                            Spacer()
                        }

                        activeCard

                        if let err = manager.errorMessage, !err.isEmpty {
                            HStack(alignment: .top, spacing: 10) {
                                Text(err)
                                    .font(.footnote)
                                    .foregroundColor(HogmanPalette.ink)
                                Spacer()
                                Button("Dismiss") {
                                    manager.errorMessage = nil
                                }
                                .font(.footnote.bold())
                                .foregroundColor(HogmanPalette.danger)
                            }
                            .padding(14)
                            .background(HogmanPalette.dangerBg)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(HogmanPalette.danger, lineWidth: 1)
                            )
                            .cornerRadius(10)
                        }

                        HStack {
                            Text("Enrolled pens")
                                .font(.headline)
                                .foregroundColor(HogmanPalette.ink)
                            Spacer()
                            Button {
                                showJoinSheet = true
                            } label: {
                                Text("Join a pen")
                                    .font(.subheadline.bold())
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 8)
                                    .background(HogmanPalette.accentHot)
                                    .foregroundColor(Color(hex: 0x1A0A04))
                                    .cornerRadius(18)
                            }
                        }
                        .padding(.top, 6)

                        if manager.pens.isEmpty {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("No pens enrolled on this device yet.")
                                    .font(.subheadline.weight(.semibold))
                                    .foregroundColor(HogmanPalette.ink)
                                Text("Scan a QR code from home.<pen> or paste an invite or device link to join.")
                                    .font(.footnote)
                                    .foregroundColor(HogmanPalette.muted)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(16)
                            .background(HogmanPalette.surface)
                            .overlay(
                                RoundedRectangle(cornerRadius: 12)
                                    .stroke(HogmanPalette.border, lineWidth: 1)
                            )
                            .cornerRadius(12)
                        } else {
                            ForEach(manager.pens) { pen in
                                penRow(pen)
                            }
                        }
                    }
                    .padding(16)
                }
            }
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Join pen") {
                        showJoinSheet = true
                    }
                    .foregroundColor(HogmanPalette.accent)
                }
            }
            .toolbarBackground(HogmanPalette.bg, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .preferredColorScheme(.dark)
        }
        .task {
            await manager.bootstrap()
        }
        .sheet(isPresented: $showJoinSheet) {
            JoinPenSheet(manager: manager) { joined in
                showJoinSheet = false
                Task {
                    await manager.connect(zone: joined.zone)
                }
            }
        }
        .sheet(item: $leaveTarget) { pen in
            LeavePenSheet(
                pen: pen,
                isConnected: manager.status.state == "connected" && manager.status.zone == pen.zone,
                manager: manager,
                onDone: { leaveTarget = nil }
            )
        }
    }

    private var activeCard: some View {
        let dotColor: Color = {
            switch manager.status.state {
            case "connected": return HogmanPalette.ok
            case "connecting": return HogmanPalette.accent
            case "removed", "error": return HogmanPalette.danger
            default: return HogmanPalette.muted
            }
        }()
        let label: String = {
            switch manager.status.state {
            case "connected": return "Connected"
            case "connecting": return "Connecting…"
            case "removed": return "Removed from pen"
            case "error": return "Error"
            default: return "Disconnected"
            }
        }()

        return VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Circle()
                    .fill(dotColor)
                    .frame(width: 10, height: 10)
                Text(label)
                    .font(.subheadline.bold())
                    .foregroundColor(dotColor)
            }

            if let zone = manager.status.zone, !zone.isEmpty {
                Text(zone)
                    .font(.system(.headline, design: .monospaced).bold())
                    .foregroundColor(HogmanPalette.ink)
            } else {
                Text(manager.pens.isEmpty ? "Ready to join a pen" : "Select a pen below to connect")
                    .font(.headline)
                    .foregroundColor(HogmanPalette.ink)
            }

            if manager.status.state == "connected", let selfIP = manager.status.selfIpv4, !selfIP.isEmpty {
                let routeCount = manager.status.peerRoutes?.count ?? 0
                Text("Device \(selfIP) · \(routeCount) split /32 route(s) · Regular internet untouched")
                    .font(.caption)
                    .foregroundColor(HogmanPalette.muted)
            }

            HStack(spacing: 10) {
                if manager.status.isActive {
                    Button {
                        manager.disconnect()
                    } label: {
                        Text("Disconnect")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .overlay(
                                RoundedRectangle(cornerRadius: 18)
                                    .stroke(HogmanPalette.border, lineWidth: 1)
                            )
                            .foregroundColor(HogmanPalette.ink)
                    }
                    if manager.status.state == "connected",
                       let zone = manager.status.zone,
                       let url = URL(string: manager.status.portal ?? "https://home.\(zone)") {
                        Button {
                            openURL(url)
                        } label: {
                            Text("Open Home")
                                .font(.subheadline.bold())
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 10)
                                .background(HogmanPalette.accent)
                                .foregroundColor(Color(hex: 0x1A0A04))
                                .cornerRadius(18)
                        }
                    }
                } else if manager.pens.count == 1, let only = manager.pens.first {
                    Button {
                        Task { await manager.connect(zone: only.zone) }
                    } label: {
                        Text("Connect to \(only.zone)")
                            .font(.subheadline.bold())
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(HogmanPalette.accentHot)
                            .foregroundColor(Color(hex: 0x1A0A04))
                            .cornerRadius(18)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(HogmanPalette.surface)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(manager.status.state == "connected" ? HogmanPalette.ok : HogmanPalette.border, lineWidth: 1.5)
        )
        .cornerRadius(12)
    }

    private func penRow(_ pen: PenMeta) -> some View {
        let isActive = manager.status.isActive && manager.status.zone == pen.zone
        let isConnected = manager.status.state == "connected" && manager.status.zone == pen.zone

        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(pen.zone)
                        .font(.system(.subheadline, design: .monospaced).bold())
                        .foregroundColor(HogmanPalette.ink)
                    let details = [
                        pen.handle.flatMap { $0.isEmpty ? nil : "@\($0)" },
                        pen.hostname.isEmpty ? nil : pen.hostname,
                    ].compactMap { $0 }.joined(separator: " · ")
                    if !details.isEmpty {
                        Text(details)
                            .font(.caption)
                            .foregroundColor(HogmanPalette.muted)
                    }
                }
                Spacer()
                Button("Leave") {
                    leaveTarget = pen
                }
                .font(.footnote.bold())
                .foregroundColor(HogmanPalette.danger)
            }

            HStack(spacing: 10) {
                if isActive {
                    Button("Disconnect") {
                        manager.disconnect()
                    }
                    .buttonStyle(.bordered)
                } else {
                    Button {
                        Task { await manager.connect(zone: pen.zone) }
                    } label: {
                        Text("Connect")
                            .font(.subheadline.bold())
                            .padding(.horizontal, 14)
                            .padding(.vertical, 7)
                            .background(HogmanPalette.accentHot)
                            .foregroundColor(Color(hex: 0x1A0A04))
                            .cornerRadius(16)
                    }
                }
                if isConnected, let url = URL(string: pen.portal.isEmpty ? "https://home.\(pen.zone)" : pen.portal) {
                    Button("Open Home") {
                        openURL(url)
                    }
                    .foregroundColor(HogmanPalette.accent)
                    .buttonStyle(.bordered)
                }
            }
        }
        .padding(14)
        .background(HogmanPalette.well)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(isConnected ? HogmanPalette.ok : HogmanPalette.border, lineWidth: 1)
        )
        .cornerRadius(12)
    }
}

private struct JoinPenSheet: View {
    @ObservedObject var manager: TunnelManager
    let onJoined: (PenMeta) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var rawLink = ""
    @State private var pastedFromClipboard = false
    @State private var parsed: ParsedLink?
    @State private var parseErr: String?
    @State private var handle = ""
    @State private var deviceName = defaultIOSDeviceName()
    @State private var submitErr: String?
    @State private var submitting = false
    @State private var showScanner = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack(spacing: 12) {
                        Button("Scan QR") {
                            showScanner = true
                        }
                        .buttonStyle(.bordered)
                        .disabled(submitting)

                        Button("Paste link") {
                            if let clip = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines),
                               !clip.isEmpty {
                                rawLink = clip
                                pastedFromClipboard = true
                                submitErr = nil
                            } else {
                                submitErr = "Clipboard is empty."
                            }
                        }
                        .buttonStyle(.bordered)
                        .disabled(submitting)
                    }

                    TextField("Join or invite link", text: $rawLink)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .disabled(submitting)
                        .onChange(of: rawLink) { newVal in
                            validate(newVal)
                        }

                    if let parsed {
                        Text(parsed.kind == "invite" ? "Invite link for \(parsed.host)" : "One-time device link for \(parsed.host)")
                            .font(.caption)
                            .foregroundColor(HogmanPalette.ok)
                    } else if let parseErr {
                        Text(parseErr)
                            .font(.caption)
                            .foregroundColor(HogmanPalette.danger)
                    }
                }

                if parsed?.kind == "invite" {
                    Section("Member handle") {
                        TextField("e.g. alice", text: $handle)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .disabled(submitting)
                    }
                }

                Section("Device name") {
                    TextField("iphone", text: $deviceName)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .disabled(submitting)
                }

                if let submitErr {
                    Section {
                        Text(submitErr)
                            .font(.caption)
                            .foregroundColor(HogmanPalette.danger)
                    }
                }
            }
            .navigationTitle("Join a pen")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .disabled(submitting)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(submitting ? "Joining…" : "Join") {
                        submit()
                    }
                    .disabled(submitting || parsed == nil || (parsed?.kind == "invite" && handle.trimmingCharacters(in: .whitespaces).isEmpty))
                }
            }
        }
        .preferredColorScheme(.dark)
        .fullScreenCover(isPresented: $showScanner) {
            QrScannerSheet(
                onScanned: { text in
                    rawLink = text
                    showScanner = false
                    validate(text)
                },
                onCancel: {
                    showScanner = false
                }
            )
        }
    }

    private func validate(_ text: String) {
        submitErr = nil
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            parsed = nil
            parseErr = nil
            return
        }
        switch manager.parseLink(trimmed) {
        case .success(let p):
            parsed = p
            parseErr = nil
        case .failure(let err):
            parsed = nil
            parseErr = err.localizedDescription
        }
    }

    private func submit() {
        submitting = true
        submitErr = nil
        let linkCopy = rawLink.trimmingCharacters(in: .whitespacesAndNewlines)
        let handleCopy = handle.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let devCopy = deviceName.trimmingCharacters(in: .whitespacesAndNewlines)

        Task {
            do {
                let meta = try await manager.join(rawLink: linkCopy, handle: handleCopy, deviceName: devCopy)
                if pastedFromClipboard {
                    UIPasteboard.general.items = []
                }
                submitting = false
                onJoined(meta)
            } catch {
                submitting = false
                submitErr = error.localizedDescription
            }
        }
    }
}

private struct LeavePenSheet: View {
    let pen: PenMeta
    let isConnected: Bool
    @ObservedObject var manager: TunnelManager
    let onDone: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var needForceConfirm: Bool
    @State private var typedZone = ""
    @State private var errMsg: String?
    @State private var leaving = false

    init(pen: PenMeta, isConnected: Bool, manager: TunnelManager, onDone: @escaping () -> Void) {
        self.pen = pen
        self.isConnected = isConnected
        self.manager = manager
        self.onDone = onDone
        _needForceConfirm = State(initialValue: !isConnected)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(
                        needForceConfirm
                        ? "Force-leaving deletes local keys on this device even if the pen cannot be reached (or if this is your last owner device). Type \(pen.zone) to confirm."
                        : "This removes this device from \(pen.zone) and deletes its local keys."
                    )
                    .font(.footnote)
                    .foregroundColor(HogmanPalette.muted)
                }

                if needForceConfirm {
                    Section("Confirm pen name") {
                        TextField(pen.zone, text: $typedZone)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .disabled(leaving)
                    }
                }

                if let errMsg {
                    Section {
                        Text(errMsg)
                            .font(.caption)
                            .foregroundColor(HogmanPalette.danger)
                    }
                }
            }
            .navigationTitle("Leave \(pen.zone)?")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .disabled(leaving)
                }
                ToolbarItem(placement: .destructiveAction) {
                    Button(leaving ? "Leaving…" : (needForceConfirm ? "Force leave" : "Leave"), role: .destructive) {
                        submit()
                    }
                    .disabled(leaving || (needForceConfirm && typedZone.trimmingCharacters(in: .whitespacesAndNewlines) != pen.zone))
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private func submit() {
        leaving = true
        errMsg = nil
        let force = needForceConfirm
        Task {
            do {
                try await manager.leave(zone: pen.zone, force: force)
                leaving = false
                onDone()
            } catch {
                leaving = false
                errMsg = error.localizedDescription
                needForceConfirm = true
            }
        }
    }
}

private func defaultIOSDeviceName() -> String {
    let raw = UIDevice.current.name.lowercased()
    let allowed = raw.map { ch -> Character in
        (ch.isASCII && (ch.isLetter || ch.isNumber || ch == "-")) ? ch : "-"
    }
    let collapsed = String(allowed)
        .split(separator: "-")
        .joined(separator: "-")
    return collapsed.isEmpty ? "iphone" : String(collapsed.prefix(32))
}
