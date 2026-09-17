import SwiftUI

enum GuardDestination: String, CaseIterable, Identifiable, Hashable {
    case guardHome = "Guard"
    case smish = "SmishGuard"
    case vish = "VishGuard"
    case phish = "PhishGuard"
    case recon = "Active Recon"
    case setup = "Setup"
    case settings = "Settings"

    var id: String { rawValue }

    var subtitle: String {
        switch self {
        case .guardHome: return "Home · Call Directory"
        case .smish: return "SMS text protection"
        case .vish: return "Voice call protection"
        case .phish: return "Email protection"
        case .recon: return "Screen a number now"
        case .setup: return "iPhone extensions"
        case .settings: return "API host · sign in"
        }
    }

    var systemImage: String {
        switch self {
        case .guardHome: return "shield.lefthalf.filled"
        case .smish: return "message.fill"
        case .vish: return "phone.fill"
        case .phish: return "envelope.fill"
        case .recon: return "viewfinder"
        case .setup: return "gearshape"
        case .settings: return "slider.horizontal.3"
        }
    }
}

/// Root shell: hamburger opens channel drawer (Guard / Smish / Vish / Phish).
struct RootShell: View {
    @State private var showMenu = false
    @State private var destination: GuardDestination = .guardHome
    @State private var isAuthenticated = APIService.shared.accessToken?.isEmpty == false

    var body: some View {
        Group {
            if isAuthenticated {
                authenticatedShell
            } else {
                LoginView {
                    isAuthenticated = true
                }
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: .npSignedOut)) { _ in
            isAuthenticated = false
        }
    }

    private var authenticatedShell: some View {
        ZStack(alignment: .leading) {
            NavigationStack {
                destinationView
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .topBarLeading) {
                            Button {
                                withAnimation(.easeOut(duration: 0.2)) { showMenu = true }
                            } label: {
                                Image(systemName: "line.3.horizontal")
                                    .font(.body.weight(.semibold))
                                    .foregroundStyle(NP.brass)
                                    .accessibilityLabel("Open menu")
                            }
                        }
                        ToolbarItem(placement: .principal) {
                            Text(destination.rawValue)
                                .font(.headline.weight(.semibold))
                                .foregroundStyle(NP.brass)
                        }
                    }
            }

            if showMenu {
                Color.black.opacity(0.45)
                    .ignoresSafeArea()
                    .onTapGesture {
                        withAnimation(.easeOut(duration: 0.2)) { showMenu = false }
                    }
                SideDrawer(selection: $destination, isOpen: $showMenu)
                    .transition(.move(edge: .leading))
                    .zIndex(2)
            }
        }
        .preferredColorScheme(.dark)
    }

    @ViewBuilder
    private var destinationView: some View {
        switch destination {
        case .guardHome, .recon:
            GuardHomeView(focusRecon: destination == .recon)
        case .smish:
            SmishGuardView()
        case .vish:
            VishGuardView()
        case .phish:
            PhishGuardView()
        case .setup:
            SetupGuideView()
        case .settings:
            GuardSettingsView()
        }
    }
}

private struct SideDrawer: View {
    @Binding var selection: GuardDestination
    @Binding var isOpen: Bool

    private let primary: [GuardDestination] = [
        .guardHome, .smish, .vish, .phish, .recon, .setup, .settings,
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("NULLPOINT")
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                        .tracking(2)
                        .foregroundStyle(NP.brass)
                    Text("Zero trust. Total visibility.")
                        .font(.caption)
                        .foregroundStyle(NP.muted)
                }
                Spacer()
                Button {
                    withAnimation(.easeOut(duration: 0.2)) { isOpen = false }
                } label: {
                    Image(systemName: "xmark")
                        .foregroundStyle(NP.muted)
                        .padding(8)
                }
                .accessibilityLabel("Close menu")
            }
            .padding(20)

            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(primary) { item in
                        Button {
                            selection = item
                            withAnimation(.easeOut(duration: 0.2)) { isOpen = false }
                        } label: {
                            HStack(spacing: 12) {
                                Image(systemName: item.systemImage)
                                    .frame(width: 22)
                                    .foregroundStyle(selection == item ? NP.brass : NP.muted)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(item.rawValue)
                                        .font(.body.weight(.semibold))
                                        .foregroundStyle(selection == item ? NP.text : NP.muted)
                                    Text(item.subtitle)
                                        .font(.caption2)
                                        .foregroundStyle(NP.muted)
                                }
                                Spacer()
                                if selection == item {
                                    Circle()
                                        .fill(NP.brass)
                                        .frame(width: 7, height: 7)
                                }
                            }
                            .padding(.horizontal, 16)
                            .padding(.vertical, 12)
                            .background(selection == item ? NP.panel2 : Color.clear)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }

            Spacer(minLength: 0)

            VStack(alignment: .leading, spacing: 8) {
                Text("Upgrade Pro")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(NP.brass)
                Text("Unlock advanced protection and intelligence.")
                    .font(.caption)
                    .foregroundStyle(NP.muted)
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(NP.panel2)
            .padding(16)
        }
        .frame(maxWidth: 300)
        .frame(maxHeight: .infinity)
        .background(NP.ink.opacity(0.98))
        .overlay(alignment: .leading) {
            Rectangle().fill(NP.brassDim).frame(width: 2)
        }
        .overlay(alignment: .trailing) {
            Rectangle().fill(NP.line).frame(width: 1)
        }
    }
}

private extension Notification.Name {
    static let npSignedOut = Notification.Name("NullPointGuard.signedOut")
}

private struct LoginView: View {
    let onSignedIn: () -> Void
    @State private var username = ""
    @State private var password = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        ZStack {
            NP.ink.ignoresSafeArea()
            VStack(alignment: .leading, spacing: 18) {
                Text("NULLPOINT")
                    .font(.system(size: 13, weight: .bold, design: .rounded))
                    .tracking(3)
                    .foregroundStyle(NP.brass)
                Text("Sign in")
                    .font(.system(size: 32, weight: .bold, design: .serif))
                    .foregroundStyle(NP.text)
                Text("Sign in to protect your calls, texts, and messages.")
                    .font(.subheadline)
                    .foregroundStyle(NP.muted)

                if let error {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(NP.danger)
                        .fixedSize(horizontal: false, vertical: true)
                }

                TextField("Username or email", text: $username)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.emailAddress)
                    .textFieldStyle(.plain)
                    .padding(13)
                    .background(NP.panel)
                    .overlay(Rectangle().stroke(NP.line, lineWidth: 1))

                SecureField("Password", text: $password)
                    .textFieldStyle(.plain)
                    .padding(13)
                    .background(NP.panel)
                    .overlay(Rectangle().stroke(NP.line, lineWidth: 1))

                Button {
                    Task { await signIn() }
                } label: {
                    HStack {
                        Spacer()
                        if busy { ProgressView().tint(NP.ink) }
                        Text(busy ? "Signing in…" : "Continue")
                            .font(.headline.weight(.semibold))
                        Spacer()
                    }
                    .padding(.vertical, 14)
                    .background(NP.signal)
                    .foregroundStyle(NP.ink)
                }
                .disabled(busy || username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || password.isEmpty)

                Text("Create your account at nullpointvector.com/app/signup.")
                    .font(.caption)
                    .foregroundStyle(NP.muted)
            }
            .padding(24)
            .frame(maxWidth: 460)
            .background(NP.panel)
            .overlay(Rectangle().stroke(NP.brassDim, lineWidth: 1))
            .padding(20)
        }
        .preferredColorScheme(.dark)
    }

    private func signIn() async {
        busy = true
        error = nil
        do {
            try await APIService.shared.login(username: username, password: password)
            onSignedIn()
        } catch let signInError {
            error = signInError.localizedDescription
        }
        busy = false
    }
}
