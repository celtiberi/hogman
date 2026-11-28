import AVFoundation
import SwiftUI

struct QrScannerSheet: View {
    let onScanned: (String) -> Void
    let onCancel: () -> Void

    @State private var cameraError: String?

    var body: some View {
        ZStack(alignment: .bottom) {
            Color(hex: 0x0E080C).ignoresSafeArea()

            if let cameraError {
                VStack(spacing: 16) {
                    Text(cameraError)
                        .foregroundColor(Color(hex: 0xF3E6D3))
                        .multilineTextAlignment(.center)
                    Button("Back to paste link", action: onCancel)
                        .buttonStyle(.bordered)
                }
                .padding(24)
            } else {
                CameraPreviewRepresentable(
                    onScanned: onScanned,
                    onError: { cameraError = $0 }
                )
                .ignoresSafeArea()

                VStack(spacing: 12) {
                    Text("Point at the QR code on home.<pen> or an invite.")
                        .font(.subheadline)
                        .foregroundColor(Color(hex: 0xF3E6D3))
                        .multilineTextAlignment(.center)
                    Button("Cancel", action: onCancel)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(Color(hex: 0x1F131B))
                        .foregroundColor(Color(hex: 0xF3E6D3))
                        .cornerRadius(8)
                }
                .padding(20)
                .background(Color(hex: 0x0E080C).opacity(0.88))
            }
        }
    }
}

private struct CameraPreviewRepresentable: UIViewControllerRepresentable {
    let onScanned: (String) -> Void
    let onError: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let vc = ScannerViewController()
        vc.onScanned = onScanned
        vc.onError = onError
        return vc
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {}
}

private final class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onScanned: ((String) -> Void)?
    var onError: ((String) -> Void)?

    private let session = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var delivered = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            configureSession()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    if granted {
                        self?.configureSession()
                    } else {
                        self?.onError?("Camera permission is needed to scan QR codes. You can also paste the link manually.")
                    }
                }
            }
        default:
            onError?("Camera access is disabled in iOS Settings. You can paste the link manually instead.")
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.session.stopRunning()
            }
        }
    }

    private func configureSession() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else {
            onError?("Camera is not available on this device. Use Paste link instead.")
            return
        }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else {
            onError?("Could not initialize QR scanner output.")
            return
        }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.addSublayer(preview)
        previewLayer = preview

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.session.startRunning()
        }
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !delivered,
              let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let value = obj.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.isEmpty else {
            return
        }
        delivered = true
        session.stopRunning()
        onScanned?(value)
    }
}
