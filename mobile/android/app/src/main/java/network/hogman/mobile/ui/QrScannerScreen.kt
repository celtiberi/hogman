package network.hogman.mobile.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

@Composable
fun QrScannerScreen(
    onScanned: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    var cameraError by remember { mutableStateOf<String?>(null) }

    val permLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
    ) { granted ->
        hasCameraPermission = granted
        if (!granted) {
            cameraError = "Camera permission is needed to scan a QR code. You can also paste the link manually."
        }
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            permLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(HogmanColors.Background),
    ) {
        if (hasCameraPermission && cameraError == null) {
            val analyzerExecutor = remember { Executors.newSingleThreadExecutor() }
            val delivered = remember { AtomicBoolean(false) }

            DisposableEffect(Unit) {
                onDispose { analyzerExecutor.shutdown() }
            }

            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { ctx ->
                    val previewView = PreviewView(ctx)
                    val providerFuture = ProcessCameraProvider.getInstance(ctx)
                    providerFuture.addListener(
                        {
                            try {
                                val provider = providerFuture.get()
                                val preview = Preview.Builder().build().also {
                                    it.surfaceProvider = previewView.surfaceProvider
                                }
                                val analysis = ImageAnalysis.Builder()
                                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                                    .build()
                                val reader = MultiFormatReader().apply {
                                    setHints(
                                        mapOf(
                                            DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
                                        ),
                                    )
                                }
                                analysis.setAnalyzer(analyzerExecutor) { proxy ->
                                    decodeQr(reader, proxy)?.let { text ->
                                        if (delivered.compareAndSet(false, true)) {
                                            previewView.post { onScanned(text) }
                                        }
                                    }
                                    proxy.close()
                                }
                                provider.unbindAll()
                                provider.bindToLifecycle(
                                    lifecycleOwner,
                                    CameraSelector.DEFAULT_BACK_CAMERA,
                                    preview,
                                    analysis,
                                )
                            } catch (t: Throwable) {
                                cameraError = t.message ?: "Could not open camera."
                            }
                        },
                        ContextCompat.getMainExecutor(ctx),
                    )
                    previewView
                },
            )

            Box(
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .fillMaxWidth()
                    .background(HogmanColors.Background.copy(alpha = 0.85f))
                    .padding(20.dp),
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(
                        text = "Point at the QR code on home.<pen> or an invite.",
                        color = HogmanColors.Ink,
                    )
                    OutlinedButton(
                        onClick = onCancel,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Cancel")
                    }
                }
            }
        } else {
            Column(
                modifier = Modifier
                    .align(Alignment.Center)
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    text = cameraError ?: "Waiting for camera permission…",
                    color = HogmanColors.Ink,
                )
                if (!hasCameraPermission) {
                    Button(onClick = { permLauncher.launch(Manifest.permission.CAMERA) }) {
                        Text("Grant camera permission")
                    }
                }
                OutlinedButton(onClick = onCancel) {
                    Text("Back to paste link")
                }
            }
        }
    }
}

private fun decodeQr(reader: MultiFormatReader, image: ImageProxy): String? {
    val plane = image.planes.firstOrNull() ?: return null
    val buf = plane.buffer
    val bytes = ByteArray(buf.remaining())
    buf.get(bytes)
    val width = image.width
    val height = image.height
    return try {
        val source = PlanarYUVLuminanceSource(
            bytes,
            plane.rowStride,
            height,
            0,
            0,
            width,
            height,
            false,
        )
        reader.decodeWithState(BinaryBitmap(HybridBinarizer(source)))?.text
    } catch (_: Throwable) {
        null
    } finally {
        reader.reset()
    }
}
