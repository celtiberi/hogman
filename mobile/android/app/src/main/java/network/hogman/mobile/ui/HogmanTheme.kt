package network.hogman.mobile.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

object HogmanColors {
    val Background = Color(0xFF0E080C)
    val Surface = Color(0xFF1F131B)
    val SurfaceWell = Color(0xFF140C11)
    val Border = Color(0xFF3A2A33)
    val Ink = Color(0xFFF3E6D3)
    val InkMuted = Color(0xFFB9A79A)
    val Accent = Color(0xFFFFC233)
    val AccentHot = Color(0xFFFF6A1A)
    val Ok = Color(0xFF8FD16A)
    val OkBg = Color(0xFF142A18)
    val WarnBg = Color(0xFF2E2210)
    val Danger = Color(0xFFFF7A7A)
    val DangerBg = Color(0xFF311319)
}

private val HogmanDarkScheme = darkColorScheme(
    primary = HogmanColors.AccentHot,
    onPrimary = Color(0xFF1A0A04),
    secondary = HogmanColors.Accent,
    onSecondary = Color(0xFF1A0A04),
    background = HogmanColors.Background,
    onBackground = HogmanColors.Ink,
    surface = HogmanColors.Surface,
    onSurface = HogmanColors.Ink,
    surfaceVariant = HogmanColors.SurfaceWell,
    onSurfaceVariant = HogmanColors.InkMuted,
    outline = HogmanColors.Border,
    error = HogmanColors.Danger,
    onError = Color(0xFF1A0508),
)

@Composable
fun HogmanTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = HogmanDarkScheme,
        content = content,
    )
}
