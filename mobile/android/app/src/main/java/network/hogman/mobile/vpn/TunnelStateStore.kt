package network.hogman.mobile.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import network.hogman.mobile.core.TunnelStatus

data class TunnelUiSnapshot(
    val status: TunnelStatus = TunnelStatus.Disconnected,
    val privateDnsHostname: String? = null,
    val lockdownActive: Boolean = false,
    val lastError: String? = null,
)

object TunnelStateStore {
    private val _state = MutableStateFlow(TunnelUiSnapshot())
    val state: StateFlow<TunnelUiSnapshot> = _state.asStateFlow()

    fun updateStatus(status: TunnelStatus) {
        _state.update { cur ->
            val err = when (status.state) {
                "error", "removed" -> status.error.ifBlank { cur.lastError }
                "connected" -> null
                else -> cur.lastError
            }
            cur.copy(status = status, lastError = err)
        }
    }

    fun updateNetworkFlags(privateDnsHostname: String?, lockdownActive: Boolean) {
        _state.update { it.copy(privateDnsHostname = privateDnsHostname, lockdownActive = lockdownActive) }
    }

    fun setError(message: String?) {
        _state.update { it.copy(lastError = message) }
    }
}
