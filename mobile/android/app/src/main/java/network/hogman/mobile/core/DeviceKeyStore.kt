package network.hogman.mobile.core

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Manages the non-cloneable 32-byte per-device state encryption key (DEK).
 *
 * The DEK is randomly generated on-device, wrapped with a non-exportable
 * Android Keystore AES-256-GCM key, and stored under [Context.getNoBackupFilesDir]
 * so it is never included in cloud backups or device-to-device transfers.
 */
object DeviceKeyStore {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEK_ALIAS = "hogman_state_kek_v1"
    private const val DEK_FILENAME = "hogman_dek.bin"
    private const val DATA_DIR_NAME = "hogman-data"
    private const val DEK_BYTES = 32
    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BITS = 128

    private val lock = Any()

    fun dataDir(context: Context): String {
        val dir = File(context.noBackupFilesDir, DATA_DIR_NAME)
        if (!dir.exists()) {
            dir.mkdirs()
        }
        return dir.absolutePath
    }

    /**
     * Unwraps the 32-byte DEK into a temporary [ByteArray], invokes [block],
     * and zeroes the buffer in a finally block before returning.
     */
    fun <T> withStateKey(context: Context, block: (ByteArray) -> T): T {
        val dek = loadOrCreateDek(context)
        try {
            return block(dek)
        } finally {
            dek.fill(0)
        }
    }

    private fun loadOrCreateDek(context: Context): ByteArray = synchronized(lock) {
        val kek = getOrCreateKek()
        val file = File(context.noBackupFilesDir, DEK_FILENAME)
        if (file.exists()) {
            return unwrapDek(kek, file.readBytes())
        }
        val dek = ByteArray(DEK_BYTES)
        SecureRandom().nextBytes(dek)
        try {
            val wrapped = wrapDek(kek, dek)
            writeAtomic(file, wrapped)
            return dek.copyOf()
        } finally {
            dek.fill(0)
        }
    }

    private fun getOrCreateKek(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val existing = ks.getKey(KEK_ALIAS, null) as? SecretKey
        if (existing != null) {
            return existing
        }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        fun buildSpec(strongBox: Boolean): KeyGenParameterSpec =
            KeyGenParameterSpec.Builder(
                KEK_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .apply {
                    if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setIsStrongBoxBacked(true)
                    }
                }
                .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                gen.init(buildSpec(strongBox = true))
                return gen.generateKey()
            } catch (_: StrongBoxUnavailableException) {
                // Fall back to standard TEE-backed Android Keystore when StrongBox is absent.
            } catch (_: Exception) {
                // Some devices throw ProviderException instead of StrongBoxUnavailableException.
            }
        }
        gen.init(buildSpec(strongBox = false))
        return gen.generateKey()
    }

    private fun wrapDek(kek: SecretKey, dek: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, kek)
        val iv = cipher.iv
        require(iv.size == GCM_IV_BYTES) { "unexpected Keystore GCM IV size ${iv.size}" }
        val ciphertext = cipher.doFinal(dek)
        val out = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, out, 0, iv.size)
        System.arraycopy(ciphertext, 0, out, iv.size, ciphertext.size)
        return out
    }

    private fun unwrapDek(kek: SecretKey, blob: ByteArray): ByteArray {
        require(blob.size > GCM_IV_BYTES + 16) { "corrupted wrapped device key blob" }
        val iv = blob.copyOfRange(0, GCM_IV_BYTES)
        val ciphertext = blob.copyOfRange(GCM_IV_BYTES, blob.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, kek, GCMParameterSpec(GCM_TAG_BITS, iv))
        val dek = cipher.doFinal(ciphertext)
        require(dek.size == DEK_BYTES) { "unexpected device key length ${dek.size}" }
        return dek
    }

    private fun writeAtomic(dest: File, bytes: ByteArray) {
        val parent = dest.parentFile ?: error("missing parent directory")
        if (!parent.exists()) {
            parent.mkdirs()
        }
        val tmp = File(parent, "${dest.name}.tmp")
        FileOutputStream(tmp).use { out ->
            out.write(bytes)
            out.fd.sync()
        }
        if (!tmp.renameTo(dest)) {
            tmp.delete()
            error("failed to persist wrapped device key atomically")
        }
    }
}
