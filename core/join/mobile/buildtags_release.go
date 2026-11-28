//go:build !hogman_mobile_debug

package mobile

// allowCustomControlCA is false in release builds so mobile apps trust only
// OS system root certificates.
const allowCustomControlCA = false
