//go:build hogman_mobile_debug

package mobile

// allowCustomControlCA is enabled only in debug/staging builds compiled with
// -tags hogman_mobile_debug for local test-CA harnesses.
const allowCustomControlCA = true
