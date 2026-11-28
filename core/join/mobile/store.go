package mobile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"tailscale.com/ipn"

	"hogman/join/internal/fsutil"
)

const (
	encryptedStoreFilename = "tailscaled.state.enc"
	encryptedAuthKeyFile   = "authkey.enc"
	stateEnvelopeVersion   = 1
)

type encryptedEnvelope struct {
	Version int               `json:"v"`
	Entries map[string]string `json:"entries"` // state key ID -> base64(nonce || ciphertext)
}

// EncryptedStateStore implements ipn.StateStore backed by an AES-256-GCM
// encrypted file keyed by a 32-byte device-bound DEK. Calling Close wipes the
// in-memory key slice.
type EncryptedStateStore struct {
	mu   sync.Mutex
	path string
	key  []byte
	aead cipher.AEAD
	data map[string][]byte
}

var _ ipn.StateStore = (*EncryptedStateStore)(nil)

// NewEncryptedStateStore opens (or initializes) an encrypted ipn.StateStore at
// <dir>/tailscaled.state.enc using a private copy of key (32 bytes).
func NewEncryptedStateStore(dir string, key []byte) (*EncryptedStateStore, error) {
	if err := validateStateKey(key); err != nil {
		return nil, err
	}
	keyCopy := make([]byte, StateKeyLen)
	copy(keyCopy, key)
	block, err := aes.NewCipher(keyCopy)
	if err != nil {
		clear(keyCopy)
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		clear(keyCopy)
		return nil, err
	}
	s := &EncryptedStateStore{
		path: filepath.Join(dir, encryptedStoreFilename),
		key:  keyCopy,
		aead: aead,
		data: make(map[string][]byte),
	}
	if err := s.loadLocked(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Close wipes the in-memory key and decrypted cache entries.
func (s *EncryptedStateStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.key)
	for k, v := range s.data {
		clear(v)
		delete(s.data, k)
	}
	s.aead = nil
}

func (s *EncryptedStateStore) loadLocked() error {
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read encrypted state: %w", err)
	}
	var env encryptedEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("decode encrypted state: %w", err)
	}
	if env.Version != stateEnvelopeVersion {
		return fmt.Errorf("unsupported encrypted state version %d", env.Version)
	}
	for id, enc := range env.Entries {
		plain, err := openGCM(s.aead, enc, []byte("hogman-state:"+id))
		if err != nil {
			return fmt.Errorf("decrypt state entry %q: %w", id, err)
		}
		s.data[id] = plain
	}
	return nil
}

func (s *EncryptedStateStore) persistLocked() error {
	if s.aead == nil {
		return errors.New("encrypted state store is closed")
	}
	env := encryptedEnvelope{
		Version: stateEnvelopeVersion,
		Entries: make(map[string]string, len(s.data)),
	}
	for id, plain := range s.data {
		enc, err := sealGCM(s.aead, plain, []byte("hogman-state:"+id))
		if err != nil {
			return err
		}
		env.Entries[id] = enc
	}
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.path, b, 0o600)
}

func (s *EncryptedStateStore) ReadState(id ipn.StateKey) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aead == nil {
		return nil, errors.New("encrypted state store is closed")
	}
	v, ok := s.data[string(id)]
	if !ok {
		return nil, ipn.ErrStateNotExist
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (s *EncryptedStateStore) WriteState(id ipn.StateKey, bs []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aead == nil {
		return errors.New("encrypted state store is closed")
	}
	k := string(id)
	if bs == nil {
		if prev, ok := s.data[k]; ok {
			clear(prev)
			delete(s.data, k)
		}
	} else {
		cp := make([]byte, len(bs))
		copy(cp, bs)
		if prev, ok := s.data[k]; ok {
			clear(prev)
		}
		s.data[k] = cp
	}
	return s.persistLocked()
}

func saveEncryptedSecret(path string, key, aad, plaintext []byte) error {
	if err := validateStateKey(key); err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	enc, err := sealGCM(aead, plaintext, aad)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, []byte(enc), 0o600)
}

func loadEncryptedSecret(path string, key, aad []byte) ([]byte, error) {
	if err := validateStateKey(key); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return openGCM(aead, string(raw), aad)
}

func sealGCM(aead cipher.AEAD, plaintext, aad []byte) (string, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, plaintext, aad)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func openGCM(aead cipher.AEAD, encoded string, aad []byte) ([]byte, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("corrupt ciphertext encoding")
	}
	ns := aead.NonceSize()
	if len(raw) < ns+aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	plain, err := aead.Open(nil, raw[:ns], raw[ns:], aad)
	if err != nil {
		return nil, errors.New("state authentication failed (wrong device key or corrupted state)")
	}
	return plain, nil
}
