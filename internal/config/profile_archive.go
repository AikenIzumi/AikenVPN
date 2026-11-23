package config

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	profileArchiveMagic = "AikenVPN-Archive-v1\n"
	archiveSaltSize     = 16
	MaxProfileArchive   = 16 << 20
)

func SaveProfileArchive(path string, profiles []Profile, password string) error {
	data, err := EncryptProfileArchive(profiles, password)
	if err != nil {
		return err
	}
	return writeConfigFile(path, data)
}

func EncryptProfileArchive(profiles []Profile, password string) ([]byte, error) {
	if len(password) > 1024 || utf8.RuneCountInString(password) < 12 {
		return nil, errors.New("Используйте пароль от 12 символов, не длиннее 1024 байт")
	}
	if len(profiles) == 0 {
		return nil, errors.New("Нет профилей для резервной копии")
	}
	plaintext, err := json.Marshal(profiles)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)

	header := make([]byte, len(profileArchiveMagic)+archiveSaltSize)
	copy(header, profileArchiveMagic)
	salt := header[len(profileArchiveMagic):]
	rand.Read(salt)
	aead, err := profileArchiveCipher(password, salt)
	if err != nil {
		return nil, err
	}
	if len(header)+len(plaintext)+aead.Overhead() > MaxProfileArchive {
		return nil, errors.New("Архив превышает 16 МиБ")
	}
	return aead.Seal(bytes.Clone(header), nil, plaintext, header), nil
}

func DecryptProfileArchive(data []byte, password string) ([]Profile, error) {
	headerLength := len(profileArchiveMagic) + archiveSaltSize
	if len(data) <= headerLength || len(data) > MaxProfileArchive || !bytes.HasPrefix(data, []byte(profileArchiveMagic)) {
		return nil, errors.New("Неподдерживаемый или повреждённый архив AikenVPN")
	}
	if password == "" || len(password) > 1024 {
		return nil, errors.New("Введите пароль архива")
	}
	header, payload := data[:headerLength], data[headerLength:]
	aead, err := profileArchiveCipher(password, header[len(profileArchiveMagic):])
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nil, payload, header)
	if err != nil {
		return nil, errors.New("Неверный пароль или повреждённый архив")
	}
	defer clear(plaintext)

	var profiles []Profile
	if err := json.Unmarshal(plaintext, &profiles); err != nil || len(profiles) == 0 {
		return nil, errors.New("Архив не содержит корректного списка профилей")
	}
	seen := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		_, duplicate := seen[profile.ID]
		if profile.ID == "" || duplicate {
			return nil, errors.New("Архив содержит пустые или повторяющиеся идентификаторы профилей")
		}
		seen[profile.ID] = struct{}{}
	}
	return profiles, nil
}

func profileArchiveCipher(password string, salt []byte) (cipher.AEAD, error) {
	passwordBytes := []byte(password)
	defer clear(passwordBytes)
	// RFC 9106's recommended parameters for memory-constrained environments.
	key := argon2.IDKey(passwordBytes, salt, 3, 64*1024, 4, 32)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}
