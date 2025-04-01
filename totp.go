package totp

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"hash"
	"sync"
	"time"
	"unicode"
)

// TOTP generates time-based one-time passwords.
type TOTP struct {
	cfg           Config     // Configuration.
	divisor       int64      // Divisor for TOTP code calculation.
	timeBytesPool *sync.Pool // Pool for time byte arrays.
	hmacPool      *sync.Pool // Pool for HMAC instances.
	decodedSecret []byte     // Decoded secret key.
}

// hmacHolder helps reuse HMAC instances efficiently.
type hmacHolder struct {
	h hash.Hash
}

// New initializes a TOTP generator with the given configuration.
func New(config ...Config) *TOTP {
	cfg := configDefault(config...)

	decodedSecret, err := base32.StdEncoding.DecodeString(cfg.Secret)
	if err != nil {
		panic(fmt.Sprintf("failed to decode Base32 secret: %v", err))
	}

	divisor := int64(1)
	for i := 0; i < int(cfg.Digits); i++ {
		divisor *= 10
	}

	timeBytesPool := &sync.Pool{
		New: func() interface{} {
			return new([8]byte)
		},
	}

	hmacPool := &sync.Pool{
		New: func() interface{} {
			h := hmac.New(cfg.Algorithm.hash, decodedSecret)
			return &hmacHolder{h: h}
		},
	}

	return &TOTP{
		cfg:           cfg,
		divisor:       divisor,
		timeBytesPool: timeBytesPool,
		hmacPool:      hmacPool,
		decodedSecret: decodedSecret,
	}
}

// GenerateForTime generates a TOTP for a specific Unix time.
func (o *TOTP) GenerateForTime(t time.Time) (string, error) {
	timeStep := t.Unix() / o.cfg.Period

	// Get a time bytes array from the pool.
	timeBytes := o.timeBytesPool.Get().(*[8]byte)
	defer o.timeBytesPool.Put(timeBytes)

	// Convert timeStep to big-endian 8-byte array.
	for i := range timeBytes {
		(*timeBytes)[7-i] = byte(timeStep >> (8 * i))
	}

	// Get a new HMAC instance from the pool.
	hmacInstance := o.hmacPool.Get().(*hmacHolder)
	defer o.hmacPool.Put(hmacInstance)

	hmacInstance.h.Reset()
	hmacInstance.h.Write(timeBytes[:])
	hmacResult := hmacInstance.h.Sum(nil)

	// Extract the dynamic binary code using offset from HMAC result.
	offset := hmacResult[len(hmacResult)-1] & 0x0F
	binaryCode := (int(hmacResult[offset])&0x7F)<<24 |
		(int(hmacResult[offset+1])&0xFF)<<16 |
		(int(hmacResult[offset+2])&0xFF)<<8 |
		(int(hmacResult[offset+3]) & 0xFF)

	// Calculate TOTP code.
	totpCode := binaryCode % int(o.divisor)

	// Use a pre-allocated buffer to avoid string allocation.
	var buf [8]byte
	codeLen := formatCode(buf[:], totpCode, int(o.cfg.Digits))

	return string(buf[:codeLen]), nil
}

// formatCode formats the TOTP code into the buffer without allocation.
func formatCode(buf []byte, code, digits int) int {
	for i := digits - 1; i >= 0; i-- {
		buf[i] = byte('0' + code%10)
		code /= 10
	}
	return digits
}

// Generate generates a TOTP for the current time.
func (o *TOTP) Generate() (string, error) {
	return o.GenerateForTime(time.Now())
}

// Validate checks whether the provided TOTP is valid for the current time.
func (o *TOTP) Validate(totp string) (bool, error) {
	return o.ValidateForTime(totp, time.Now())
}

// ValidateForTime checks if the given TOTP is valid for a specific time, considering allowed skew.
func (o *TOTP) ValidateForTime(totp string, t time.Time) (bool, error) {
	if len(totp) != int(o.cfg.Digits) || !isValidInteger(totp) {
		return false, errors.New("invalid TOTP format")
	}

	baseTimeStep := t.Unix() / o.cfg.Period

	// Check the TOTP within the allowed skew range.
	for i := -o.cfg.Skew; i <= o.cfg.Skew; i++ {
		timeStep := baseTimeStep + int64(i)
		expected, err := o.GenerateForTime(time.Unix(timeStep*o.cfg.Period, 0))
		if err != nil {
			return false, fmt.Errorf("error generating expected TOTP for time step %d: %w", timeStep, err)
		}

		// Securely compare the TOTP codes.
		if subtle.ConstantTimeCompare([]byte(totp), []byte(expected)) == 1 {
			return true, nil
		}
	}

	return false, nil
}

// isValidInteger checks if the input string contains only digits.
func isValidInteger(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
