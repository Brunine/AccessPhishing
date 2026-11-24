// Package profiles implements M10b application profiles: the validated,
// tenant-owned contract describing how to phish/proxy one target login surface
// (docs/PROFILES/SCHEMA.md). It provides untrusted-input validation (every rule
// ID from docs/PROFILES/VALIDATION.md), canonicalization + checksum stamping for
// forensic traceability, and the runtime flow-instantiation gate the M5 proxy
// uses to refuse unsupported auth/MFA methods.
package profiles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// MaxSpecBytes bounds a raw profile document (mirrors engineconfig.MaxConfigBytes).
const MaxSpecBytes = 64 << 10 // 64 KiB

// Runtime instantiation errors (M10b Phase 3 rulings 1 & 2). These are NOT
// import-time validation failures: a reserved-method profile is storable, but
// cannot be launched. The HTTP layer maps them to 409 / 501 with the rule ID.
var (
	// ErrAuthMethodUnsupported is returned when a stored profile's auth.method
	// is anything but form/basic at instantiation time (409 AUTH-METHOD-UNSUPPORTED).
	ErrAuthMethodUnsupported = errors.New("profiles: auth method unsupported at runtime")
	// ErrMFAMethodUnsupported is returned when a stored profile's mfa.mode is
	// push_intercept/custom at instantiation time (501 MFA-METHOD-UNSUPPORTED).
	ErrMFAMethodUnsupported = errors.New("profiles: mfa method unsupported at runtime")
)

// Rule IDs carried on validation violations and runtime errors. They are the
// exact machine-checkable identifiers from docs/PROFILES/VALIDATION.md.
const (
	CodeAuthMethodUnsupported = "AUTH-METHOD-UNSUPPORTED"
	CodeMFAMethodUnsupported  = "MFA-METHOD-UNSUPPORTED"
)

// ParseYAML decodes a raw profile document into a generic map for validation.
// It enforces the size limit and rejects a non-mapping root. The map is the
// untrusted structure every rule is checked against.
func ParseYAML(raw []byte) (map[string]any, error) {
	if len(raw) > MaxSpecBytes {
		return nil, fmt.Errorf("profiles: document is %d bytes, limit is %d", len(raw), MaxSpecBytes)
	}
	var root any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("profiles: parse yaml: %w", err)
	}
	m, ok := normalize(root).(map[string]any)
	if !ok {
		return nil, errors.New("profiles: document root must be a mapping")
	}
	return m, nil
}

// normalize converts yaml.v3's decoded shapes into JSON-friendly Go types so a
// single canonicalization + traversal path handles both YAML and JSON input.
// yaml.v3 already uses string keys for mappings, but nested values may be
// map[string]interface{} / []interface{}; this makes the types uniform.
func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = normalize(val)
		}
		return out
	case map[any]any: // defensive: older/edge decoders
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[fmt.Sprintf("%v", k)] = normalize(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = normalize(val)
		}
		return out
	default:
		return v
	}
}

// Canonicalize returns the deterministic JSON encoding of a parsed spec.
// encoding/json sorts map keys recursively, so the output is stable regardless
// of the source key order — the basis for a reproducible checksum.
func Canonicalize(spec map[string]any) ([]byte, error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("profiles: canonicalize: %w", err)
	}
	return b, nil
}

// Checksum returns the hex SHA-256 of a canonical spec.
func Checksum(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// ChecksumOf canonicalizes then hashes a parsed spec in one step.
func ChecksumOf(spec map[string]any) (string, error) {
	c, err := Canonicalize(spec)
	if err != nil {
		return "", err
	}
	return Checksum(c), nil
}

// InstantiateFlow is the runtime gate the proxy applies before serving a
// campaign's bound profile (M10b Phase 3 rulings 1 & 2). The spec is assumed
// already schema-valid (it passed import validation); this enforces only what
// the runtime actually supports:
//
//   - auth.method must be form or basic, else ErrAuthMethodUnsupported (409).
//   - mfa.mode must be none or totp_field, else ErrMFAMethodUnsupported (501).
//
// Auth method is checked before MFA so an unsupported SSO method surfaces as a
// 409 even when MFA is also exotic.
func InstantiateFlow(spec map[string]any) error {
	method, _ := mapStr(spec, "auth", "method")
	switch method {
	case "form", "basic":
		// supported
	default:
		return fmt.Errorf("%w: %q", ErrAuthMethodUnsupported, method)
	}

	mode, _ := mapStr(spec, "mfa", "mode")
	switch mode {
	case "", "none", "totp_field":
		// supported (empty is treated as none by the proxy)
	default:
		return fmt.Errorf("%w: %q", ErrMFAMethodUnsupported, mode)
	}
	return nil
}

// InstantiateFlowJSON decodes a stored canonical-JSON spec and applies the
// runtime instantiation gate (see InstantiateFlow). Used by the launch path,
// where the profile is read back from the database as JSON.
func InstantiateFlowJSON(canonical []byte) error {
	var m map[string]any
	if err := json.Unmarshal(canonical, &m); err != nil {
		return fmt.Errorf("profiles: decode spec: %w", err)
	}
	return InstantiateFlow(m)
}

// Name returns the declared metadata.name of a parsed spec.
func Name(spec map[string]any) string {
	n, _ := mapStr(spec, "metadata", "name")
	return n
}

// mapStr walks nested string-keyed maps and returns the string at the path.
func mapStr(m map[string]any, path ...string) (string, bool) {
	cur := any(m)
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = mm[k]
		if !ok {
			return "", false
		}
	}
	s, ok := cur.(string)
	return s, ok
}
