package server

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// VerifyForwardedCert checks the client certificate a TLS-terminating proxy passed on, in
// Envoy's X-Forwarded-Client-Cert form (what Azure Container Apps' ingress sends):
//
//	Hash=<sha256>;Cert="<URL-encoded PEM>";Chain="<URL-encoded PEM>"
//
// The proxy must replace any copy a client sent, so the header must hold exactly one element:
// a second one means the proxy appended to a client's header, and the client could have
// shaped what gets read. The proxy may accept any certificate, so the chain, the dates and
// the client-auth usage are all checked here against roots.
func VerifyForwardedCert(header string, roots *x509.CertPool) error {
	if header == "" {
		return errors.New("no client certificate header")
	}
	fields, err := parseXFCC(header)
	if err != nil {
		return err
	}
	var certs []*x509.Certificate
	for _, key := range []string{"cert", "chain"} {
		v, ok := fields[key]
		if !ok {
			continue
		}
		cs, err := decodePEM(v)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		certs = append(certs, cs...)
	}
	if len(certs) == 0 {
		return errors.New("no certificate in the client certificate header")
	}
	if roots == nil {
		return errors.New("no client CA configured")
	}
	leaf, intermediates := certs[0], x509.NewCertPool()
	for _, c := range certs[1:] {
		if !c.Equal(leaf) {
			intermediates.AddCert(c)
		}
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

// parseXFCC reads one element's key=value pairs. Keys are lowercased. A value may be quoted,
// with \" for a quote inside it. A second element (a comma outside quotes), an unterminated
// quote, a pair without "=" or a repeated key is an error.
func parseXFCC(h string) (map[string]string, error) {
	out := map[string]string{}
	var key, val strings.Builder
	inKey, quoted, escaped, wasQuoted := true, false, false, false
	flush := func() error {
		k := strings.ToLower(strings.TrimSpace(key.String()))
		defer func() { key.Reset(); val.Reset(); inKey, wasQuoted = true, false }()
		if k == "" && val.Len() == 0 && inKey {
			return nil // an empty pair, as after a trailing ";"
		}
		if inKey || k == "" {
			return fmt.Errorf("malformed client certificate header near %q", k)
		}
		if _, dup := out[k]; dup {
			return fmt.Errorf("client certificate header repeats %q", k)
		}
		out[k] = val.String()
		return nil
	}
	for _, c := range h {
		if quoted {
			switch {
			case escaped:
				val.WriteRune(c)
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				quoted, wasQuoted = false, true
			default:
				val.WriteRune(c)
			}
			continue
		}
		switch c {
		case '"':
			if inKey || val.Len() > 0 || wasQuoted {
				return nil, errors.New("misplaced quote in the client certificate header")
			}
			quoted = true
		case '=':
			if inKey {
				inKey = false
			} else {
				val.WriteRune(c)
			}
		case ';':
			if err := flush(); err != nil {
				return nil, err
			}
		case ',':
			return nil, errors.New("client certificate header has more than one element: the proxy must replace a client's header, not append to it")
		default:
			if wasQuoted && !unicode.IsSpace(c) {
				return nil, errors.New("text after a quoted value in the client certificate header")
			}
			if inKey {
				key.WriteRune(c)
			} else if !wasQuoted {
				val.WriteRune(c)
			}
		}
	}
	if quoted {
		return nil, errors.New("unterminated quote in the client certificate header")
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

// decodePEM undoes the URL encoding and reads every certificate. Envoy percent-encodes
// everything (so PathUnescape keeps a literal "+"); some proxies use form encoding instead,
// with "+" for a space, which the fallback handles.
func decodePEM(v string) ([]*x509.Certificate, error) {
	var lastErr error
	for _, unescape := range []func(string) (string, error){url.PathUnescape, url.QueryUnescape} {
		s, err := unescape(v)
		if err != nil {
			lastErr = err
			continue
		}
		certs, err := parseCerts([]byte(s))
		if err == nil {
			return certs, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func parseCerts(b []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM certificate")
	}
	return certs, nil
}
