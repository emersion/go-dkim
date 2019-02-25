package dkim

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var randReader io.Reader = rand.Reader

// SignOptions is used to configure Sign. Domain, Selector and Signer are
// mandatory.
type SignOptions struct {
	// The SDID claiming responsibility for an introduction of a message into the
	// mail stream. Hence, the SDID value is used to form the query for the public
	// key. The SDID MUST correspond to a valid DNS name under which the DKIM key
	// record is published.
	Domain string
	// The selector subdividing the namespace for the domain.
	Selector string
	// The Agent or User Identifier (AUID) on behalf of which the SDID is taking
	// responsibility.
	Identifier string

	// The key used to sign the message.
	Signer crypto.Signer
	// The hash algorithm used to sign the message.
	Hash crypto.Hash

	// Header and body canonicalization algorithms.
	HeaderCanonicalization string
	BodyCanonicalization   string

	// A list of header fields to include in the signature. If nil, all headers
	// will be included. If not nil, "From" MUST be in the list.
	//
	// See RFC 6376 section 5.4.1 for recommended header fields.
	HeaderKeys []string

	// The expiration time. A zero value means no expiration.
	Expiration time.Time

	// A list of query methods used to retrieve the public key.
	QueryMethods []string
}

// Sign signs a message. It reads it from r and writes the signed version to w.
func Sign(w io.Writer, r io.Reader, options *SignOptions) error {
	if options == nil {
		return fmt.Errorf("dkim: no options specified")
	}
	if options.Domain == "" {
		return fmt.Errorf("dkim: no domain specified")
	}
	if options.Selector == "" {
		return fmt.Errorf("dkim: no selector specified")
	}
	if options.Signer == nil {
		return fmt.Errorf("dkim: no signer specified")
	}

	headerCan := options.HeaderCanonicalization
	if headerCan == "" {
		headerCan = "simple"
	}
	if _, ok := canonicalizers[headerCan]; !ok {
		return fmt.Errorf("dkim: unknown header canonicalization %q", headerCan)
	}

	bodyCan := options.BodyCanonicalization
	if bodyCan == "" {
		bodyCan = "simple"
	}
	if _, ok := canonicalizers[bodyCan]; !ok {
		return fmt.Errorf("dkim: unknown body canonicalization %q", bodyCan)
	}

	var keyAlgo string
	switch options.Signer.Public().(type) {
	case *rsa.PublicKey:
		keyAlgo = "rsa"
	default:
		return fmt.Errorf("dkim: unsupported key algorithm %T", options.Signer.Public())
	}

	hash := options.Hash
	var hashAlgo string
	switch options.Hash {
	case crypto.SHA1:
		hashAlgo = "sha1"
	case 0: // sha256 is the default
		hash = crypto.SHA256
		fallthrough
	case crypto.SHA256:
		hashAlgo = "sha256"
	default:
		return fmt.Errorf("dkim: unsupported hash algorithm")
	}

	if options.HeaderKeys != nil {
		ok := false
		for _, k := range options.HeaderKeys {
			if strings.ToLower(k) == "from" {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("dkim: the From header field must be signed")
		}
	}

	// Read header
	br := bufio.NewReader(r)
	h, err := readHeader(br)
	if err != nil {
		return err
	}

	// Hash body
	// We need to keep a copy of the body in memory
	var b bytes.Buffer
	hasher := hash.New()
	can := canonicalizers[bodyCan].CanonicalizeBody(hasher)
	mw := io.MultiWriter(&b, can)
	if _, err := io.Copy(mw, br); err != nil {
		return err
	}
	if err := can.Close(); err != nil {
		return err
	}
	bodyHashed := hasher.Sum(nil)

	params := map[string]string{
		"v":  "1",
		"a":  keyAlgo + "-" + hashAlgo,
		"bh": base64.StdEncoding.EncodeToString(bodyHashed),
		"c":  headerCan + "/" + bodyCan,
		"d":  options.Domain,
		//"l": "", // TODO
		"s": options.Selector,
		"t": formatTime(now()),
		//"z": "", // TODO
	}

	var headerKeys []string
	if options.HeaderKeys != nil {
		headerKeys = options.HeaderKeys
	} else {
		for _, kv := range h {
			k, _ := parseHeaderField(kv)
			headerKeys = append(headerKeys, k)
		}
	}
	params["h"] = formatTagList(headerKeys)

	if options.Identifier != "" {
		params["i"] = options.Identifier
	}

	if options.QueryMethods != nil {
		params["q"] = formatTagList(options.QueryMethods)
	}

	if !options.Expiration.IsZero() {
		params["x"] = formatTime(options.Expiration)
	}

	// Hash and sign headers
	hasher.Reset()
	picker := newHeaderPicker(h)
	for _, k := range headerKeys {
		kv := picker.Pick(k)
		if kv == "" {
			continue
		}
		kv = canonicalizers[headerCan].CanonicalizeHeader(kv)
		if _, err := hasher.Write([]byte(kv)); err != nil {
			return err
		}
	}

	params["b"] = ""
	sigField := formatSignature(params)
	sigField = canonicalizers[headerCan].CanonicalizeHeader(sigField)
	sigField = strings.TrimRight(sigField, crlf)
	if _, err := hasher.Write([]byte(sigField)); err != nil {
		return err
	}
	hashed := hasher.Sum(nil)

	sig, err := options.Signer.Sign(randReader, hashed, hash)
	if err != nil {
		return err
	}
	params["b"] = base64.StdEncoding.EncodeToString(sig)
	sigField = formatSignature(params)

	if _, err := w.Write([]byte(sigField)); err != nil {
		return err
	}
	if err := writeHeader(w, h); err != nil {
		return err
	}

	_, err = io.Copy(w, &b)
	return err
}

func formatSignature(params map[string]string) string {
	var fold strings.Builder
	var maxLen = 58
	var headers = formatHeaderParams(params)
	fold.WriteString("DKIM-Signature: ")
	writeHeaders(&fold, headers, maxLen)
	if v, ok := params["b"]; ok {
		fold.WriteString(headSep)
		fold.WriteString(strings.Join(ChunkString("b="+v, maxLen-3), headSep))
	}
	fold.WriteString(crlf)
	return fold.String()
}

func writeHeaders(to io.Writer, headers []string, maxLen int) {
	var iternalStringBuf bytes.Buffer
	var header string

	for len(headers) != 0 {
		// pop-left header
		header, headers = headers[0], headers[1:]
		bufSize := iternalStringBuf.Len()
		headerSize := utf8.RuneCountInString(header)
		switch {
		case (bufSize + headerSize) <= maxLen:
			iternalStringBuf.WriteString(header)
			if iternalStringBuf.Len() == maxLen {
				to.Write(iternalStringBuf.Bytes())
				iternalStringBuf.Reset()
				iternalStringBuf.WriteString(headSep)
			}

		case (bufSize + headerSize) > maxLen:
			to.Write(iternalStringBuf.Bytes())
			iternalStringBuf.Reset()
			iternalStringBuf.WriteString(headSep)
			fallthrough

		default:
			if headerSize < maxLen {
				iternalStringBuf.WriteString(header)

			} else {
				// otherwise
				// in case when current header gt maxLen
				// split header to part and set parts in head of slice
				to.Write(iternalStringBuf.Bytes())
				iternalStringBuf.Reset()
				headers = append(ChunkString(header, maxLen-3), headers...)
			}
		}
	}
	to.Write(iternalStringBuf.Bytes())
}

func formatTagList(l []string) string {
	return strings.Join(l, ": ")
}

func formatTime(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}

func ChunkString(s string, chunkSize int) []string {
	var chunks []string
	runes := []rune(s)

	if len(runes) == 0 {
		return []string{s}
	}

	for i := 0; i < len(runes); i += chunkSize {
		nn := i + chunkSize
		if nn > len(runes) {
			nn = len(runes)
		}
		chunks = append(chunks, string(runes[i:nn]))
	}
	return chunks
}
