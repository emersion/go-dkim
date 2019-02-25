package dkim

import (
	"bufio"
	"errors"
	"io"
	"net/textproto"
	"sort"
	"strings"
)

const crlf = "\r\n"
const headSep = crlf + "\t"

var headersPos = []string{"v", "a", "c", "d", "i", "q", "s", "t", "h", "bh", "b"}

type header []string

type dkimHeaderKeys []string

func (h dkimHeaderKeys) Len() int {
	return len(h)
}

func (h dkimHeaderKeys) Less(i, j int) bool {
	var idxI, idxJ = 0, 1
	for idx, v := range headersPos {
		if v == h[i] {
			idxI = idx
		}
		if v == h[j] {
			idxJ = idx
		}
	}
	return idxI < idxJ
}

func (h dkimHeaderKeys) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func readHeader(r *bufio.Reader) (header, error) {
	tr := textproto.NewReader(r)

	var h header
	for {
		l, err := tr.ReadLine()
		if err != nil {
			return h, err
		}

		if len(l) == 0 {
			break
		} else if len(h) > 0 && (l[0] == ' ' || l[0] == '\t') {
			// This is a continuation line
			h[len(h)-1] += l + crlf
		} else {
			h = append(h, l+crlf)
		}
	}

	return h, nil
}

func writeHeader(w io.Writer, h header) error {
	for _, kv := range h {
		if _, err := w.Write([]byte(kv)); err != nil {
			return err
		}
	}
	_, err := w.Write([]byte(crlf))
	return err
}

func parseHeaderField(s string) (k string, v string) {
	kv := strings.SplitN(s, ":", 2)
	k = strings.TrimSpace(kv[0])
	if len(kv) > 1 {
		v = strings.TrimSpace(kv[1])
	}
	return
}

func parseHeaderParams(s string) (map[string]string, error) {
	pairs := strings.Split(s, ";")
	params := make(map[string]string)
	for _, s := range pairs {
		kv := strings.SplitN(s, "=", 2)
		if len(kv) != 2 {
			if strings.TrimSpace(s) == "" {
				continue
			}
			return params, errors.New("dkim: malformed header params")
		}

		params[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return params, nil
}

func formatHeaderParams(params map[string]string) []string {
	keys := make(dkimHeaderKeys, 0, len(params))
	for k := range params {
		if k == "b" {
			continue
		} else {
			keys = append(keys, k)
		}
	}
	sort.Sort(keys)
	headers := make([]string, 0, len(params))
	for _, k := range keys {
		v := params[k]
		headers = append(headers, k+"="+v+"; ")
	}
	return headers
}

type headerPicker struct {
	h      header
	picked map[string]int
}

func newHeaderPicker(h header) *headerPicker {
	return &headerPicker{
		h:      h,
		picked: make(map[string]int),
	}
}

func (p *headerPicker) Pick(key string) string {
	at := p.picked[key]
	loverKey := strings.ToLower(key)
	for i := len(p.h) - 1; i >= 0; i-- {
		kv := p.h[i]
		k, _ := parseHeaderField(kv)

		if strings.ToLower(k) != loverKey {
			continue
		}

		if at == 0 {
			p.picked[key]++
			return kv
		}
		at--
	}

	return ""
}
