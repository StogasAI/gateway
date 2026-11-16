package inputfiles

import (
	"bytes"
	"io"
	"strconv"
	"unicode/utf8"
)

// officeXML reads the tokens of one part of an Office file, which is in memory. Go's
// encoding/xml reads such XML at about 10 MB a second, and a file may hold officeXMLBytes of
// it, so this scanner reads only what the parts need: elements by their local name, the
// attributes that a caller asks for, and text. It checks that elements nest and close, within
// officeDepth, and refuses document type declarations, since no Office part has one and their
// entities are how XML expands without bound.
type officeXML struct {
	data  []byte
	at    int
	depth int
	// open holds the qualified names of the open elements.
	open [officeDepth][]byte
	// closing is a start element that closes itself, whose end is the next token.
	closing bool
}

const (
	xmlStart = iota + 1
	xmlEnd
	xmlText
)

// xmlToken is a start element, an end element or text. Its slices point into the part, or into
// a copy where text held an entity, and live until the part is released.
type xmlToken struct {
	kind uint8
	// name is the element's name without its namespace prefix.
	name []byte
	// attrs are a start element's attributes, as written.
	attrs []byte
	text  []byte
}

// newOfficeXML reads a part as UTF-8, the encoding that Office and LibreOffice write.
func newOfficeXML(data []byte) (*officeXML, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if bytes.HasPrefix(data, []byte("\xff\xfe")) || bytes.HasPrefix(data, []byte("\xfe\xff")) {
		return nil, errOfficeUnreadable
	}
	if bytes.HasPrefix(data, []byte("<?xml")) {
		end := bytes.Index(data, []byte("?>"))
		if end < 0 {
			return nil, errOfficeUnreadable
		}
		declaration := xmlToken{attrs: data[len("<?xml"):end]}
		if encoding := declaration.attr("encoding"); encoding != "" && !bytes.EqualFold([]byte(encoding), []byte("utf-8")) {
			return nil, errOfficeUnreadable
		}
	}
	return &officeXML{data: data}, nil
}

func xmlSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// local returns a qualified name without its prefix.
func local(name []byte) []byte {
	return name[bytes.LastIndexByte(name, ':')+1:]
}

// next returns the part's next token, or io.EOF after the root element closed.
func (x *officeXML) next() (xmlToken, error) {
	if x.closing {
		x.closing = false
		x.depth--
		return xmlToken{kind: xmlEnd, name: local(x.open[x.depth])}, nil
	}
	for {
		rest := x.data[x.at:]
		if len(rest) == 0 {
			if x.depth != 0 {
				return xmlToken{}, errOfficeUnreadable
			}
			return xmlToken{}, io.EOF
		}
		if rest[0] != '<' {
			end := bytes.IndexByte(rest, '<')
			if end < 0 {
				end = len(rest)
			}
			x.at += end
			if x.depth == 0 {
				if len(bytes.TrimLeft(rest[:end], " \t\r\n")) != 0 {
					return xmlToken{}, errOfficeUnreadable
				}
				continue
			}
			text, err := unescapeXML(rest[:end])
			return xmlToken{kind: xmlText, text: text}, err
		}
		switch {
		case bytes.HasPrefix(rest, []byte("<!--")):
			end := bytes.Index(rest[4:], []byte("-->"))
			if end < 0 {
				return xmlToken{}, errOfficeUnreadable
			}
			x.at += 4 + end + 3
		case bytes.HasPrefix(rest, []byte("<![CDATA[")):
			end := bytes.Index(rest[9:], []byte("]]>"))
			if end < 0 || x.depth == 0 {
				return xmlToken{}, errOfficeUnreadable
			}
			x.at += 9 + end + 3
			return xmlToken{kind: xmlText, text: rest[9 : 9+end]}, nil
		case bytes.HasPrefix(rest, []byte("<?")):
			end := bytes.Index(rest, []byte("?>"))
			if end < 0 {
				return xmlToken{}, errOfficeUnreadable
			}
			x.at += end + 2
		case bytes.HasPrefix(rest, []byte("<!")):
			return xmlToken{}, errOfficeUnreadable
		case bytes.HasPrefix(rest, []byte("</")):
			end := bytes.IndexByte(rest, '>')
			if end < 0 || x.depth == 0 {
				return xmlToken{}, errOfficeUnreadable
			}
			name := bytes.TrimRight(rest[2:end], " \t\r\n")
			if !bytes.Equal(name, x.open[x.depth-1]) {
				return xmlToken{}, errOfficeUnreadable
			}
			x.at += end + 1
			x.depth--
			return xmlToken{kind: xmlEnd, name: local(name)}, nil
		default:
			i := 1
			for i < len(rest) && !xmlSpace(rest[i]) && rest[i] != '>' && rest[i] != '/' {
				i++
			}
			// The tag ends at the first > outside an attribute's quotes.
			j := i
			for {
				if j >= len(rest) || rest[j] == '<' {
					return xmlToken{}, errOfficeUnreadable
				}
				c := rest[j]
				if c == '>' {
					break
				}
				j++
				if c == '"' || c == '\'' {
					quote := bytes.IndexByte(rest[j:], c)
					if quote < 0 {
						return xmlToken{}, errOfficeUnreadable
					}
					j += quote + 1
				}
			}
			name, attrs := rest[1:i], rest[i:j]
			// A part has one root element.
			if len(name) == 0 || x.depth == officeDepth || x.depth == 0 && x.open[0] != nil {
				return xmlToken{}, errOfficeUnreadable
			}
			if len(attrs) > 0 && attrs[len(attrs)-1] == '/' {
				attrs, x.closing = attrs[:len(attrs)-1], true
			}
			x.at += j + 1
			x.open[x.depth] = name
			x.depth++
			return xmlToken{kind: xmlStart, name: local(name), attrs: attrs}, nil
		}
	}
}

// unescapeXML replaces the character and entity references of text or an attribute value. Text
// without one is returned as it is.
func unescapeXML(raw []byte) ([]byte, error) {
	amp := bytes.IndexByte(raw, '&')
	if amp < 0 {
		return raw, nil
	}
	out := make([]byte, 0, len(raw))
	for amp >= 0 {
		out = append(out, raw[:amp]...)
		raw = raw[amp+1:]
		end := bytes.IndexByte(raw, ';')
		if end < 1 || end > 10 {
			return nil, errOfficeUnreadable
		}
		switch reference := string(raw[:end]); reference {
		case "amp":
			out = append(out, '&')
		case "lt":
			out = append(out, '<')
		case "gt":
			out = append(out, '>')
		case "quot":
			out = append(out, '"')
		case "apos":
			out = append(out, '\'')
		default:
			base, digits := 10, reference[1:]
			if reference[0] != '#' || digits == "" {
				return nil, errOfficeUnreadable
			}
			if digits[0] == 'x' {
				base, digits = 16, digits[1:]
			}
			n, err := strconv.ParseUint(digits, base, 32)
			// XML has no NUL, surrogate or character past U+10FFFF.
			if err != nil || n == 0 || n > utf8.MaxRune || !utf8.ValidRune(rune(n)) {
				return nil, errOfficeUnreadable
			}
			out = utf8.AppendRune(out, rune(n))
		}
		raw = raw[end+1:]
		amp = bytes.IndexByte(raw, '&')
	}
	return append(out, raw...), nil
}

// find returns the value of a start element's attribute by local name, as written. prefixed
// selects by namespace prefix: 1 takes only an attribute with one, as r:id beside id, 0 only one
// without, and -1 either. Namespace declarations are not attributes.
func (t xmlToken) find(name string, prefixed int) ([]byte, bool) {
	rest := t.attrs
	for {
		start := 0
		for start < len(rest) && xmlSpace(rest[start]) {
			start++
		}
		equals := bytes.IndexByte(rest[start:], '=')
		if equals < 0 {
			return nil, false
		}
		equals += start
		end := equals
		for end > start && xmlSpace(rest[end-1]) {
			end--
		}
		key := rest[start:end]
		quote := equals + 1
		for quote < len(rest) && xmlSpace(rest[quote]) {
			quote++
		}
		if quote >= len(rest) || rest[quote] != '"' && rest[quote] != '\'' {
			return nil, false
		}
		close := bytes.IndexByte(rest[quote+1:], rest[quote])
		if close < 0 {
			return nil, false
		}
		value := rest[quote+1 : quote+1+close]
		rest = rest[quote+close+2:]
		colon := bytes.LastIndexByte(key, ':')
		if string(key[colon+1:]) != name || string(key) == "xmlns" || colon >= 0 && string(key[:colon]) == "xmlns" {
			continue
		}
		if prefixed < 0 || (colon >= 0) == (prefixed == 1) {
			return value, true
		}
	}
}

// attr returns an attribute by local name, with or without a prefix, or "".
func (t xmlToken) attr(name string) string {
	value, _ := t.find(name, -1)
	if value, err := unescapeXML(value); err == nil {
		return string(value)
	}
	return ""
}

// prefixed returns an attribute by local name that has a namespace prefix, or "".
func (t xmlToken) prefixed(name string) string {
	value, _ := t.find(name, 1)
	if value, err := unescapeXML(value); err == nil {
		return string(value)
	}
	return ""
}

// number returns an attribute as a whole number, or fallback where it is absent or not one.
func (t xmlToken) number(name string, fallback int) int {
	value, found := t.find(name, -1)
	if n, err := strconv.Atoi(string(value)); found && err == nil {
		return n
	}
	return fallback
}

// text returns the text inside the element that just started, up to 1 KiB, and reads past the
// element.
func (x *officeXML) text() (string, error) {
	var text []byte
	for depth := x.depth; ; {
		token, err := x.next()
		if err != nil {
			return "", err
		}
		if token.kind == xmlText && len(text)+len(token.text) <= 1024 {
			text = append(text, token.text...)
		}
		if x.depth < depth {
			return string(text), nil
		}
	}
}

// skip reads past the element that just started.
func (x *officeXML) skip() error {
	for depth := x.depth; ; {
		if _, err := x.next(); err != nil {
			return err
		}
		if x.depth < depth {
			return nil
		}
	}
}

// each calls visit for every token of the part.
func (x *officeXML) each(visit func(xmlToken) error) error {
	for {
		token, err := x.next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := visit(token); err != nil {
			return err
		}
	}
}
