package inputfiles

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/maximhq/bifrost/transports/stogas/inputfiles/filetype"
)

// officeKind is what an Office file holds.
type officeKind uint8

const (
	officeDocument officeKind = iota + 1
	officeSpreadsheet
	officePresentation
)

func (k officeKind) String() string {
	switch k {
	case officeDocument:
		return "a text document"
	case officeSpreadsheet:
		return "a spreadsheet"
	case officePresentation:
		return "a presentation"
	}
	return "an unknown file"
}

// officeMediaTypes name what a file of each Office type holds.
var officeMediaTypes = func() map[string]officeKind {
	kinds := map[string]officeKind{}
	for kind, mediaTypes := range map[officeKind][]string{
		officeDocument: filetype.Documents, officeSpreadsheet: filetype.Spreadsheets, officePresentation: filetype.Presentations,
	} {
		for _, mediaType := range mediaTypes {
			kinds[mediaType] = kind
		}
	}
	return kinds
}()

// officeExtensions name the type of an archive that declares no Office type, as providers read
// it from the filename. The content then has to be of that type's kind.
var officeExtensions = map[string]string{
	".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".docm": "application/vnd.ms-word.document.macroenabled.12",
	".odt":  "application/vnd.oasis.opendocument.text",
	".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".xlsm": "application/vnd.ms-excel.sheet.macroenabled.12",
	".ods":  "application/vnd.oasis.opendocument.spreadsheet",
	".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	".pptm": "application/vnd.ms-powerpoint.presentation.macroenabled.12",
	".odp":  "application/vnd.oasis.opendocument.presentation",
}

// officeFile names the Office type of an inline document, or "": a zip archive that declares an
// Office type, or that declares no type, only application/octet-stream or only that it is a zip
// archive, and whose filename has an Office extension.
func officeFile(declared, payload, filename string) string {
	mediaType := strings.ToLower(declared)
	if officeMediaTypes[mediaType] == 0 {
		switch mediaType {
		case "", "application/octet-stream", "application/zip", "application/x-zip-compressed":
			mediaType = officeExtensions[strings.ToLower(path.Ext(filename))]
		default:
			return ""
		}
	}
	if data := head(payload); mediaType == "" || !bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		return ""
	}
	return mediaType
}

// Extractable names an inline document that text extraction can turn into prompt text, or
// returns the zero Type for any other file. declared is its declared media type and payload its
// base64 data, of which it reads only the start.
func Extractable(declared, payload, filename string) filetype.Type {
	if TextFile(declared, payload) {
		mediaType := strings.ToLower(declared)
		if !filetype.IsText(mediaType) {
			mediaType = "text/plain"
		}
		return filetype.Type{Family: filetype.Text, MediaType: mediaType}
	}
	if mediaType := officeFile(declared, payload, filename); mediaType != "" {
		return filetype.Type{Family: filetype.Office, MediaType: mediaType}
	}
	if pdfFile(declared, payload, filename) {
		return filetype.Type{Family: filetype.PDF, MediaType: filetype.PDFMediaType}
	}
	return filetype.Type{}
}

// Bounds of the work that one Office file may cause. Its parts are untrusted XML in an
// untrusted archive, so every size is checked before the bytes are read.
const (
	// officeDirectoryBytes bounds the archive's directory, which Go's reader holds in memory at
	// about ten times its size: 1 MiB lists at most 22,000 parts.
	officeDirectoryBytes = 1 << 20
	// officeXMLBytes bounds the XML that the gateway inflates and parses from one file. A sheet's
	// XML is about seven times its text, so a file within officeTextBytes fits.
	officeXMLBytes = 32 << 20
	// officeTextBytes bounds the text of one file, about two million tokens, which no model
	// reads.
	officeTextBytes = 8 << 20
	// officeDepth bounds element nesting. The decoder keeps one record for each open element.
	officeDepth = 256
	// officeColumns is the widest sheet of Excel and LibreOffice.
	officeColumns = 16384
)

// readError is a reason that follows the attachment's path in a refusal of a file that text
// extraction cannot read.
type readError string

func (e readError) Error() string { return string(e) }

const (
	errOfficeUnreadable = readError("is not a readable Office file")
	errOfficeTooLarge   = readError("holds more than text extraction reads: 32 MiB of XML or 8 MiB of text")
)

// extractOffice returns the text of an Office file of the declared kind. retain admits bytes
// that the extraction keeps in memory, before it keeps them.
func extractOffice(data []byte, kind officeKind, retain func(int) error) (string, error) {
	archive, err := openOfficeArchive(data, retain)
	if err != nil {
		return "", err
	}
	reader := &officeReader{parts: archive, budget: officeXMLBytes, out: officeText{retain: retain}, retain: retain}
	var found officeKind
	switch {
	case archive["content.xml"] != nil && archive["_rels/.rels"] == nil:
		found, err = reader.openDocument(kind)
	default:
		found, err = reader.openXML(kind)
	}
	if err == nil && reader.out.err != nil {
		err = reader.out.err
	}
	if err != nil {
		var refusal readError
		var capacity capacityError
		if errors.As(err, &refusal) || errors.As(err, &capacity) {
			return "", err
		}
		// A syntax error of the archive or its XML says nothing that helps the client more.
		return "", errOfficeUnreadable
	}
	if found != kind {
		return "", readError("declares " + kind.String() + ", but its content is " + found.String())
	}
	text := strings.TrimRight(reader.out.b.String(), "\n")
	// The same rule as for a text file: the text is UTF-8 and has no NUL.
	if !utf8.ValidString(text) || strings.IndexByte(text, 0) >= 0 {
		return "", errOfficeUnreadable
	}
	return text, nil
}

// capacityError carries a refusal of retain unchanged, so that the caller reports it as its own.
type capacityError struct{ error }

func (e capacityError) Unwrap() error { return e.error }

// openOfficeArchive lists the archive's parts by lowercase name, since part names compare
// without case. Go's reader keeps a record of every entry that the directory holds, and reads
// entries until one is not a directory entry, whatever the end record says of their number and
// size. So the directory must end where the end record starts, within officeDirectoryBytes,
// which bounds what the reader keeps.
func openOfficeArchive(data []byte, retain func(int) error) (map[string]*zip.File, error) {
	// The reader takes the last end record in the file's last 65 KiB.
	const record, window = 22, 65 << 10
	from := max(len(data)-window, 0)
	end := bytes.LastIndex(data[from:], []byte("PK\x05\x06"))
	if end < 0 || len(data)-from-end < record {
		return nil, errOfficeUnreadable
	}
	end += from
	entries := binary.LittleEndian.Uint16(data[end+10:])
	size, offset := binary.LittleEndian.Uint32(data[end+12:]), binary.LittleEndian.Uint32(data[end+16:])
	// A zip64 locator before the end record replaces these numbers, and no Office file within the
	// bounds needs one.
	if entries == math.MaxUint16 || size > officeDirectoryBytes || end >= 20 && bytes.Equal(data[end-20:end-16], []byte("PK\x06\x07")) {
		return nil, errOfficeTooLarge
	}
	if uint64(offset)+uint64(size) != uint64(end) {
		return nil, errOfficeUnreadable
	}
	if retain != nil {
		if err := retain(10 * int(size)); err != nil {
			return nil, capacityError{err}
		}
	}
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errOfficeUnreadable
	}
	parts := make(map[string]*zip.File, len(archive.File))
	for _, file := range archive.File {
		// Some Windows libraries write part names with backslashes, which Office reads.
		name := strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(file.Name, `\`, "/"), "/"))
		if _, exists := parts[name]; !exists {
			parts[name] = file
		}
	}
	return parts, nil
}

type officeReader struct {
	parts  map[string]*zip.File
	budget int64
	out    officeText
	retain func(int) error
}

// officeText collects a file's text within officeTextBytes.
type officeText struct {
	b      strings.Builder
	retain func(int) error
	// held counts the text that paragraphs and table cells hold before it is written, and
	// charged what retain admitted of held and written text together.
	held, charged int
	err           error
	// list says that the last block was a list item, which the next one follows without a
	// blank line.
	list bool
}

// admit admits the text that is held and written once held more bytes are held and written more
// are written, in steps, so that a long file does not ask for each word. Written text counts
// seven times: it becomes a JSON string, where each UTF-8 byte may require six bytes.
func (o *officeText) admit(held, written int) bool {
	if o.err != nil {
		return false
	}
	if need := o.held + held + 7*(o.b.Len()+written); need > o.charged {
		step := max(need-o.charged, 64<<10)
		if o.retain != nil {
			if err := o.retain(step); err != nil {
				o.err = capacityError{err}
				return false
			}
		}
		o.charged += step
	}
	return true
}

// hold counts n bytes that a paragraph or a cell keeps until its block is written.
func (o *officeText) hold(n int) bool {
	if o.err == nil && o.held+n > officeTextBytes {
		o.err = errOfficeTooLarge
	}
	if !o.admit(n, 0) {
		return false
	}
	o.held += n
	return true
}

func (o *officeText) write(text string) {
	if o.err == nil && o.b.Len()+len(text) > officeTextBytes {
		o.err = errOfficeTooLarge
	}
	if o.admit(0, len(text)) {
		o.b.WriteString(text)
	}
}

// block writes a paragraph, heading, table or list item after a blank line, or after a single
// line break between two list items.
func (o *officeText) block(text string, list bool) {
	if text == "" {
		return
	}
	if o.b.Len() > 0 {
		if list && o.list {
			o.write("\n")
		} else {
			o.write("\n\n")
		}
	}
	o.list = list
	o.write(text)
}

// line writes a line directly below the last one.
func (o *officeText) line(text string) {
	if o.b.Len() > 0 {
		o.write("\n")
	}
	o.list = false
	o.write(text)
}

// part reads a part by name for parsing, within the file's budget, or returns nil when the
// archive has no such part.
func (r *officeReader) part(name string) (*officeXML, error) {
	file := r.parts[strings.ToLower(name)]
	if file == nil {
		return nil, nil
	}
	size := file.UncompressedSize64
	if size > uint64(r.budget) {
		return nil, errOfficeTooLarge
	}
	r.budget -= int64(size)
	if r.retain != nil {
		if err := r.retain(int(size)); err != nil {
			return nil, capacityError{err}
		}
	}
	stream, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	// The archive's reader checks the stated size and the checksum only at the end of the
	// stream, so a part that inflates past its stated size stops here.
	data := make([]byte, size+1)
	n, err := io.ReadFull(stream, data)
	if err != io.ErrUnexpectedEOF || uint64(n) != size {
		return nil, errOfficeUnreadable
	}
	return newOfficeXML(data[:n])
}

// required opens a part that the format requires.
func (r *officeReader) required(name string) (*officeXML, error) {
	part, err := r.part(name)
	if err == nil && part == nil {
		err = errOfficeUnreadable
	}
	return part, err
}

type officeRelationship struct {
	kind, target string
}

// relationships reads the relationships of a part, by ID, with each target as a part name.
// External targets are left out.
func (r *officeReader) relationships(name string) (map[string]officeRelationship, error) {
	dir, base := path.Split(name)
	part, err := r.part(dir + "_rels/" + base + ".rels")
	if err != nil || part == nil {
		return nil, err
	}
	relationships := make(map[string]officeRelationship)
	err = part.each(func(token xmlToken) error {
		start, ok := token, token.kind == xmlStart
		if !ok || string(start.name) != "Relationship" || start.attr("TargetMode") == "External" {
			return nil
		}
		target := start.attr("Target")
		if !strings.HasPrefix(target, "/") {
			target = dir + target
		}
		kind := start.attr("Type")
		relationships[start.attr("Id")] = officeRelationship{kind[strings.LastIndexByte(kind, '/')+1:], strings.TrimPrefix(path.Clean("/"+target), "/")}
		return nil
	})
	return relationships, err
}

// related returns the target of the first relationship of a kind, such as styles, or "".
func related(relationships map[string]officeRelationship, kind string) string {
	found := ""
	for _, relationship := range relationships {
		// Map order must not choose between two parts of one kind.
		if relationship.kind == kind && (found == "" || relationship.target < found) {
			found = relationship.target
		}
	}
	return found
}

// openXML reads an Office Open XML file, whose package relationships name its main part.
func (r *officeReader) openXML(declared officeKind) (officeKind, error) {
	relationships, err := r.relationships("")
	if err != nil {
		return 0, err
	}
	main := related(relationships, "officeDocument")
	if main == "" {
		return 0, errOfficeUnreadable
	}
	own, err := r.relationships(main)
	if err != nil {
		return 0, err
	}
	part, err := r.required(main)
	if err != nil {
		return 0, err
	}
	// Text may come before the root element.
	var start xmlToken
	for start.kind != xmlStart {
		if start, err = part.next(); err != nil {
			return 0, err
		}
	}
	var kind officeKind
	switch string(start.name) {
	case "document":
		kind = officeDocument
	case "workbook":
		kind = officeSpreadsheet
	case "presentation":
		kind = officePresentation
	}
	if kind != declared {
		if kind == 0 {
			return 0, errOfficeUnreadable
		}
		return kind, nil
	}
	switch kind {
	case officeDocument:
		err = r.wordDocument(part, own)
	case officeSpreadsheet:
		err = r.workbook(part, own)
	default:
		err = r.presentation(part, own)
	}
	return kind, err
}

// officeTable collects the rows of a table in a document or on a slide.
type officeTable struct {
	rows [][]string
	row  []string
	cell []string
	open bool
}

// markdown renders the table with its first row as the header.
func (t *officeTable) markdown() string {
	width := 0
	for _, row := range t.rows {
		width = max(width, len(row))
	}
	if width == 0 {
		return ""
	}
	var b strings.Builder
	for i, row := range t.rows {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteByte('|')
		for column := range width {
			b.WriteByte(' ')
			if column < len(row) {
				b.WriteString(row[column])
			}
			b.WriteString(" |")
		}
		if i == 0 {
			b.WriteString("\n|" + strings.Repeat(" --- |", width))
		}
	}
	return b.String()
}

// officeBlocks turns the paragraphs and tables of a document part or a slide into blocks. Word,
// PowerPoint and OpenDocument name the elements differently and nest them the same way.
type officeBlocks struct {
	out *officeText
	// emit takes a finished block outside every table, in place of out.
	emit       func(text string, list bool)
	paragraphs []*officeParagraph
	tables     []*officeTable
}

type officeParagraph struct {
	text    strings.Builder
	heading int
	list    bool
	level   int
}

func (b *officeBlocks) paragraph() *officeParagraph {
	if len(b.paragraphs) == 0 {
		return nil
	}
	return b.paragraphs[len(b.paragraphs)-1]
}

func (b *officeBlocks) startParagraph() *officeParagraph {
	paragraph := &officeParagraph{}
	b.paragraphs = append(b.paragraphs, paragraph)
	return paragraph
}

// text adds text to the open paragraph.
func (b *officeBlocks) text(text string) {
	if paragraph := b.paragraph(); paragraph != nil && b.out.hold(len(text)) {
		paragraph.text.WriteString(text)
	}
}

// bytes adds text to the open paragraph.
func (b *officeBlocks) bytes(text []byte) {
	if paragraph := b.paragraph(); paragraph != nil && b.out.hold(len(text)) {
		paragraph.text.Write(text)
	}
}

// endParagraph closes the open paragraph and places its text: in the open table cell, or as a
// block.
func (b *officeBlocks) endParagraph() {
	paragraph := b.paragraph()
	if paragraph == nil {
		return
	}
	b.paragraphs = b.paragraphs[:len(b.paragraphs)-1]
	text := strings.TrimSpace(paragraph.text.String())
	if text == "" {
		return
	}
	indent := strings.Repeat("  ", max(min(paragraph.level, 8), 0))
	switch {
	case paragraph.heading > 0:
		text = strings.Repeat("#", min(paragraph.heading, 6)) + " " + text
	case paragraph.list:
		text = indent + "- " + text
	default:
		// A slide's outline levels show as indentation, since a slide does not say which
		// paragraphs have bullets.
		text = indent + text
	}
	b.place(text, paragraph.list)
}

func (b *officeBlocks) place(text string, list bool) {
	if len(b.tables) > 0 {
		if table := b.tables[len(b.tables)-1]; table.open {
			table.cell = append(table.cell, text)
		}
		return
	}
	if b.emit != nil {
		b.emit(text, list)
		return
	}
	b.out.block(text, list)
}

func (b *officeBlocks) startTable() { b.tables = append(b.tables, &officeTable{}) }

func (b *officeBlocks) table() *officeTable {
	if len(b.tables) == 0 {
		return nil
	}
	return b.tables[len(b.tables)-1]
}

// startCell opens a cell, which costs its separators even when it is empty.
func (b *officeBlocks) startCell() {
	if table := b.table(); table != nil && b.out.hold(4) {
		table.cell, table.open = nil, true
	}
}

// endCell closes the open cell. A table cell is one line, so its paragraphs join with <br> and a
// vertical bar is escaped.
func (b *officeBlocks) endCell() {
	if table := b.table(); table != nil && table.open {
		text := strings.Join(table.cell, "<br>")
		text = strings.NewReplacer("\r\n", "<br>", "\n", "<br>", "\r", "<br>", "|", `\|`).Replace(text)
		table.row, table.open = append(table.row, text), false
	}
}

func (b *officeBlocks) endRow() {
	if table := b.table(); table != nil {
		table.rows, table.row = append(table.rows, table.row), nil
	}
}

// endTable places the table. One inside a cell of another becomes that cell's lines.
func (b *officeBlocks) endTable() {
	table := b.table()
	if table == nil {
		return
	}
	b.tables = b.tables[:len(b.tables)-1]
	if outer := b.table(); outer != nil && outer.open {
		for _, row := range table.rows {
			outer.cell = append(outer.cell, strings.Join(row, " | "))
		}
		return
	}
	b.place(table.markdown(), false)
}

// wordDocument reads a Word document: its body, then the footnotes and endnotes that the body
// refers to. Headers, footers and comments are left out.
func (r *officeReader) wordDocument(body *officeXML, relationships map[string]officeRelationship) error {
	styles, err := r.wordStyles(related(relationships, "styles"))
	if err != nil {
		return err
	}
	blocks := &officeBlocks{out: &r.out}
	if err := r.wordPart(body, blocks, styles, false, ""); err != nil {
		return err
	}
	for _, notes := range []struct{ kind, mark string }{{"footnotes", ""}, {"endnotes", "e"}} {
		part, err := r.part(related(relationships, notes.kind))
		if err != nil {
			return err
		}
		if part == nil {
			continue
		}
		if err := r.wordPart(part, blocks, styles, true, notes.mark); err != nil {
			return err
		}
	}
	return nil
}

// wordStyle is what a paragraph style says of its paragraphs: a heading level from 1, or 0, and
// whether they are list items.
type wordStyle struct {
	heading int
	list    bool
}

// wordStyles reads the paragraph styles by ID. Style IDs follow the language of the author's
// Word, while the names of the built-in styles do not.
func (r *officeReader) wordStyles(name string) (map[string]wordStyle, error) {
	styles := make(map[string]wordStyle)
	part, err := r.part(name)
	if err != nil || part == nil {
		return styles, err
	}
	id := ""
	err = part.each(func(token xmlToken) error {
		start, ok := token, token.kind == xmlStart
		if !ok {
			return nil
		}
		style := styles[id]
		switch string(start.name) {
		case "style":
			id = start.attr("styleId")
			return nil
		case "name":
			name := strings.ToLower(start.attr("val"))
			if level, found := strings.CutPrefix(name, "heading "); found {
				if n, err := strconv.Atoi(level); err == nil && n >= 1 && n <= 9 {
					style.heading = n
				}
			} else if name == "title" {
				style.heading = 1
			}
		case "outlineLvl":
			if n, err := strconv.Atoi(start.attr("val")); err == nil && n >= 0 && n < 9 && style.heading == 0 {
				style.heading = n + 1
			}
		case "numPr":
			style.list = true
		default:
			return nil
		}
		if id != "" {
			styles[id] = style
		}
		return nil
	})
	return styles, err
}

// wordPart reads the paragraphs and tables of the body, or with notes set, of the footnotes or
// endnotes part, where mark tells endnotes from footnotes.
func (r *officeReader) wordPart(part *officeXML, blocks *officeBlocks, styles map[string]wordStyle, notes bool, mark string) error {
	inText := false
	// note is the reference of the open footnote or endnote, whose blocks join into one.
	note := ""
	var noteText []string
	if notes {
		blocks.emit = func(text string, _ bool) { noteText = append(noteText, text) }
		defer func() { blocks.emit = nil }()
	}
	return part.each(func(token xmlToken) error {
		switch token.kind {
		case xmlStart:
			switch string(token.name) {
			// Deleted and moved-away text, the copy of a drawing for older readers, and the
			// earlier formatting of a tracked change are not the document's text.
			case "del", "moveFrom", "Fallback", "pPrChange", "rPrChange", "sectPr":
				return part.skip()
			case "footnote", "endnote":
				// Separator lines are notes with a type.
				if kind := token.attr("type"); notes && kind != "" && kind != "normal" {
					return part.skip()
				}
				note, noteText = "[^"+mark+token.attr("id")+"]", nil
			case "p":
				blocks.startParagraph()
			case "pStyle":
				if paragraph := blocks.paragraph(); paragraph != nil {
					style := styles[token.attr("val")]
					paragraph.heading, paragraph.list = style.heading, style.list
				}
			case "outlineLvl":
				if paragraph := blocks.paragraph(); paragraph != nil {
					if n, err := strconv.Atoi(token.attr("val")); err == nil && n >= 0 && n < 9 {
						paragraph.heading = n + 1
					}
				}
			case "numPr":
				if paragraph := blocks.paragraph(); paragraph != nil {
					paragraph.list = true
				}
			case "ilvl":
				if paragraph := blocks.paragraph(); paragraph != nil {
					paragraph.level, _ = strconv.Atoi(token.attr("val"))
				}
			case "t":
				inText = true
			case "tab":
				blocks.text("\t")
			case "br", "cr":
				blocks.text("\n")
			case "noBreakHyphen":
				blocks.text("-")
			case "footnoteReference":
				blocks.text("[^" + token.attr("id") + "]")
			case "endnoteReference":
				blocks.text("[^e" + token.attr("id") + "]")
			case "tbl":
				blocks.startTable()
			case "tc":
				blocks.startCell()
			}
		case xmlText:
			if inText {
				blocks.bytes(token.text)
			}
		case xmlEnd:
			switch string(token.name) {
			case "t":
				inText = false
			case "p":
				blocks.endParagraph()
			case "tc":
				blocks.endCell()
			case "tr":
				blocks.endRow()
			case "tbl":
				blocks.endTable()
			case "footnote", "endnote":
				if notes && note != "" && len(noteText) > 0 {
					r.out.block(note+": "+strings.Join(noteText, "\n"), false)
				}
				note = ""
			}
		}
		return nil
	})
}

// presentation reads a PowerPoint file: each slide in the order of the slide list, with its
// speaker notes.
func (r *officeReader) presentation(main *officeXML, relationships map[string]officeRelationship) error {
	var slides []string
	err := main.each(func(token xmlToken) error {
		if start := token; start.kind == xmlStart && string(start.name) == "sldId" {
			if relationship, found := relationships[start.prefixed("id")]; found && relationship.kind == "slide" {
				slides = append(slides, relationship.target)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i, slide := range slides {
		r.out.block("## Slide "+strconv.Itoa(i+1), false)
		own, err := r.relationships(slide)
		if err != nil {
			return err
		}
		part, err := r.required(slide)
		if err != nil {
			return err
		}
		blocks := &officeBlocks{out: &r.out, emit: func(text string, _ bool) { r.out.line(text) }}
		if err := r.slidePart(part, blocks, "sldNum", "dt", "ftr"); err != nil {
			return err
		}
		notes, err := r.part(related(own, "notesSlide"))
		if err != nil {
			return err
		}
		if notes == nil {
			continue
		}
		first := true
		blocks.emit = func(text string, _ bool) {
			if first {
				r.out.line("Notes:")
				first = false
			}
			r.out.line(text)
		}
		// A notes page repeats the slide's image, number, date, header and footer.
		if err := r.slidePart(notes, blocks, "sldNum", "sldImg", "dt", "ftr", "hdr"); err != nil {
			return err
		}
	}
	return nil
}

// slidePart reads the paragraphs and tables of a slide or a notes page, except those of the
// placeholders whose types are left out.
func (r *officeReader) slidePart(part *officeXML, blocks *officeBlocks, leaveOut ...string) error {
	inText := false
	return part.each(func(token xmlToken) error {
		switch token.kind {
		case xmlStart:
			switch string(token.name) {
			case "Fallback":
				return part.skip()
			case "sp":
				// A shape names its placeholder before its text.
				return r.slideShape(part, blocks, leaveOut)
			case "p":
				blocks.startParagraph()
			case "pPr":
				if paragraph := blocks.paragraph(); paragraph != nil {
					paragraph.level, _ = strconv.Atoi(token.attr("lvl"))
				}
			case "t":
				inText = true
			case "br":
				blocks.text("\n")
			case "tbl":
				blocks.startTable()
			case "tc":
				blocks.startCell()
			}
		case xmlText:
			if inText {
				blocks.bytes(token.text)
			}
		case xmlEnd:
			switch string(token.name) {
			case "t":
				inText = false
			case "p":
				blocks.endParagraph()
			case "tc":
				blocks.endCell()
			case "tr":
				blocks.endRow()
			case "tbl":
				blocks.endTable()
			}
		}
		return nil
	})
}

// slideShape reads the shape that just started, unless its placeholder is one that is left out.
func (r *officeReader) slideShape(part *officeXML, blocks *officeBlocks, leaveOut []string) error {
	depth := part.depth
	inText := false
	for {
		token, err := part.next()
		if err != nil {
			return err
		}
		switch token.kind {
		case xmlStart:
			switch string(token.name) {
			case "ph":
				kind := token.attr("type")
				for _, left := range leaveOut {
					if kind == left {
						// Leave the placeholder, then the rest of the shape.
						for part.depth >= depth {
							if _, err := part.next(); err != nil {
								return err
							}
						}
						return nil
					}
				}
			case "p":
				blocks.startParagraph()
			case "pPr":
				if paragraph := blocks.paragraph(); paragraph != nil {
					paragraph.level, _ = strconv.Atoi(token.attr("lvl"))
				}
			case "t":
				inText = true
			case "br":
				blocks.text("\n")
			}
		case xmlText:
			if inText {
				blocks.bytes(token.text)
			}
		case xmlEnd:
			switch string(token.name) {
			case "t":
				inText = false
			case "p":
				blocks.endParagraph()
			}
			if part.depth < depth {
				return nil
			}
		}
	}
}

// workbook reads an Excel file: each worksheet in the order of the workbook, as a heading with
// its name and the sheet's rows as CSV.
func (r *officeReader) workbook(main *officeXML, relationships map[string]officeRelationship) error {
	type sheet struct{ name, target string }
	var sheets []sheet
	date1904 := false
	err := main.each(func(token xmlToken) error {
		start, ok := token, token.kind == xmlStart
		if !ok {
			return nil
		}
		switch string(start.name) {
		case "workbookPr":
			date1904 = xmlTrue(start.attr("date1904"))
		case "sheet":
			// Chart sheets and macro sheets hold no cells.
			if relationship, found := relationships[start.prefixed("id")]; found && relationship.kind == "worksheet" {
				sheets = append(sheets, sheet{start.attr("name"), relationship.target})
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	shared, err := r.sharedStrings(related(relationships, "sharedStrings"))
	if err != nil {
		return err
	}
	dates, err := r.dateStyles(related(relationships, "styles"))
	if err != nil {
		return err
	}
	for _, sheet := range sheets {
		r.out.block("## "+strings.TrimSpace(sheet.name), false)
		part, err := r.required(sheet.target)
		if err != nil {
			return err
		}
		if err := r.worksheet(part, shared, dates, date1904); err != nil {
			return err
		}
	}
	return nil
}

func xmlTrue(value string) bool { return value == "1" || value == "true" }

// sharedStrings reads the workbook's string table, which cells refer to by index.
func (r *officeReader) sharedStrings(name string) ([]string, error) {
	part, err := r.part(name)
	if err != nil || part == nil {
		return nil, err
	}
	var table []string
	var item strings.Builder
	inText := false
	err = part.each(func(token xmlToken) error {
		switch token.kind {
		case xmlStart:
			switch string(token.name) {
			case "si":
				item.Reset()
			case "rPh":
				// Phonetic readings repeat the text in another script.
				return part.skip()
			case "t":
				inText = true
			}
		case xmlText:
			if inText {
				item.Write(token.text)
			}
		case xmlEnd:
			switch string(token.name) {
			case "t":
				inText = false
			case "si":
				if r.retain != nil {
					if err := r.retain(item.Len() + 16); err != nil {
						return capacityError{err}
					}
				}
				table = append(table, item.String())
			}
		}
		return nil
	})
	return table, err
}

// dateStyles reports, for each cell format of the workbook, whether it shows a number as a date
// or a time. A cell names its format by index.
func (r *officeReader) dateStyles(name string) ([]bool, error) {
	part, err := r.part(name)
	if err != nil || part == nil {
		return nil, err
	}
	custom := make(map[string]bool)
	var dates []bool
	inFormats := false
	err = part.each(func(token xmlToken) error {
		switch token.kind {
		case xmlStart:
			switch string(token.name) {
			case "numFmt":
				custom[token.attr("numFmtId")] = dateFormat(token.attr("formatCode"))
			case "cellXfs":
				inFormats = true
			case "xf":
				if inFormats {
					id := token.attr("numFmtId")
					date, found := custom[id]
					if !found {
						n, _ := strconv.Atoi(id)
						// The built-in date and time formats, with those of East Asian locales.
						date = n >= 14 && n <= 22 || n >= 27 && n <= 36 || n >= 45 && n <= 47 || n >= 50 && n <= 58
					}
					dates = append(dates, date)
				}
			}
		case xmlEnd:
			if string(token.name) == "cellXfs" {
				inFormats = false
			}
		}
		return nil
	})
	return dates, err
}

// dateFormat reports whether a number format code shows a date or a time: one with a date or
// time letter outside quoted text, escaped characters and bracketed sections. An elapsed time,
// such as [h]:mm, counts hours rather than naming a moment and stays a number.
func dateFormat(code string) bool {
	for i := 0; i < len(code); i++ {
		switch c := code[i]; c {
		case '"':
			end := strings.IndexByte(code[i+1:], '"')
			if end < 0 {
				return false
			}
			i += end + 1
		case '\\', '_', '*':
			i++
		case '[':
			end := strings.IndexByte(code[i:], ']')
			if end < 0 {
				return false
			}
			if section := strings.ToLower(code[i+1 : i+end]); section != "" && strings.Trim(section, "hms") == "" {
				return false
			}
			i += end
		case 'y', 'Y', 'm', 'M', 'd', 'D', 'h', 'H', 's', 'S':
			return true
		}
	}
	return false
}

// excelDate writes a serial date as ISO 8601: a date, a time of day, or both. It reports false
// for a number outside the calendar that Excel shows.
func excelDate(serial float64, date1904 bool) (string, bool) {
	if math.IsNaN(serial) || serial < 0 || serial >= 2958466 {
		return "", false
	}
	days := math.Floor(serial)
	seconds := math.Round((serial - days) * 86400)
	if seconds >= 86400 {
		days, seconds = days+1, 0
	}
	// Day 1 is January 1, 1900, and day 60 is a February 29 that 1900 did not have, so later
	// days count from December 30, 1899.
	epoch := time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC)
	switch {
	case date1904:
		epoch = time.Date(1904, 1, 1, 0, 0, 0, 0, time.UTC)
	case days < 60:
		epoch = time.Date(1899, 12, 31, 0, 0, 0, 0, time.UTC)
	}
	moment := epoch.AddDate(0, 0, int(days)).Add(time.Duration(seconds) * time.Second)
	switch {
	case days == 0 && !date1904:
		return moment.Format("15:04:05"), true
	case seconds == 0:
		return moment.Format("2006-01-02"), true
	}
	return moment.Format("2006-01-02T15:04:05"), true
}

// csvRow collects the cells of a sheet's row by column.
type csvRow struct {
	cells []string
	next  int
}

// set places a value in a column. A column past the widest sheet is dropped.
func (r *csvRow) set(column int, value string) {
	r.next = column + 1
	if value == "" || column < 0 || column >= officeColumns {
		return
	}
	for len(r.cells) <= column {
		r.cells = append(r.cells, "")
	}
	r.cells[column] = value
}

// write writes the row as a line of CSV (RFC 4180) and empties it. An empty row writes nothing.
// Cells can share one long string, so the line stops at the text bound before it is built.
func (r *csvRow) write(out *officeText) {
	cells := r.cells
	r.cells, r.next = r.cells[:0], 0
	if len(cells) == 0 || out.err != nil {
		return
	}
	var line strings.Builder
	for i, cell := range cells {
		if line.Len()+len(cell) > officeTextBytes {
			out.err = errOfficeTooLarge
			return
		}
		if i > 0 {
			line.WriteByte(',')
		}
		if strings.ContainsAny(cell, ",\"\r\n") || cell != strings.TrimSpace(cell) {
			line.WriteString(`"` + strings.ReplaceAll(cell, `"`, `""`) + `"`)
		} else {
			line.WriteString(cell)
		}
	}
	out.line(line.String())
}

// column reads the column of a cell reference such as BC12, from 0, or -1 without one.
func column(reference string) int {
	n := 0
	for i := 0; i < len(reference); i++ {
		c := reference[i] | 0x20
		if c < 'a' || c > 'z' {
			break
		}
		if n = n*26 + int(c-'a') + 1; n > officeColumns {
			return officeColumns
		}
	}
	return n - 1
}

// worksheet writes the rows of a sheet. A cell shows the value that Excel stored for it: a
// formula's last result, and a date or time where the cell's format shows one.
func (r *officeReader) worksheet(part *officeXML, shared []string, dates []bool, date1904 bool) error {
	var row csvRow
	var value strings.Builder
	var kind string
	style, at := 0, 0
	// capture is 1 inside a cell's v element and 2 inside the t elements of its inline string.
	capture := 0
	inline := false
	return part.each(func(token xmlToken) error {
		switch token.kind {
		case xmlStart:
			switch string(token.name) {
			case "c":
				kind = token.attr("t")
				style, _ = strconv.Atoi(token.attr("s"))
				if at = column(token.attr("r")); at < 0 {
					at = row.next
				}
				value.Reset()
			case "v":
				capture = 1
			case "is":
				inline = true
			case "rPh":
				return part.skip()
			case "t":
				if inline {
					capture = 2
				}
			}
		case xmlText:
			if capture != 0 {
				if value.Len()+len(token.text) > officeTextBytes {
					return errOfficeTooLarge
				}
				value.Write(token.text)
			}
		case xmlEnd:
			switch string(token.name) {
			case "v", "t":
				capture = 0
			case "is":
				inline = false
			case "c":
				text := value.String()
				switch kind {
				case "s":
					text = ""
					if i, err := strconv.Atoi(strings.TrimSpace(value.String())); err == nil && i >= 0 && i < len(shared) {
						text = shared[i]
					}
				case "b":
					if text == "1" {
						text = "TRUE"
					} else if text == "0" {
						text = "FALSE"
					}
				case "", "n":
					if style >= 0 && style < len(dates) && dates[style] {
						if serial, err := strconv.ParseFloat(text, 64); err == nil {
							if date, ok := excelDate(serial, date1904); ok {
								text = date
							}
						}
					}
				}
				row.set(at, text)
			case "row":
				// The text bound stops the sheet at once: every further row could copy a
				// shared string again.
				row.write(&r.out)
				return r.out.err
			}
		}
		return nil
	})
}

// openDocument reads an OpenDocument file, whose content.xml holds a text document, a
// spreadsheet or a presentation.
func (r *officeReader) openDocument(declared officeKind) (officeKind, error) {
	part, err := r.required("content.xml")
	if err != nil {
		return 0, err
	}
	var kind officeKind
	body := false
	for kind == 0 {
		token, err := part.next()
		if err != nil {
			return 0, err
		}
		start := token
		switch {
		case start.kind != xmlStart:
		case part.depth == 2:
			body = string(start.name) == "body"
		case part.depth == 3 && body:
			// The body's one child names what the file holds.
			switch string(start.name) {
			case "text":
				kind = officeDocument
			case "spreadsheet":
				kind = officeSpreadsheet
			case "presentation":
				kind = officePresentation
			default:
				return 0, errOfficeUnreadable
			}
		}
	}
	if kind != declared {
		return kind, nil
	}
	return kind, r.openDocumentBody(part, kind)
}

// openDocumentBody reads the body that just started.
func (r *officeReader) openDocumentBody(part *officeXML, kind officeKind) error {
	blocks := &officeBlocks{out: &r.out}
	sheet := kind == officeSpreadsheet
	var row csvRow
	// rows and columns repeat the row or cell that is open.
	rows, columns := 1, 1
	cellValue, cellSet := "", false
	lists, slides := 0, 0
	item := false
	notes := false
	// note is the citation of the open footnote, footnotes the notes of the open paragraph, and
	// restore what takes blocks again after each open note.
	note := ""
	var footnotes []string
	var restore []func(string, bool)
	if kind == officePresentation {
		blocks.emit = func(text string, _ bool) { r.out.line(text) }
	}
	repeated := func(start xmlToken, name string) int { return max(start.number(name, 1), 1) }
	for {
		token, err := part.next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch token.kind {
		case xmlStart:
			switch string(token.name) {
			// Deleted text, comments and a sheet's cell notes are not the file's text.
			case "tracked-changes", "annotation", "forms":
				if err := part.skip(); err != nil {
					return err
				}
			case "note-citation":
				// A footnote shows as its citation, and its text follows the paragraph.
				citation, err := part.text()
				if err != nil {
					return err
				}
				note = "[^" + strings.TrimSpace(citation) + "]"
				blocks.text(note)
			case "note-body":
				outer := blocks.emit
				blocks.emit = func(text string, _ bool) {
					if note != "" {
						text, note = note+": "+text, ""
					}
					footnotes = append(footnotes, text)
				}
				restore = append(restore, outer)
			case "page":
				slides++
				notes = false
				r.out.block("## Slide "+strconv.Itoa(slides), false)
			case "notes":
				notes = true
			case "h":
				paragraph := blocks.startParagraph()
				paragraph.heading = repeated(token, "outline-level")
			case "p":
				paragraph := blocks.startParagraph()
				if lists > 0 && item {
					paragraph.list, paragraph.level, item = true, lists-1, false
				}
			case "list":
				lists++
			case "list-item":
				item = true
			case "s":
				blocks.text(strings.Repeat(" ", min(repeated(token, "c"), 1024)))
			case "tab":
				blocks.text("\t")
			case "line-break":
				blocks.text("\n")
			case "table":
				if sheet {
					r.out.block("## "+strings.TrimSpace(token.attr("name")), false)
				} else {
					blocks.startTable()
				}
			case "table-row":
				rows = repeated(token, "number-rows-repeated")
			case "table-cell", "covered-table-cell":
				if !sheet {
					blocks.startCell()
					break
				}
				columns = repeated(token, "number-columns-repeated")
				cellValue, cellSet = "", false
				switch token.attr("value-type") {
				case "float", "percentage", "currency":
					cellValue, cellSet = token.attr("value"), true
				case "date":
					cellValue, cellSet = token.attr("date-value"), true
				case "boolean":
					cellValue, cellSet = strings.ToUpper(token.attr("boolean-value")), true
				}
				// The cell's paragraphs are its text, which a typed value replaces.
				blocks.startTable()
				blocks.startCell()
			}
		case xmlText:
			blocks.bytes(token.text)
		case xmlEnd:
			switch string(token.name) {
			case "note-body":
				blocks.emit, restore = restore[len(restore)-1], restore[:len(restore)-1]
			case "h", "p":
				if notes && blocks.paragraph() != nil && strings.TrimSpace(blocks.paragraph().text.String()) != "" {
					notes = false
					r.out.line("Notes:")
				}
				blocks.endParagraph()
				if len(blocks.paragraphs) == 0 && len(restore) == 0 {
					for _, text := range footnotes {
						blocks.place(text, false)
					}
					footnotes = nil
				}
			case "list":
				lists--
			case "list-item":
				item = false
			case "table":
				if !sheet {
					blocks.endTable()
				}
			case "table-row":
				if !sheet {
					blocks.endRow()
					break
				}
				cells := append([]string(nil), row.cells...)
				row.write(&r.out)
				// A repeated row with content writes again, within the text bound.
				for n := 1; n < rows && len(cells) > 0 && r.out.err == nil; n++ {
					row.cells = append(row.cells[:0], cells...)
					row.write(&r.out)
				}
			case "table-cell", "covered-table-cell":
				if !sheet {
					blocks.endCell()
					break
				}
				table := blocks.table()
				text := strings.Join(table.cell, "\n")
				blocks.tables = blocks.tables[:len(blocks.tables)-1]
				if cellSet {
					text = cellValue
				}
				at := row.next
				if text == "" {
					row.next = min(at+columns, officeColumns)
					break
				}
				for n := 0; n < columns && at+n < officeColumns; n++ {
					row.set(at+n, text)
				}
			}
		}
		if r.out.err != nil {
			return r.out.err
		}
	}
}
