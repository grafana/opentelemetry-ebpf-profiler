package gsym

import (
	"bufio"
	"encoding/binary"
	"os"
)

type FileWriter struct {
	offset int64
	err    error

	tmpbuf [8]byte
	bw     *bufio.Writer
	inner  *os.File
}

func NewFileWriter(f *os.File) *FileWriter {
	return &FileWriter{inner: f, bw: bufio.NewWriter(f)}
}

func (w *FileWriter) Write(data []byte) {
	if w.err != nil {
		return
	}
	_, w.err = w.bw.Write(data)
	w.offset += int64(len(data))
}

func (w *FileWriter) WriteU8(v uint8) {
	if w.err != nil {
		return
	}
	w.Write([]byte{v})
}

func (w *FileWriter) WriteU16(v uint16) {
	if w.err != nil {
		return
	}
	buf := w.tmpbuf[:2]
	binary.LittleEndian.PutUint16(buf, v)
	w.Write(buf)
}

func (w *FileWriter) WriteU32(v uint32) {
	if w.err != nil {
		return
	}
	buf := w.tmpbuf[:4]
	binary.LittleEndian.PutUint32(buf, v)
	w.Write(buf)
}

func (w *FileWriter) WriteU64(v uint64) {
	if w.err != nil {
		return
	}
	buf := w.tmpbuf[:8]
	binary.LittleEndian.PutUint64(buf, v)
	w.Write(buf)
}

func (w *FileWriter) WriteULEB(v uint64) {
	if w.err != nil {
		return
	}
	for {
		b := uint8(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		w.WriteU8(b)
		if v == 0 {
			break
		}
	}
}

func (w *FileWriter) Tell() int64 {
	return w.offset
}

func (w *FileWriter) AlignTo(align int64) {
	if w.err != nil {
		return
	}
	padding := (align - (w.offset % align)) % align
	if padding == 0 {
		return
	}
	w.Write(make([]byte, padding))
}

func (w *FileWriter) Flush() {
	if w.err != nil {
		return
	}
	w.err = w.bw.Flush()
}

func (w *FileWriter) Fixup32(value uint32, offset int64) {
	if w.err != nil {
		return
	}
	buf := w.tmpbuf[:4]
	binary.LittleEndian.PutUint32(buf, value)
	_, w.err = w.inner.WriteAt(buf, offset)
}

func (w *FileWriter) Fixup(value []byte, offset int64) {
	if w.err != nil {
		return
	}
	_, w.err = w.inner.WriteAt(value, offset)
}
