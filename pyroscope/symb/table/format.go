package table

import (
	"bufio"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
)

type vaTableHeader struct {
	entrySize uint64
	count     uint64
	offset    uint64
	crc       uint32
	_         uint32
}
type rangeTableHeader struct {
	fieldSize uint64
	count     uint64
	offset    uint64
	crc       uint32
	_         uint32
}

type stringsTableHeader struct {
	size   uint64
	offset uint64
	crc    uint32
	_      uint32
}

type header struct {
	// 0
	magic   uint32
	version uint32
	// 8
	vaTableHeader vaTableHeader
	// 40
	rangeTableHeader rangeTableHeader
	// 72
	stringsTableHeader stringsTableHeader
	// 92
}

const headerSize = 96
const fieldsCount = 4
const fieldsEntrySize4 = fieldsCount * 4
const fieldsEntrySize8 = fieldsCount * 8

type rangeEntry struct {
	length     uint64
	depth      uint64
	funcOffset uint64
	fileOffset uint64
}

func writeHeader(output io.Writer, hdr *header) error {
	headerBuf := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(headerBuf[0:], hdr.magic)
	binary.LittleEndian.PutUint32(headerBuf[4:], hdr.version)

	binary.LittleEndian.PutUint64(headerBuf[8:], hdr.vaTableHeader.entrySize)
	binary.LittleEndian.PutUint64(headerBuf[16:], hdr.vaTableHeader.count)
	binary.LittleEndian.PutUint64(headerBuf[24:], hdr.vaTableHeader.offset)
	binary.LittleEndian.PutUint32(headerBuf[32:], hdr.vaTableHeader.crc)

	binary.LittleEndian.PutUint64(headerBuf[40:], hdr.rangeTableHeader.fieldSize)
	binary.LittleEndian.PutUint64(headerBuf[48:], hdr.rangeTableHeader.count)
	binary.LittleEndian.PutUint64(headerBuf[56:], hdr.rangeTableHeader.offset)
	binary.LittleEndian.PutUint32(headerBuf[64:], hdr.rangeTableHeader.crc)

	binary.LittleEndian.PutUint64(headerBuf[72:], hdr.stringsTableHeader.size)
	binary.LittleEndian.PutUint64(headerBuf[80:], hdr.stringsTableHeader.offset)
	binary.LittleEndian.PutUint32(headerBuf[88:], hdr.stringsTableHeader.crc)

	if _, err := output.Write(headerBuf); err != nil {
		return err
	}
	return nil
}

func readHeader(file *os.File) (header, error) {
	headerBuf := make([]byte, headerSize)
	if _, readErr := file.Read(headerBuf); readErr != nil {
		return header{}, readErr
	}
	hdr := header{}
	hdr.magic = binary.LittleEndian.Uint32(headerBuf[0:])
	hdr.version = binary.LittleEndian.Uint32(headerBuf[4:])
	hdr.vaTableHeader.entrySize = binary.LittleEndian.Uint64(headerBuf[8:])
	hdr.vaTableHeader.count = binary.LittleEndian.Uint64(headerBuf[16:])
	hdr.vaTableHeader.offset = binary.LittleEndian.Uint64(headerBuf[24:])
	hdr.vaTableHeader.crc = binary.LittleEndian.Uint32(headerBuf[32:])
	hdr.rangeTableHeader.fieldSize = binary.LittleEndian.Uint64(headerBuf[40:])
	hdr.rangeTableHeader.count = binary.LittleEndian.Uint64(headerBuf[48:])
	hdr.rangeTableHeader.offset = binary.LittleEndian.Uint64(headerBuf[56:])
	hdr.rangeTableHeader.crc = binary.LittleEndian.Uint32(headerBuf[64:])
	hdr.stringsTableHeader.size = binary.LittleEndian.Uint64(headerBuf[72:])
	hdr.stringsTableHeader.offset = binary.LittleEndian.Uint64(headerBuf[80:])
	hdr.stringsTableHeader.crc = binary.LittleEndian.Uint32(headerBuf[88:])

	return hdr, nil
}

func write(f *os.File, rb *rangesBuilder, sb *stringBuilder, opt options) error {
	buf := bufio.NewWriter(f)
	hdr := &header{
		magic:   magic,
		version: version,
	}

	if err := writeHeader(buf, hdr); err != nil {
		return err
	}

	hdr.vaTableHeader.offset = headerSize
	hdr.rangeTableHeader.offset = headerSize
	hdr.stringsTableHeader.offset = headerSize
	hdr.stringsTableHeader.size = uint64(len(sb.buf))

	crc := crc32.New(castagnoli)
	_, _ = crc.Write(sb.buf)
	hdr.stringsTableHeader.crc = crc.Sum32()

	if err := writeRangeEntries(rb, hdr, buf); err != nil {
		return err
	}
	if err := buf.Flush(); err != nil {
		return err
	}

	if _, err := f.Write(sb.buf); err != nil {
		return err
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if err := writeHeader(f, hdr); err != nil {
		return err
	}
	return nil
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func writeRangeEntries(rb *rangesBuilder, hdr *header, buf *bufio.Writer) error {
	hdr.vaTableHeader.count = uint64(len(rb.va))
	hdr.rangeTableHeader.count = uint64(len(rb.entries))
	calculateSizes(rb, hdr)
	vaBuf := make([]byte, hdr.vaTableHeader.entrySize)
	{
		crc := crc32.New(castagnoli)
		ww := io.MultiWriter(crc, buf)
		if hdr.vaTableHeader.entrySize == 4 {
			for i := range rb.va {
				binary.LittleEndian.PutUint32(vaBuf, uint32(rb.va[i]))
				if _, err := ww.Write(vaBuf); err != nil {
					return err
				}
			}
		} else {
			for i := range rb.va {
				binary.LittleEndian.PutUint64(vaBuf, rb.va[i])
				if _, err := ww.Write(vaBuf); err != nil {
					return err
				}
			}
		}
		hdr.vaTableHeader.crc = crc.Sum32()
	}
	bsWritten := len(rb.va) * int(hdr.vaTableHeader.entrySize)
	hdr.rangeTableHeader.offset += uint64(bsWritten)

	{
		crc := crc32.New(castagnoli)
		ww := io.MultiWriter(crc, buf)
		if hdr.rangeTableHeader.fieldSize == 4 {
			entryBuf := make([]byte, fieldsEntrySize4)
			for i := range rb.entries {
				writeFields4(entryBuf, rb.entries[i])
				if _, err := ww.Write(entryBuf); err != nil {
					return err
				}
			}
			bsWritten += len(rb.entries) * fieldsEntrySize4
		} else {
			entryBuf := make([]byte, fieldsEntrySize8)
			for i := range rb.entries {
				writeFields8(entryBuf, rb.entries[i])
				if _, err := ww.Write(entryBuf); err != nil {
					return err
				}
			}
			bsWritten += len(rb.entries) * fieldsEntrySize8
		}
		hdr.rangeTableHeader.crc = crc.Sum32()
	}

	hdr.stringsTableHeader.offset += uint64(bsWritten)

	return nil
}

func writeFields8(entryBuf []byte, e rangeEntry) {
	binary.LittleEndian.PutUint64(entryBuf[0:], e.length)
	binary.LittleEndian.PutUint64(entryBuf[8:], e.depth)
	binary.LittleEndian.PutUint64(entryBuf[16:], e.funcOffset)
	binary.LittleEndian.PutUint64(entryBuf[24:], e.fileOffset)
}

func writeFields4(entryBuf []byte, e rangeEntry) {
	binary.LittleEndian.PutUint32(entryBuf[0:], uint32(e.length))
	binary.LittleEndian.PutUint32(entryBuf[4:], uint32(e.depth))
	binary.LittleEndian.PutUint32(entryBuf[8:], uint32(e.funcOffset))
	binary.LittleEndian.PutUint32(entryBuf[12:], uint32(e.fileOffset))
}

func readFields8(entryBuf []byte) rangeEntry {
	return rangeEntry{
		length:     binary.LittleEndian.Uint64(entryBuf[0:]),
		depth:      binary.LittleEndian.Uint64(entryBuf[8:]),
		funcOffset: binary.LittleEndian.Uint64(entryBuf[16:]),
		fileOffset: binary.LittleEndian.Uint64(entryBuf[24:]),
	}
}

func readFields4(entryBuf []byte) rangeEntry {
	return rangeEntry{
		length:     uint64(binary.LittleEndian.Uint32(entryBuf[0:])),
		depth:      uint64(binary.LittleEndian.Uint32(entryBuf[4:])),
		funcOffset: uint64(binary.LittleEndian.Uint32(entryBuf[8:])),
		fileOffset: uint64(binary.LittleEndian.Uint32(entryBuf[12:])),
	}
}

func calculateSizes(rb *rangesBuilder, hdr *header) {
	const maxUint32 = uint64(^uint32(0))
	hdr.vaTableHeader.entrySize = 4
	hdr.rangeTableHeader.fieldSize = 4
	for _, va := range rb.va {
		if va > maxUint32 {
			hdr.vaTableHeader.entrySize = 8
			break
		}
	}

	for _, e := range rb.entries {
		if e.length > maxUint32 || e.depth > maxUint32 || e.funcOffset > maxUint32 || e.fileOffset > maxUint32 {
			hdr.rangeTableHeader.fieldSize = 8
			break
		}
	}
}
