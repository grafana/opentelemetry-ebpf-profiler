package python

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/coredumpstore"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
)

type extractor interface {
	extract(t testing.TB) (elf, debugElf *pfelf.Reference)
	id() string
	version() Version
}
type dockerPythonExtractor struct {
	name       string
	debugName  string
	base       string
	dockerfile string
	withDebug  bool
	ver        Version
}

func (e dockerPythonExtractor) id() string {
	return e.name
}
func (e dockerPythonExtractor) version() Version {
	return e.ver
}
func (e dockerPythonExtractor) extract(t testing.TB) (elfRef, debugElfRef *pfelf.Reference) {
	//d := filepath.Join("extractorcache", e.name)
	d := filepath.Join("/home/korniltsev/p/opentelemetry-ebpf-profiler/interpreter/python/extractorcache", e.name)
	t.Logf("%s %s", e.name, d)
	_, err := os.Stat(d)
	t.Cleanup(func() {
		if t.Failed() {
			_ = os.RemoveAll(d)
		}
	})
	if err != nil {
		err = os.MkdirAll(d, 0o777)
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(d, "Dockerfile"), []byte(e.dockerfile), 0o600)
		require.NoError(t, err)
		c := exec.Command("docker", "build",
			"--output=.",
			".")
		buffer := bytes.NewBuffer(nil)
		c.Stderr = buffer
		c.Dir = d
		err = c.Run()
		if err != nil {
			t.Skip(err.Error(), buffer.String())
		}
	}

	es, err := os.ReadDir(d)
	require.NoError(t, err)
	if e.withDebug {
		require.Len(t, es, 3)
	} else {
		require.Len(t, es, 2)
	}
	elfPath, debugElfPath := "", ""
	for _, entry := range es {
		n := entry.Name()
		if n == "Dockerfile" {
			continue
		}
		if strings.Contains(n, ".debug") {
			debugElfPath = n
		} else {
			elfPath = n
		}
	}
	t.Logf("%s %s", elfPath, debugElfPath)

	elfPath = filepath.Join(d, elfPath)

	elfRef = pfelf.NewReference(elfPath, pfelf.SystemOpener)
	elf, err := elfRef.GetELF()
	require.NoError(t, err)
	t.Cleanup(func() {
		elfRef.Close()
	})
	if e.withDebug {
		debugElfRef = pfelf.NewReference(filepath.Join(d, debugElfPath), pfelf.SystemOpener)
		_, err = debugElfRef.GetELF()
		require.NoError(t, err)
		t.Cleanup(func() {
			debugElfRef.Close()
		})
	} else {
		s, _ := elf.ReadSymbols()
		if s != nil {
			_, err = s.LookupSymbolAddress("_PyEval_EvalFrameDefault.cold")
			if err == nil {
				debugElfRef = elfRef
			}
		}
	}

	return elfRef, debugElfRef
}

func alpine(base string, ver Version) dockerPythonExtractor {
	dockerfile := fmt.Sprintf(`
FROM %s as builder
RUN apk add python3 python3-dbg
RUN mkdir /out
RUN cp /usr/lib/debug/usr/lib/libpython*1.0.debug /out
RUN cp /usr/lib/libpython*1.0 /out
FROM scratch
COPY --from=builder /out /
`, base)
	return dockerPythonExtractor{
		ver:        ver,
		debugName:  "",
		name:       "alpine:" + base,
		dockerfile: dockerfile,
		withDebug:  true,
	}
}

func python(base, debugName string, version Version) dockerPythonExtractor {
	dockerfile := fmt.Sprintf(`
FROM %s as builder
RUN mkdir /out
RUN cp /usr/local/lib/libpython*1.0 /out
FROM scratch
COPY --from=builder /out /
`, base)
	return dockerPythonExtractor{
		ver:        version,
		debugName:  debugName,
		base:       base,
		name:       "python:" + base,
		dockerfile: dockerfile,
		withDebug:  false,
	}
}

func debian(base string, ver Version) dockerPythonExtractor {
	dockerfile := fmt.Sprintf(`
FROM %s as builder
RUN apt-get update && apt-get -y install  python3 python3-dbg binutils original-awk grep
RUN <<EOF
set -ex
mkdir /out
cp /usr/bin/$(readlink /usr/bin/python3) /out
build_id=$(readelf -n /usr/bin/$(readlink /usr/bin/python3) | grep "Build ID" | awk '{print $3}')
dir_name=$(echo "$build_id" | cut -c1-2)
file_name=$(echo "$build_id" | cut -c3-).debug
debug_file_path="/usr/lib/debug/.build-id/$dir_name/$file_name"
cp $debug_file_path /out/$(readlink /usr/bin/python3).debug
EOF
FROM scratch
COPY --from=builder /out /
`, base)
	return dockerPythonExtractor{
		ver:        ver,
		debugName:  "",
		name:       "debian:" + base,
		dockerfile: dockerfile,
		withDebug:  true,
	}
}

type storeExtractor struct {
	ver     Version
	storeID string
}

func (e storeExtractor) id() string {
	return e.storeID
}
func (e storeExtractor) version() Version {
	return e.ver
}

func (e storeExtractor) extract(t testing.TB) (elf, debugElf *pfelf.Reference) {
	s, err := coredumpstore.New()
	require.NoError(t, err)
	parsedID, err := modulestore.IDFromString(e.id())
	require.NoError(t, err)
	buf := bytes.NewBuffer(nil)
	err = s.UnpackModule(parsedID, buf)
	require.NoError(t, err)

	tempFile := filepath.Join(t.TempDir(), e.storeID)
	err = os.WriteFile(tempFile, buf.Bytes(), 0o600)
	require.NoError(t, err)

	fileRef := pfelf.NewReference(tempFile, pfelf.SystemOpener)
	_, err = fileRef.GetELF()
	require.NoError(t, err)
	t.Cleanup(func() {
		fileRef.Close()
	})
	return fileRef, nil
}
