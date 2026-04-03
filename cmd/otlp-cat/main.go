package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
)

func main() {
	exeFilter := flag.String("exe", "cat", "filter by process.executable.name")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [-exe name] <file.pb.bin>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(1)
	}
	req := pprofileotlp.NewExportRequest()
	if err := req.UnmarshalProto(data); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal: %v\n", err)
		os.Exit(1)
	}

	profiles := req.Profiles()
	dic := profiles.Dictionary()
	strTab := dic.StringTable()

	str := func(idx int32) string {
		if idx >= 0 && int(idx) < strTab.Len() {
			return strTab.At(int(idx))
		}
		return fmt.Sprintf("<invalid-str-%d>", idx)
	}

	rps := profiles.ResourceProfiles()
	for i := 0; i < rps.Len(); i++ {
		rp := rps.At(i)
		attrs := rp.Resource().Attributes()
		exeName := attrStr(attrs, "process.executable.name")
		if *exeFilter != "" && exeName != *exeFilter {
			continue
		}

		pid := attrInt(attrs, "process.pid")
		exePath := attrStr(attrs, "process.executable.path")
		fmt.Printf("=== resource: pid=%d exe=%s path=%s ===\n", pid, exeName, exePath)

		sps := rp.ScopeProfiles()
		for j := 0; j < sps.Len(); j++ {
			sp := sps.At(j)
			profs := sp.Profiles()
			for k := 0; k < profs.Len(); k++ {
				prof := profs.At(k)
				printProfile(prof, dic, str)
			}
		}
	}
}

func printProfile(prof pprofile.Profile, dic pprofile.ProfilesDictionary, str func(int32) string) {
	t := prof.Time().AsTime()
	dur := time.Duration(prof.DurationNano())
	sampleTypeName := str(prof.SampleType().TypeStrindex())
	sampleTypeUnit := str(prof.SampleType().UnitStrindex())
	fmt.Printf("\n  profile: time=%s duration=%s sampleType=%s/%s samples=%d\n",
		t.Format(time.RFC3339Nano), dur, sampleTypeName, sampleTypeUnit, prof.Samples().Len())

	attrTab := dic.AttributeTable()
	samples := prof.Samples()
	for i := 0; i < samples.Len(); i++ {
		s := samples.At(i)
		fmt.Printf("\n  sample #%d  values=%v  timestamps=%d\n",
			i, int64SliceToSlice(s.Values()), s.TimestampsUnixNano().Len())

		printSampleAttrs(s.AttributeIndices(), attrTab, str)
		printStack(s.StackIndex(), dic, str)
	}
}

func printStack(stackIdx int32, dic pprofile.ProfilesDictionary, str func(int32) string) {
	stackTab := dic.StackTable()
	if stackIdx <= 0 || int(stackIdx) >= stackTab.Len() {
		fmt.Printf("    stack: <none>\n")
		return
	}
	stack := stackTab.At(int(stackIdx))
	locIndices := stack.LocationIndices()
	locTab := dic.LocationTable()
	funcTab := dic.FunctionTable()
	mapTab := dic.MappingTable()
	attrTab := dic.AttributeTable()

	fmt.Printf("    stack (%d frames):\n", locIndices.Len())
	for i := 0; i < locIndices.Len(); i++ {
		locIdx := locIndices.At(i)
		if int(locIdx) >= locTab.Len() {
			fmt.Printf("      [%d] <invalid-loc-%d>\n", i, locIdx)
			continue
		}
		loc := locTab.At(int(locIdx))
		addr := loc.Address()

		mappingName := ""
		if mi := loc.MappingIndex(); mi > 0 && int(mi) < mapTab.Len() {
			mappingName = str(mapTab.At(int(mi)).FilenameStrindex())
		}

		frameType := locAttrStr(loc.AttributeIndices(), attrTab, str, "profile.frame.type")

		lines := loc.Lines()
		if lines.Len() == 0 {
			fmt.Printf("      [%d] 0x%x", i, addr)
			printFrameMeta(mappingName, frameType)
			continue
		}
		for li := 0; li < lines.Len(); li++ {
			line := lines.At(li)
			funcIdx := line.FunctionIndex()
			funcName := "<unknown>"
			fileName := ""
			if int(funcIdx) < funcTab.Len() {
				f := funcTab.At(int(funcIdx))
				funcName = str(f.NameStrindex())
				fileName = str(f.FilenameStrindex())
			}
			source := ""
			if fileName != "" {
				source = fmt.Sprintf(" %s:%d", fileName, line.Line())
			}
			fmt.Printf("      [%d] 0x%x %s%s", i, addr, funcName, source)
			printFrameMeta(mappingName, frameType)
		}
	}
}

func printFrameMeta(mapping, frameType string) {
	var parts []string
	if mapping != "" {
		parts = append(parts, mapping)
	}
	if frameType != "" {
		parts = append(parts, frameType)
	}
	if len(parts) > 0 {
		fmt.Printf("  [%s]\n", strings.Join(parts, " "))
	} else {
		fmt.Println()
	}
}

func locAttrStr(indices pcommon.Int32Slice, attrTab pprofile.KeyValueAndUnitSlice, str func(int32) string, key string) string {
	for i := 0; i < indices.Len(); i++ {
		idx := indices.At(i)
		if int(idx) >= attrTab.Len() {
			continue
		}
		a := attrTab.At(int(idx))
		if str(a.KeyStrindex()) == key {
			return a.Value().AsString()
		}
	}
	return ""
}

func printSampleAttrs(indices pcommon.Int32Slice, attrTab pprofile.KeyValueAndUnitSlice, str func(int32) string) {
	if indices.Len() == 0 {
		return
	}
	var parts []string
	for i := 0; i < indices.Len(); i++ {
		idx := indices.At(i)
		if int(idx) >= attrTab.Len() {
			continue
		}
		a := attrTab.At(int(idx))
		key := str(a.KeyStrindex())
		val := a.Value().AsString()
		parts = append(parts, fmt.Sprintf("%s=%s", key, val))
	}
	fmt.Printf("    attrs: %s\n", strings.Join(parts, " "))
}

func int64SliceToSlice(s pcommon.Int64Slice) []int64 {
	out := make([]int64, s.Len())
	for i := 0; i < s.Len(); i++ {
		out[i] = s.At(i)
	}
	return out
}

func attrStr(m pcommon.Map, key string) string {
	v, ok := m.Get(key)
	if !ok {
		return ""
	}
	return v.Str()
}

func attrInt(m pcommon.Map, key string) int64 {
	v, ok := m.Get(key)
	if !ok {
		return 0
	}
	return v.Int()
}
