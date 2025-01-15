package main

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"go.opentelemetry.io/ebpf-profiler/processmanager"
	"net/http"
	"strings"

	"github.com/klauspost/compress/zstd"
)

func binariesHandler(writer http.ResponseWriter, request *http.Request) {
	if ctlr == nil {
		return
	}
	fid := request.URL.Query().Get("fid")
	verbose := request.URL.Query().Get("verbose") == "true"
	_ = "verbose"
	if fid == "" {
		fids := ctlr.Tracer.ProcessManager.AllKnownFiles()
		ss := make([]string, 0, len(fids))
		for fid := range fids {
			if verbose {
				ss = append(ss, fid.StringNoQuotes()+" "+verboseInfo(fid.StringNoQuotes()))
			} else {
				ss = append(ss, fid.StringNoQuotes())
			}
		}
		fmt.Fprintf(writer, "%s", strings.Join(ss, "\n"))
		return
	}

	// Get file info for the specific FID
	info := ctlr.Tracer.ProcessManager.CollectFileInfo(fid)
	if info.File == nil {
		http.Error(writer, "File not found", http.StatusNotFound)
		return
	}

	// Create and send tar archive
	if err := createTarArchive(writer, fid, info); err != nil {
		http.Error(writer, fmt.Sprintf("Error creating archive: %v", err), http.StatusInternalServerError)
		return
	}
}

func verboseInfo(fid string) string {
	info := ctlr.Tracer.ProcessManager.CollectFileInfo(fid)
	info.File = nil
	info.DebugFile = nil
	marshal, _ := json.Marshal(info)
	return string(marshal)
}

func createTarArchive(writer http.ResponseWriter, fid string, info processmanager.FileInfo) error {
	// Set response headers for tar.zst file download
	writer.Header().Set("Content-Type", "application/x-tar+zstd")
	writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.tar.zst", fid))

	// Create zstd compression writer
	zstdWriter, err := zstd.NewWriter(writer)
	if err != nil {
		return fmt.Errorf("failed to create zstd writer: %v", err)
	}
	defer zstdWriter.Close()

	// Create tar writer on top of zstd writer
	tarWriter := tar.NewWriter(zstdWriter)
	defer tarWriter.Close()

	// Helper function to add file to tar archive
	addFile := func(name string, content []byte) error {
		header := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header for %s: %v", name, err)
		}
		if _, err := tarWriter.Write(content); err != nil {
			return fmt.Errorf("failed to write file content for %s: %v", name, err)
		}
		return nil
	}

	// Add binary file
	if err := addFile("./file", info.File); err != nil {
		return err
	}

	// Add debug file if present
	if len(info.DebugFile) > 0 {
		if err := addFile("./debug", info.DebugFile); err != nil {
			return err
		}
	}

	info.File = nil
	info.DebugFile = nil
	infoJson, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal info.json: %v", err)
	}
	if err := addFile("./info.json", infoJson); err != nil {
		return err
	}

	return nil
}
