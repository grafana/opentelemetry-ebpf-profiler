package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

func main() {
	// Create output directory
	err := os.MkdirAll("out", 0755)
	if err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		return
	}

	// Read pods from file
	file, err := os.Open("pods.txt")
	if err != nil {
		fmt.Printf("Error opening pods.txt: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		podName := strings.Fields(scanner.Text())[0]
		processPod(podName)
	}
}

var lock sync.Mutex

func processPod(podName string) {
	fmt.Printf("Processing pod %s\n", podName)
	// Start port-forward with random local port
	PATH := "/home/korniltsev/.nvm/versions/node/v23.6.0/bin:/home/korniltsev/.pyenv/shims:/home/korniltsev/.pyenv/bin:/home/korniltsev/trash/google-cloud-sdk/bin:/home/korniltsev/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/home/korniltsev/.local/bin:/home/korniltsev/sdk/go1.23.4/go/bin:/home/korniltsev/go/bin"
	cmd := exec.Command("/home/korniltsev/.local/bin/kubectl", "port-forward", podName, ":7239", "-n", "pyroscope-ebpf-otel-dev-001")
	cmd.Env = append(os.Environ(), fmt.Sprintf("PATH=%s", PATH))

	// Create pipes for stdout
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Error starting port-forward for %s: %v\n", podName, err)
		return
	}

	// Read the first line of output to get the port
	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil {
		err2, _ := io.ReadAll(stderr)
		fmt.Printf("Error reading port-forward output for %s: %v stderr %s\n", podName, err, err2)
		cmd.Process.Kill()
		return
	}

	// Extract port number using regex
	re := regexp.MustCompile(`Forwarding from [^:]+:(\d+)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) != 2 {
		fmt.Printf("Could not parse port from output for %s: %s\n", podName, line)
		cmd.Process.Kill()
		return
	}

	localPort := matches[1]
	fmt.Printf("Using local port %s for pod %s\n", localPort, podName)

	// Wait a bit for port-forward to establish
	time.Sleep(2 * time.Second)

	// Get list of file IDs using the detected port
	resp, err := http.Get(fmt.Sprintf("http://localhost:%s/binaries", localPort))
	if err != nil {
		fmt.Printf("Error getting binaries for %s: %v\n", podName, err)
		cmd.Process.Kill()
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response for %s: %v\n", podName, err)
		cmd.Process.Kill()
		return
	}

	// Process each file ID
	fids := strings.Split(string(body), "\n")
	fmt.Printf("total files %d\n", len(fids))
	for idx, fid := range fids {
		fid = strings.TrimSpace(fid)
		if fid == "" {
			continue
		}

		lock.Lock()
		if alreadyDownloaded(fid) {
			fmt.Printf("File %s already downloaded, skipping\n", fid)
			lock.Unlock()
			continue
		}
		outPath := filepath.Join("out", fid+".tar.zst")
		out, err := os.Create(outPath)
		lock.Unlock()
		if err != nil {
			fmt.Printf("Error creating output file for %s: %v\n", fid, err)
			continue
		}

		// Download the file using the detected port
		if err := downloadFile(fid, localPort, out); err != nil {
			fmt.Printf("Error downloading %s from %s: %v\n", fid, podName, err)
			os.Remove(outFilePath(fid))
			continue
		}

		fmt.Printf("Successfully downloaded file # %4d fid = %s from %s\n", idx, fid, podName)
	}

	// Kill port-forward process
	cmd.Process.Kill()
}

func alreadyDownloaded(fid string) bool {
	_, err := os.Stat(outFilePath(fid))
	return err == nil
}

func outFilePath(fid string) string {
	return filepath.Join("out", fid+".tar.zst")
}

func downloadFile(fid, port string, out *os.File) error {
	defer out.Close()
	resp, err := http.Get(fmt.Sprintf("http://localhost:%s/binaries?fid=%s", port, fid))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	fmt.Printf("downloading %s... ", fid)

	_, err = io.Copy(out, resp.Body)
	return err
}
