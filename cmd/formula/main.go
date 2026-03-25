package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"text/template"
	"time"
)

var formulaTmpl = template.Must(template.New("formula").Parse(formulaTemplate))

const formulaTemplate = `class Ghasec < Formula
  desc ""
  homepage "https://github.com/koki-develop/ghasec"
  version "{{.Version}}"
  license "MIT"

  on_macos do
    on_intel do
      url "https://github.com/koki-develop/ghasec/releases/download/v#{version}/ghasec_Darwin_x86_64.tar.gz"
      sha256 "{{.Darwin_x86_64}}"
    end
    on_arm do
      url "https://github.com/koki-develop/ghasec/releases/download/v#{version}/ghasec_Darwin_arm64.tar.gz"
      sha256 "{{.Darwin_arm64}}"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/koki-develop/ghasec/releases/download/v#{version}/ghasec_Linux_x86_64.tar.gz"
      sha256 "{{.Linux_x86_64}}"
    end
    on_arm do
      url "https://github.com/koki-develop/ghasec/releases/download/v#{version}/ghasec_Linux_arm64.tar.gz"
      sha256 "{{.Linux_arm64}}"
    end
  end

  def install
    bin.install "ghasec"
  end

  test do
    system "#{bin}/ghasec", "--help"
  end
end
`

var archiveKeys = []string{
	"Darwin_x86_64",
	"Darwin_arm64",
	"Linux_x86_64",
	"Linux_arm64",
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	version := flag.String("version", "", "release version (e.g. 0.0.2)")
	flag.Parse()

	if *version == "" {
		return fmt.Errorf("-version is required")
	}

	shas, err := fetchSHA256s(*version)
	if err != nil {
		return err
	}
	for _, key := range archiveKeys {
		if _, ok := shas[key]; !ok {
			return fmt.Errorf("missing SHA256 for %s", key)
		}
	}
	shas["Version"] = *version

	var buf bytes.Buffer
	if err := formulaTmpl.Execute(&buf, shas); err != nil {
		return fmt.Errorf("rendering formula: %w", err)
	}
	_, err = buf.WriteTo(os.Stdout)
	if err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

func fetchSHA256s(version string) (map[string]string, error) {
	var mu sync.Mutex
	shas := make(map[string]string)
	errs := make([]error, len(archiveKeys))

	var wg sync.WaitGroup
	for i, key := range archiveKeys {
		wg.Go(func() {
			url := fmt.Sprintf(
				"https://github.com/koki-develop/ghasec/releases/download/v%s/ghasec_%s.tar.gz",
				version, key,
			)
			sha, err := downloadSHA256(url)
			if err != nil {
				errs[i] = fmt.Errorf("%s: %w", key, err)
				return
			}
			mu.Lock()
			shas[key] = sha
			mu.Unlock()
		})
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return shas, nil
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

func downloadSHA256(url string) (string, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("downloading %s: status %d", url, resp.StatusCode)
	}

	h := sha256.New()
	if _, err := io.Copy(h, resp.Body); err != nil {
		return "", fmt.Errorf("reading %s: %w", url, err)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
