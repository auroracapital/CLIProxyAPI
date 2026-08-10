package cmd

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"gopkg.in/yaml.v3"
)

func TestDoPluginInstallPreservesConfigAndPersistsManifest(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	pluginsDir := filepath.Join(workspace, "plugins")
	configPath := filepath.Join(workspace, "config.yaml")
	initial := "plugins:\n  enabled: false\n  dir: " + strconvQuoteYAML(pluginsDir) + "\n  configs:\n    sample-provider:\n      enabled: false\n      priority: 7\n      mode: fast\n"
	if errWrite := os.WriteFile(configPath, []byte(initial), 0o600); errWrite != nil {
		t.Fatalf("WriteFile(config) error = %v", errWrite)
	}
	cfg, errLoad := config.LoadConfig(configPath)
	if errLoad != nil {
		t.Fatalf("LoadConfig() error = %v", errLoad)
	}

	archiveData := makePluginInstallZip(t, "sample-provider.so", "library-data")
	archiveName := "sample-provider_1.4.0_linux_amd64.zip"
	checksum := sha256.Sum256(archiveData)
	httpClient := pluginInstallHTTPDoer{
		"https://api.github.com/repos/example/sample-plugin/releases/latest": []byte(`{
			"tag_name": "v1.4.0",
			"assets": [
				{"name": "` + archiveName + `", "browser_download_url": "https://downloads.example/` + archiveName + `"},
				{"name": "checksums.txt", "browser_download_url": "https://downloads.example/checksums.txt"}
			]
		}`),
		"https://downloads.example/" + archiveName: archiveData,
		"https://downloads.example/checksums.txt":  []byte(hex.EncodeToString(checksum[:]) + "  " + archiveName + "\n"),
	}
	var output bytes.Buffer
	persistCalls := 0
	result, errInstall := DoPluginInstall(context.Background(), cfg, configPath, PluginInstallOptions{
		Repository: "https://github.com/example/sample-plugin",
		GOOS:       "linux",
		GOARCH:     "amd64",
		HTTPClient: httpClient,
		Output:     &output,
		PersistConfig: func(context.Context) error {
			persistCalls++
			return nil
		},
	})
	if errInstall != nil {
		t.Fatalf("DoPluginInstall() error = %v", errInstall)
	}
	if persistCalls != 1 {
		t.Fatalf("PersistConfig calls = %d, want 1", persistCalls)
	}
	if result.ID != "sample-provider" || result.Version != "1.4.0" {
		t.Fatalf("result = %#v", result)
	}
	if !strings.Contains(output.String(), "Global plugin loading is disabled") {
		t.Fatalf("output missing global disabled warning:\n%s", output.String())
	}

	saved, errSaved := config.LoadConfig(configPath)
	if errSaved != nil {
		t.Fatalf("LoadConfig(saved) error = %v", errSaved)
	}
	if saved.Plugins.Enabled {
		t.Fatal("Plugins.Enabled = true, want unchanged false")
	}
	item := saved.Plugins.Configs["sample-provider"]
	if item.Enabled == nil || !*item.Enabled || item.Priority != 7 {
		t.Fatalf("saved plugin config = %#v, want enabled with priority 7", item)
	}
	raw, errMarshal := yaml.Marshal(&item.Raw)
	if errMarshal != nil {
		t.Fatalf("Marshal(plugin raw) error = %v", errMarshal)
	}
	text := string(raw)
	for _, want := range []string{"mode: fast", "store:", "release-tag: v1.4.0", "repository: https://github.com/example/sample-plugin"} {
		if !strings.Contains(text, want) {
			t.Fatalf("saved plugin config missing %q:\n%s", want, text)
		}
	}
	wantPath := filepath.Join(pluginsDir, "linux", "amd64", "sample-provider-v1.4.0.so")
	if data, errRead := os.ReadFile(wantPath); errRead != nil || string(data) != "library-data" {
		t.Fatalf("installed plugin = %q, error = %v", data, errRead)
	}

	var failedOutput bytes.Buffer
	_, errPersist := DoPluginInstall(context.Background(), cfg, configPath, PluginInstallOptions{
		Repository: "https://github.com/example/sample-plugin",
		GOOS:       "linux",
		GOARCH:     "amd64",
		HTTPClient: httpClient,
		Output:     &failedOutput,
		PersistConfig: func(context.Context) error {
			return errors.New("backend unavailable")
		},
	})
	if errPersist == nil || !strings.Contains(errPersist.Error(), "local config updated") || !strings.Contains(errPersist.Error(), "backend unavailable") {
		t.Fatalf("DoPluginInstall() persistence error = %v", errPersist)
	}
	if failedOutput.Len() != 0 {
		t.Fatalf("failed persistence printed success output:\n%s", failedOutput.String())
	}
}

func TestDoPluginInstallRejectsUnavailableConfigBeforeInstalling(t *testing.T) {
	t.Parallel()

	pluginsDir := t.TempDir()
	cfg := &config.Config{Plugins: config.PluginsConfig{Dir: pluginsDir}}
	cfg.NormalizePluginsConfig()
	archiveData := makePluginInstallZip(t, "sample.so", "library-data")
	archiveName := "sample_1.0.0_linux_amd64.zip"
	checksum := sha256.Sum256(archiveData)
	httpClient := pluginInstallHTTPDoer{
		"https://api.github.com/repos/example/sample/releases/latest": []byte(`{
			"tag_name": "v1.0.0",
			"assets": [
				{"name": "` + archiveName + `", "browser_download_url": "https://downloads.example/` + archiveName + `"},
				{"name": "checksums.txt", "browser_download_url": "https://downloads.example/checksums.txt"}
			]
		}`),
		"https://downloads.example/" + archiveName: archiveData,
		"https://downloads.example/checksums.txt":  []byte(hex.EncodeToString(checksum[:]) + "  " + archiveName + "\n"),
	}

	_, errInstall := DoPluginInstall(context.Background(), cfg, filepath.Join(pluginsDir, "missing", "config.yaml"), PluginInstallOptions{
		Repository: "https://github.com/example/sample",
		GOOS:       "linux",
		GOARCH:     "amd64",
		HTTPClient: httpClient,
		Output:     io.Discard,
	})
	if errInstall == nil || !strings.Contains(errInstall.Error(), "config file is unavailable") {
		t.Fatalf("DoPluginInstall() error = %v, want config preflight error", errInstall)
	}
	wantPath := filepath.Join(pluginsDir, "linux", "amd64", "sample-v1.0.0.so")
	if _, errStat := os.Stat(wantPath); !os.IsNotExist(errStat) {
		t.Fatalf("installed plugin stat error = %v, want file not created", errStat)
	}
}

func strconvQuoteYAML(value string) string {
	return strconv.Quote(value)
}

func makePluginInstallZip(t *testing.T, name, content string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	file, errCreate := writer.Create(name)
	if errCreate != nil {
		t.Fatalf("Create(%s) error = %v", name, errCreate)
	}
	if _, errWrite := file.Write([]byte(content)); errWrite != nil {
		t.Fatalf("Write(%s) error = %v", name, errWrite)
	}
	if errClose := writer.Close(); errClose != nil {
		t.Fatalf("Close() error = %v", errClose)
	}
	return buffer.Bytes()
}

type pluginInstallHTTPDoer map[string][]byte

func (d pluginInstallHTTPDoer) Do(req *http.Request) (*http.Response, error) {
	body, ok := d[req.URL.String()]
	status := http.StatusOK
	if !ok {
		status = http.StatusNotFound
		body = []byte("not found")
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}
