package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/pluginstore"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"gopkg.in/yaml.v3"
)

// PluginInstallOptions configures a one-shot GitHub Release plugin install.
type PluginInstallOptions struct {
	Repository    string
	Version       string
	ID            string
	GOOS          string
	GOARCH        string
	HTTPClient    pluginstore.HTTPDoer
	PersistConfig func(context.Context) error
	Output        io.Writer
}

// DoPluginInstall installs a standard GitHub Release plugin, records its
// pinned release manifest in config, and prints a concise result summary.
func DoPluginInstall(ctx context.Context, cfg *config.Config, configPath string, options PluginInstallOptions) (pluginstore.InstallResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg == nil {
		return pluginstore.InstallResult{}, fmt.Errorf("plugin-install: config is nil")
	}
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return pluginstore.InstallResult{}, fmt.Errorf("plugin-install: config path is required")
	}
	if errConfigFile := validatePluginInstallConfigFile(configPath); errConfigFile != nil {
		return pluginstore.InstallResult{}, fmt.Errorf("plugin-install: config file is unavailable: %w", errConfigFile)
	}
	cfg.NormalizePluginsConfig()
	pluginsDir, errPluginsDir := config.ResolvePluginsDir(cfg.Plugins.Dir)
	if errPluginsDir != nil {
		return pluginstore.InstallResult{}, fmt.Errorf("plugin-install: %w", errPluginsDir)
	}

	httpClient := options.HTTPClient
	if httpClient == nil && strings.TrimSpace(cfg.ProxyURL) != "" {
		client := &http.Client{}
		util.SetProxy(&sdkconfig.SDKConfig{ProxyURL: strings.TrimSpace(cfg.ProxyURL)}, client)
		httpClient = client
	}
	client := pluginstore.Client{HTTPClient: httpClient, Auth: cfg.Plugins.StoreAuth}
	goos := strings.TrimSpace(options.GOOS)
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := strings.TrimSpace(options.GOARCH)
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	result, manifest, errInstall := client.InstallGitHubRepository(ctx, pluginstore.GitHubInstallRequest{
		Repository: options.Repository,
		Version:    options.Version,
		ID:         options.ID,
		Options: pluginstore.InstallOptions{
			PluginsDir: pluginsDir,
			GOOS:       goos,
			GOARCH:     goarch,
		},
	})
	if errInstall != nil {
		if strings.TrimSpace(result.Path) != "" {
			return result, fmt.Errorf("plugin-install: plugin file installed at %s but release finalization failed: %w", result.Path, errInstall)
		}
		return pluginstore.InstallResult{}, fmt.Errorf("plugin-install: %w", errInstall)
	}
	if errConfig := enableInstalledPluginConfig(cfg, result.ID, manifest); errConfig != nil {
		return result, fmt.Errorf("plugin-install: plugin file installed at %s but config update failed: %w", result.Path, errConfig)
	}
	if errSave := config.SaveConfigPreserveComments(configPath, cfg); errSave != nil {
		return result, fmt.Errorf("plugin-install: plugin file installed at %s but config save failed: %w", result.Path, errSave)
	}
	if options.PersistConfig != nil {
		if errPersist := options.PersistConfig(ctx); errPersist != nil {
			return result, fmt.Errorf("plugin-install: plugin file installed at %s and local config updated, but backend persistence failed: %w", result.Path, errPersist)
		}
	}

	output := options.Output
	if output == nil {
		output = os.Stdout
	}
	if result.Skipped {
		_, _ = fmt.Fprintln(output, "Plugin is already installed")
	} else {
		_, _ = fmt.Fprintln(output, "Plugin installed successfully")
	}
	_, _ = fmt.Fprintf(output, "  Repository: %s\n", strings.TrimSpace(manifest.Repository))
	_, _ = fmt.Fprintf(output, "  ID:         %s\n", result.ID)
	_, _ = fmt.Fprintf(output, "  Version:    %s\n", result.Version)
	_, _ = fmt.Fprintf(output, "  Platform:   %s/%s\n", goos, goarch)
	_, _ = fmt.Fprintf(output, "  Path:       %s\n", result.Path)
	_, _ = fmt.Fprintln(output, "  Enabled:    true")
	if !cfg.Plugins.Enabled {
		_, _ = fmt.Fprintln(output, "\nGlobal plugin loading is disabled. Set plugins.enabled: true before starting the server.")
	}
	return result, nil
}

func validatePluginInstallConfigFile(configPath string) error {
	file, errOpen := os.OpenFile(configPath, os.O_RDWR, 0)
	if errOpen != nil {
		return errOpen
	}
	info, errStat := file.Stat()
	if errClose := file.Close(); errClose != nil && errStat == nil {
		return fmt.Errorf("close config file: %w", errClose)
	}
	if errStat != nil {
		return fmt.Errorf("inspect config file: %w", errStat)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("config path is not a regular file")
	}
	return nil
}

func enableInstalledPluginConfig(cfg *config.Config, id string, manifest pluginstore.Manifest) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("plugin id is empty")
	}
	cfg.NormalizePluginsConfig()
	item := cfg.Plugins.Configs[id]
	node := installedPluginConfigNode(item)
	var manifestNode yaml.Node
	if errEncode := manifestNode.Encode(manifest); errEncode != nil {
		return fmt.Errorf("encode store manifest: %w", errEncode)
	}
	setInstalledPluginYAMLValue(node, "enabled", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	setInstalledPluginYAMLValue(node, "store", &manifestNode)
	var updated config.PluginInstanceConfig
	if errDecode := node.Decode(&updated); errDecode != nil {
		return fmt.Errorf("decode plugin config: %w", errDecode)
	}
	cfg.Plugins.Configs[id] = updated
	return nil
}

func installedPluginConfigNode(item config.PluginInstanceConfig) *yaml.Node {
	if item.Raw.Kind == yaml.MappingNode {
		return cloneInstalledPluginYAMLNode(&item.Raw)
	}
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if item.Enabled != nil {
		setInstalledPluginYAMLValue(node, "enabled", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(*item.Enabled)})
	}
	if item.Priority != 0 {
		setInstalledPluginYAMLValue(node, "priority", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(item.Priority)})
	}
	return node
}

func setInstalledPluginYAMLValue(mapping *yaml.Node, key string, value *yaml.Node) {
	if mapping.Kind != yaml.MappingNode {
		mapping.Kind = yaml.MappingNode
		mapping.Tag = "!!map"
		mapping.Content = nil
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index] != nil && mapping.Content[index].Value == key {
			mapping.Content[index+1] = value
			return
		}
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		value,
	)
}

func cloneInstalledPluginYAMLNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	out := *node
	if len(node.Content) > 0 {
		out.Content = make([]*yaml.Node, 0, len(node.Content))
		for _, child := range node.Content {
			out.Content = append(out.Content, cloneInstalledPluginYAMLNode(child))
		}
	}
	return &out
}
