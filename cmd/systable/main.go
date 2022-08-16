package main

import (
	gojson "encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/dcantah/systable"
	"github.com/spf13/pflag"
)

var (
	version string
	arch    string
	format  string
	exact   bool
)

var homeDir string

func init() {
	dir, err := os.UserHomeDir()
	if err != nil {
		panic(fmt.Errorf("failed to get users home directory: %w", err))
	}
	homeDir = dir

	pflag.StringVarP(&version, "version", "v", "", "Linux kernel version (Example: 'v6.0')")
	pflag.StringVarP(&arch, "arch", "a", "", "Linux kernel architecture (Values: 'arm', 'x86', 'x64')")
	pflag.StringVarP(&format, "format", "f", "", "Format of the output (Values: 'table', 'json')")
	pflag.BoolVarP(&exact, "exact", "e", false, "Narrow the search to only syscalls that match the queries exactly")

	pflag.Usage = func() {
		helpText := `Usage: systable [options...] <query>...

View syscall table information for a chosen Linux kernel version and architecture. If no arguments
are provided the program returns all syscalls for the chosen (architecture+version) tuple, otherwise
returns information for only the set specified.

Editing ~/.systable/config.json will change the default settings for all invocations.

-f, --format			Format of the output (Values: 'table', 'json'. Default: 'table').
 -a, --arch <arch>		Linux kernel architecture (Values: 'arm', 'x86', 'x64'. Default: 'x64').
 -v, --version			Linux kernel version. Must be a valid git tag. (Default: 'v6.0').
 -e,--exact			Narrow the search to only syscalls that match the queries exactly.
`
		if _, err := os.Stdout.Write([]byte(helpText)); err != nil {
			panic(err)
		}
	}
}

type config struct {
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Format       string `json:"format"`
}

const (
	x86Tbl = "https://raw.githubusercontent.com/torvalds/linux/%s/arch/x86/entry/syscalls/syscall_32.tbl"
	x64Tbl = "https://raw.githubusercontent.com/torvalds/linux/%s/arch/x86/entry/syscalls/syscall_64.tbl"
	armTbl = "https://raw.githubusercontent.com/torvalds/linux/%s/arch/arm/tools/syscall.tbl"

	syscallHeader = "https://raw.githubusercontent.com/torvalds/linux/%s/include/linux/syscalls.h"
)

const (
	json  = "json"
	table = "table"
)

const (
	defaultVersion = "v6.0"
	defaultArch    = systable.X64Arch
	defaultFormat  = table
)

const configFileName = "config.json"

const (
	tblCacheFileFormatString     = "%s-%s.tbl"
	headersCacheFileFormatString = "%s-syscalls.h"
)

func configDir() string {
	return filepath.Join(homeDir, ".systable")
}

func cacheDir() string {
	return filepath.Join(configDir(), "cache")
}

func createDirs() error {
	if err := os.MkdirAll(cacheDir(), 0o744); err != nil {
		return fmt.Errorf("failed to create config and cache directories: %w", err)
	}
	return nil
}

func getOrCreateConfigFile() (config, error) {
	cfgPath := filepath.Join(configDir(), configFileName)
	if _, err := os.Stat(cfgPath); err == nil {
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			return config{}, err
		}

		var cfg config
		if err := gojson.Unmarshal(data, &cfg); err != nil {
			return cfg, err
		}
		return cfg, nil
	}

	cfg := config{
		Version:      defaultVersion,
		Architecture: string(defaultArch),
		Format:       defaultFormat,
	}
	data, err := gojson.Marshal(&cfg)
	if err != nil {
		return config{}, err
	}

	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func validateArgs(version, arch, format string, find []string, exact bool) error {
	if exact && len(find) == 0 {
		return errors.New("--exact provided but no search query was supplied")
	}

	if version[0] != 'v' {
		return fmt.Errorf("invalid kernel version: %q", version)
	}

	architecture := systable.Architecture(arch)
	switch architecture {
	case systable.X86Arch, systable.X64Arch, systable.ArmArch:
	default:
		return fmt.Errorf("unknown architecture specified: %q", arch)
	}

	switch format {
	case table, json:
	default:
		return fmt.Errorf("unknown format specified: %q", format)
	}

	return nil
}

func displayTable(archMap *systable.ArchitectureMapping) error {
	callingConv := archMap.CallingConvention

	w := tabwriter.NewWriter(os.Stdout, 4, 8, 3, ' ', 0)
	header := fmt.Sprintf("Num(%s)\tName\t", callingConv.Number)
	header += fmt.Sprintf("Arg0(%s)\tArg1(%s)\tArg2(%s)\tArg3(%s)\tArg4(%s)\tArg5(%s)\t", callingConv.Arg0, callingConv.Arg1, callingConv.Arg2, callingConv.Arg3, callingConv.Arg4, callingConv.Arg5)

	fmt.Fprintln(w, header)
	for _, syscall := range archMap.Syscalls {
		args := make([]string, 6)
		copy(args, []string(syscall.Arguments))
		if _, err := fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			syscall.Number,
			syscall.Name,
			args[0],
			args[1],
			args[2],
			args[3],
			args[4],
			args[5],
		); err != nil {
			return err
		}
	}
	return w.Flush()
}

func parseAndDisplay(tblData string, headerData string, args []string) error {
	parser := systable.NewSyscallParser(tblData, headerData)

	var opts []systable.SyscallParseOpts
	if exact {
		opts = append(opts, systable.WithExactMatch(args))
	} else if len(args) > 0 {
		opts = append(opts, systable.WithFindSubstrings(args))
	}

	archMap, err := parser.Parse(systable.Architecture(arch), opts...)
	if err != nil {
		return err
	}

	switch format {
	case json:
		if err := gojson.NewEncoder(os.Stdout).Encode(archMap); err != nil {
			return err
		}
	case table:
		if err := displayTable(archMap); err != nil {
			return err
		}
	}

	return nil
}

func fetchAndCache(url string, cacheFilePath string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch syscall data from %q: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get syscall.tbl at %q: %q", url, resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read syscall data from connection to %q: %w", url, err)
	}

	// Write the table into our cache so we don't have to do the http dance again.
	if err := os.WriteFile(cacheFilePath, data, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write syscall table to cache at %q: %w", cacheFilePath, err)
	}

	return data, nil
}

func run() error {
	pflag.Parse()

	if err := createDirs(); err != nil {
		return err
	}

	cfg, err := getOrCreateConfigFile()
	if err != nil {
		return err
	}

	if arch == "" {
		arch = cfg.Architecture
	}

	if version == "" {
		version = cfg.Version
	}

	if format == "" {
		format = cfg.Format
	}

	args := pflag.Args()
	if err := validateArgs(version, arch, format, args, exact); err != nil {
		return err
	}

	tblCacheFilePath := filepath.Join(cacheDir(), fmt.Sprintf(tblCacheFileFormatString, version, arch))
	headerCacheFilePath := filepath.Join(cacheDir(), fmt.Sprintf(headersCacheFileFormatString, version))

	_, err = os.Stat(tblCacheFilePath)
	tblCacheFileExists := err == nil

	_, err = os.Stat(headerCacheFilePath)
	headerCacheFileExists := err == nil

	if tblCacheFileExists && headerCacheFileExists {
		tblData, err := os.ReadFile(tblCacheFilePath)
		if err != nil {
			return fmt.Errorf("failed to read syscall table from cache %q: %w", tblCacheFilePath, err)
		}

		headerData, err := os.ReadFile(headerCacheFilePath)
		if err != nil {
			return fmt.Errorf("failed to read syscall header from cache %q: %w", headerCacheFilePath, err)
		}

		return parseAndDisplay(string(tblData), string(headerData), args)
	}

	syscallTableURL := ""
	architecture := systable.Architecture(arch)
	switch architecture {
	case systable.X86Arch:
		syscallTableURL = x86Tbl
	case systable.X64Arch:
		syscallTableURL = x64Tbl
	case systable.ArmArch:
		syscallTableURL = armTbl
	}

	syscallTableURL = fmt.Sprintf(syscallTableURL, version)
	syscallHeaderURL := fmt.Sprintf(syscallHeader, version)

	syscallTable, err := fetchAndCache(syscallTableURL, tblCacheFilePath)
	if err != nil {
		return err
	}

	headerData, err := fetchAndCache(syscallHeaderURL, headerCacheFilePath)
	if err != nil {
		return err
	}

	return parseAndDisplay(string(syscallTable), string(headerData), args)
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
