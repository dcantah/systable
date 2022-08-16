package systable

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var errNoMatches = errors.New("no syscalls found")

// Enough for the current lot of em.
const bufSize = 500

type SyscallParser struct {
	tblData    string
	headerData string
}

type parseOpts struct {
	exactMatch bool
	find       []string
}

type SyscallParseOpts func(*parseOpts)

func WithExactMatch(find []string) SyscallParseOpts {
	return func(parser *parseOpts) {
		parser.exactMatch = true
		parser.find = find
	}
}

func WithFindSubstrings(find []string) SyscallParseOpts {
	return func(parser *parseOpts) {
		parser.find = find
	}
}

func NewSyscallParser(tblData string, headerData string) *SyscallParser {
	return &SyscallParser{
		tblData:    tblData,
		headerData: headerData,
	}
}

func (sp *SyscallParser) Parse(arch Architecture, opts ...SyscallParseOpts) (*ArchitectureMapping, error) {
	var parseOpts parseOpts
	for _, opt := range opts {
		opt(&parseOpts)
	}

	search := len(parseOpts.find) > 0

	// To avoid some runtime allocs.
	syscalls := make([]Syscall, 0, bufSize)

	var syscall Syscall
	lines := strings.Split(sp.tblData, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip comments and empty lines.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// An entry in a tbl looks like the following:
		//
		// 0	common	restart_syscall		sys_restart_syscall
		//
		// Thus:
		// fields[0] == syscall number
		// fields[1] == abi
		// fields[2] == syscall name
		// fields[3] == entrypoint
		fields := strings.Fields(line)

		// Unimplemented syscalls will have less than the typical number of fields.
		if len(fields) < 4 {
			continue
		}

		abi := fields[1]
		syscallName := fields[2]
		entryPoint := fields[3]
		if abi == "x32" && arch == X64Arch || entryPoint == "sys_ni_syscall" || entryPoint == "sys_syscall" {
			continue
		}

		syscallNumber, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, err
		}

		if arch == X64Arch {
			entryPoint = strings.TrimPrefix(entryPoint, "__x64_")
		}

		switch entryPoint {
		case "sys_mmap":
			entryPoint = "ksys_mmap_pgoff"
		case "sys_statfs64_wrapper", "sys_fstatfs64_wrapper":
			entryPoint = strings.TrimSuffix(entryPoint, "_wrapper")
		case "sys_arm_fadvise64_64", "sys_ia32_fadvise64_64":
			entryPoint = strings.Replace(entryPoint, "arm_", "", 1)
			entryPoint = strings.Replace(entryPoint, "ia32_", "", 1)
			syscallName = "fadvise64_64"
		case "sys_ia32_fadvise64":
			entryPoint = strings.Replace(entryPoint, "ia32_", "", 1)
			syscallName = "fadvise64"
		case "sys_mmap2":
			entryPoint = "sys_mmap_pgoff"
		default:
		}

		syscall.Number = uint16(syscallNumber)
		syscall.Name = syscallName
		syscall.ManPage = manPage(syscall.Name)

		re := regexp.MustCompile(`(?:asmlinkage|unsigned) long ` + entryPoint + `\(([^)]+)\);`)
		matches := re.FindStringSubmatch(string(sp.headerData))
		args := []string{}
		if matches != nil {
			if matches[1] != "void" {
				args = strings.Split(matches[1], ",")
				for i, arg := range args {
					args[i] = strings.ReplaceAll(strings.TrimSpace(arg), "__user ", "")
				}
			}
		}
		syscall.Arguments = args

		if search {
			for i, str := range parseOpts.find {
				if parseOpts.exactMatch {
					if syscall.Name == str {
						syscalls = append(syscalls, syscall)
						parseOpts.find = append(parseOpts.find[:i], parseOpts.find[i+1:]...)
						break
					}
				} else {
					if strings.Contains(syscall.Name, str) {
						syscalls = append(syscalls, syscall)
					}
				}
			}
		} else {
			syscalls = append(syscalls, syscall)
		}
	}

	if len(syscalls) == 0 {
		return nil, errNoMatches
	}

	archMap := &ArchitectureMapping{
		Syscalls: syscalls,
	}

	switch arch {
	case X86Arch:
		archMap.CallingConvention = x86Args
	case X64Arch:
		archMap.CallingConvention = x64Args
	case ArmArch:
		archMap.CallingConvention = armArgs
	}

	return archMap, nil
}
