package systable

type Architecture string

const (
	// Supported architectures.
	X86Arch Architecture = "x86"
	X64Arch Architecture = "x64"
	ArmArch Architecture = "arm"
)

// ARCH	    NR	 RETURN	 ARG0	 ARG1	 ARG2	 ARG3	 ARG4	 ARG5
// x86	    eax	 eax	 ebx	 ecx	 edx	 esi	 edi	 ebp
// x64	    rax	 rax	 rdi	 rsi	 rdx	 r10	 r8	     r9
// arm		r7	 r0	     r0	     r1	     r2	     r3	     r4	     r5

type CallingConvention struct {
	Number string `json:"number"`
	Return string `json:"return"`
	Arg0   string `json:"arg0"`
	Arg1   string `json:"arg1"`
	Arg2   string `json:"arg2"`
	Arg3   string `json:"arg3"`
	Arg4   string `json:"arg4"`
	Arg5   string `json:"arg5"`
}

var x86Args = CallingConvention{
	Number: "eax",
	Return: "eax",
	Arg0:   "ebx",
	Arg1:   "ecx",
	Arg2:   "edx",
	Arg3:   "esi",
	Arg4:   "edi",
	Arg5:   "ebp",
}

var x64Args = CallingConvention{
	Number: "rax",
	Return: "rax",
	Arg0:   "rdi",
	Arg1:   "rsi",
	Arg2:   "rdx",
	Arg3:   "r10",
	Arg4:   "r8",
	Arg5:   "r9",
}

var armArgs = CallingConvention{
	Number: "r7",
	Return: "r0",
	Arg0:   "r0",
	Arg1:   "r1",
	Arg2:   "r2",
	Arg3:   "r3",
	Arg4:   "r4",
	Arg5:   "r5",
}

type ArchitectureMapping struct {
	CallingConvention CallingConvention `json:"calling_convention"`
	Syscalls          []Syscall         `json:"syscalls"`
}

