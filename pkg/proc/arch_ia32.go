package proc

import (
	"encoding/binary"

	"github.com/derekparker/delve/pkg/dwarf/frame"
	"github.com/derekparker/delve/pkg/dwarf/op"
	"golang.org/x/arch/x86/x86asm"
)

// I386 represents the Intel ia32 CPU architecture.
type I386 struct {
	ptrSize                 int
	breakInstruction        []byte
	breakInstructionLen     int
	gStructOffset           uint32
	hardwareBreakpointUsage []bool
	goos                    string

	// crosscall2fn is the DIE of crosscall2, a function used by the go runtime
	// to call C functions. This function in go 1.9 (and previous versions) had
	// a bad frame descriptor which needs to be fixed to generate good stack
	// traces.
	crosscall2fn *Function
}

const (
	i386DwarfIPRegNum uint64 = 8
	i386DwarfSPRegNum uint64 = 4
	i386DwarfBPRegNum uint64 = 5
)

// I386Arch returns an initialized I386
// struct.
func I386Arch(goos string) *I386 {
	var breakInstr = []byte{0xCC}

	return &I386{
		ptrSize:                 4,
		breakInstruction:        breakInstr,
		breakInstructionLen:     len(breakInstr),
		hardwareBreakpointUsage: make([]bool, 4),
		goos: goos,
	}
}

// PtrSize returns the size of a pointer
// on this architecture.
func (a *I386) PtrSize() int {
	return a.ptrSize
}

// BreakpointInstruction returns the Breakpoint
// instruction for this architecture.
func (a *I386) BreakpointInstruction() []byte {
	return a.breakInstruction
}

// BreakpointSize returns the size of the
// breakpoint instruction on this architecture.
func (a *I386) BreakpointSize() int {
	return a.breakInstructionLen
}

// If DerefTLS returns true the value of regs.TLS()+GStructOffset() is a
// pointer to the G struct
func (a *I386) DerefTLS() bool {
	// XXX fixme
	return a.goos == "windows"
}

// XXX fixme
const (
	I386crosscall2SPOffsetBad        = 0x4
	I386crosscall2SPOffsetWindows    = 0x8c
	I386crosscall2SPOffsetNonWindows = 0x2c
)

// FixFrameUnwindContext adds default architecture rules to fctxt or returns
// the default frame unwind context if fctxt is nil.
func (a *I386) FixFrameUnwindContext(fctxt *frame.FrameContext, pc uint64, bi *BinaryInfo) *frame.FrameContext {
	if fctxt == nil {
		// When there's no frame descriptor entry use BP (the frame pointer) instead
		// - return register is [bp + a.PtrSize()] (i.e. [cfa-a.PtrSize()])
		// - cfa is bp + a.PtrSize()*2
		// - bp is [bp] (i.e. [cfa-a.PtrSize()*2])
		// - sp is cfa

		return &frame.FrameContext{
			RetAddrReg: i386DwarfIPRegNum,
			Regs: map[uint64]frame.DWRule{
				i386DwarfIPRegNum: frame.DWRule{
					Rule:   frame.RuleOffset,
					Offset: int64(-a.PtrSize()),
				},
				i386DwarfBPRegNum: frame.DWRule{
					Rule:   frame.RuleOffset,
					Offset: int64(-2 * a.PtrSize()),
				},
				i386DwarfSPRegNum: frame.DWRule{
					Rule:   frame.RuleValOffset,
					Offset: 0,
				},
			},
			CFA: frame.DWRule{
				Rule:   frame.RuleCFA,
				Reg:    i386DwarfBPRegNum,
				Offset: int64(2 * a.PtrSize()),
			},
		}
	}

	if a.crosscall2fn == nil {
		a.crosscall2fn = bi.LookupFunc["crosscall2"]
	}

	if a.crosscall2fn != nil && pc >= a.crosscall2fn.Entry && pc < a.crosscall2fn.End {
		rule := fctxt.CFA
		if rule.Offset == I386crosscall2SPOffsetBad {
			switch a.goos {
			case "windows":
				rule.Offset += I386crosscall2SPOffsetWindows
			default:
				rule.Offset += I386crosscall2SPOffsetNonWindows
			}
		}
		fctxt.CFA = rule
	}

	// We assume that RBP is the frame pointer and we want to keep it updated,
	// so that we can use it to unwind the stack even when we encounter frames
	// without descriptor entries.
	// If there isn't a rule already we emit one.
	if fctxt.Regs[i386DwarfBPRegNum].Rule == frame.RuleUndefined {
		fctxt.Regs[i386DwarfBPRegNum] = frame.DWRule{
			Rule:   frame.RuleFramePointer,
			Reg:    i386DwarfBPRegNum,
			Offset: 0,
		}
	}

	return fctxt
}

// RegSize returns the size (in bytes) of register regnum.
// The mapping between hardware registers and DWARF registers is specified
// in the System V ABI I386 Architecture Processor Supplement page 25,
// figure 2.14
// https://www.uclibc.org/docs/psABI-i386.pdf
func (a *I386) RegSize(regnum uint64) int {
	// XMM registers
	if regnum >= 21 && regnum <= 28 {
		return 16
	}
	// x87 registers
	if regnum >= 11 && regnum <= 18 {
		return 10
	}
	// mmx registers
	if regnum >= 29 && regnum <= 36 {
		return 8
	}
	return 4
}

// The mapping between hardware registers and DWARF registers is specified
// in the System V ABI I386 Architecture Processor Supplement page 25,
// figure 2.14
// https://www.uclibc.org/docs/psABI-i386.pdf

var asm32DwarfToHardware = map[int]x86asm.Reg{
	0: x86asm.EAX,
	1: x86asm.ECX,
	2: x86asm.EDX,
	3: x86asm.EBX,
	4: x86asm.ESP,
	5: x86asm.EBP,
	6: x86asm.ESI,
	7: x86asm.EDI,
}

var i386DwarfToName = map[int]string{
	9:  "Eflags",
	11: "ST(0)",
	12: "ST(1)",
	13: "ST(2)",
	14: "ST(3)",
	16: "ST(4)",
	17: "ST(5)",
	18: "ST(6)",
	19: "ST(7)",
	21: "XMM0",
	22: "XMM1",
	23: "XMM2",
	24: "XMM3",
	25: "XMM4",
	26: "XMM5",
	27: "XMM6",
	28: "XMM7",
	39: "MXCSR",
	40: "Es",
	41: "Cs",
	42: "Ss",
	43: "Ds",
	44: "Fs",
	45: "Gs",
}

func maxI386DwarfRegister() int {
	max := int(i386DwarfIPRegNum)
	for i := range asm32DwarfToHardware {
		if i > max {
			max = i
		}
	}
	for i := range i386DwarfToName {
		if i > max {
			max = i
		}
	}
	return max
}

// RegistersToDwarfRegisters converts hardware registers to the format used
// by the DWARF expression interpreter.
func (a *I386) RegistersToDwarfRegisters(regs Registers) op.DwarfRegisters {
	dregs := make([]*op.DwarfRegister, maxI386DwarfRegister()+1)

	dregs[i386DwarfIPRegNum] = op.DwarfRegisterFromUint64(regs.PC())
	dregs[i386DwarfSPRegNum] = op.DwarfRegisterFromUint64(regs.SP())
	dregs[i386DwarfBPRegNum] = op.DwarfRegisterFromUint64(regs.BP())

	for dwarfReg, asmReg := range asm32DwarfToHardware {
		v, err := regs.Get(int(asmReg))
		if err == nil {
			dregs[dwarfReg] = op.DwarfRegisterFromUint64(v)
		}
	}

	for _, reg := range regs.Slice() {
		for dwarfReg, regName := range i386DwarfToName {
			if regName == reg.Name {
				dregs[dwarfReg] = op.DwarfRegisterFromBytes(reg.Bytes)
			}
		}
	}

	return op.DwarfRegisters{Regs: dregs, ByteOrder: binary.LittleEndian, PCRegNum: i386DwarfIPRegNum, SPRegNum: i386DwarfSPRegNum, BPRegNum: i386DwarfBPRegNum}
}

// GoroutineToDwarfRegisters extract the saved DWARF registers from a parked
// goroutine in the format used by the DWARF expression interpreter.
func (a *I386) GoroutineToDwarfRegisters(g *G) op.DwarfRegisters {
	dregs := make([]*op.DwarfRegister, i386DwarfIPRegNum+1)
	dregs[i386DwarfIPRegNum] = op.DwarfRegisterFromUint64(g.PC)
	dregs[i386DwarfSPRegNum] = op.DwarfRegisterFromUint64(g.SP)
	dregs[i386DwarfBPRegNum] = op.DwarfRegisterFromUint64(g.BP)
	return op.DwarfRegisters{Regs: dregs, ByteOrder: binary.LittleEndian, PCRegNum: i386DwarfIPRegNum, SPRegNum: i386DwarfSPRegNum, BPRegNum: i386DwarfBPRegNum}
}
