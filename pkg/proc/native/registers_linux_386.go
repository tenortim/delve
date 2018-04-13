package native

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"
	sys "golang.org/x/sys/unix"

	"github.com/derekparker/delve/pkg/proc"
)

// Regs is a wrapper for sys.PtraceRegs.
type Regs struct {
	regs   *sys.PtraceRegs
	fpregs []proc.Register
}

func (r *Regs) Slice() []proc.Register {
	var regs = []struct {
		k string
		v uint64
	}{
		{"Eip", uint64(r.regs.Eip)},
		{"Esp", uint64(r.regs.Esp)},
		{"Eax", uint64(r.regs.Eax)},
		{"Ebx", uint64(r.regs.Ebx)},
		{"Ecx", uint64(r.regs.Ecx)},
		{"Edx", uint64(r.regs.Edx)},
		{"Edi", uint64(r.regs.Edi)},
		{"Esi", uint64(r.regs.Esi)},
		{"Ebp", uint64(r.regs.Ebp)},
		{"Orig_eax", uint64(r.regs.Orig_eax)},
		{"Xcs", uint64(r.regs.Xcs)},
		{"Eflags", uint64(r.regs.Eflags)},
		{"Xss", uint64(r.regs.Xss)},
		{"Xds", uint64(r.regs.Xds)},
		{"Xes", uint64(r.regs.Xes)},
		{"Xfs", uint64(r.regs.Xfs)},
		{"Xgs", uint64(r.regs.Xgs)},
	}
	out := make([]proc.Register, 0, len(regs)+len(r.fpregs))
	for _, reg := range regs {
		if reg.k == "Eflags" {
			out = proc.AppendEflagReg(out, reg.k, reg.v)
		} else {
			out = proc.AppendDwordReg(out, reg.k, uint32(reg.v))
		}
	}
	out = append(out, r.fpregs...)
	return out
}

// PC returns the value of RIP register.
func (r *Regs) PC() uint64 {
	return r.regs.PC()
}

// SP returns the value of RSP register.
func (r *Regs) SP() uint64 {
	return uint64(r.regs.Esp)
}

func (r *Regs) BP() uint64 {
	return uint64(r.regs.Ebp)
}

// CX returns the value of RCX register.
func (r *Regs) CX() uint64 {
	return uint64(r.regs.Ecx)
}

// TLS returns the address of the thread
// local storage memory segment.
func (r *Regs) TLS(t proc.Thread) uint64 {
	var err error
	var tlsbase uintptr
	thread := t.(*Thread)
	thread.dbp.execPtraceFunc(func() { tlsbase, err = PtraceGetThreadBase(thread.ID) })
	if err != nil {
		// What to do here?
		panic("unable to obtain TLS base")
	}
	return uint64(tlsbase)
}

func (r *Regs) GAddr() (uint64, bool) {
	return 0, false
}

// SetPC sets RIP to the value specified by 'pc'.
func (r *Regs) SetPC(t proc.Thread, pc uint64) (err error) {
	thread := t.(*Thread)
	r.regs.SetPC(pc)
	thread.dbp.execPtraceFunc(func() { err = sys.PtraceSetRegs(thread.ID, r.regs) })
	return
}

func (r *Regs) Get(n int) (uint64, error) {
	reg := x86asm.Reg(n)
	const (
		mask8  = 0x000f
		mask16 = 0x00ff
	)

	switch reg {
	// 8-bit
	case x86asm.AL:
		return uint64(r.regs.Eax & mask8), nil
	case x86asm.CL:
		return uint64(r.regs.Ecx & mask8), nil
	case x86asm.DL:
		return uint64(r.regs.Edx & mask8), nil
	case x86asm.BL:
		return uint64(r.regs.Ebx & mask8), nil
	case x86asm.AH:
		return uint64((r.regs.Eax >> 8) & mask8), nil
	case x86asm.CH:
		return uint64((r.regs.Ecx >> 8) & mask8), nil
	case x86asm.DH:
		return uint64((r.regs.Edx >> 8) & mask8), nil
	case x86asm.BH:
		return uint64((r.regs.Ebx >> 8) & mask8), nil
	case x86asm.SPB:
		return uint64(r.regs.Esp & mask8), nil
	case x86asm.BPB:
		return uint64(r.regs.Ebp & mask8), nil
	case x86asm.SIB:
		return uint64(r.regs.Esi & mask8), nil
	case x86asm.DIB:
		return uint64(r.regs.Edi & mask8), nil

	// 16-bit
	case x86asm.AX:
		return uint64(r.regs.Eax & mask16), nil
	case x86asm.CX:
		return uint64(r.regs.Ecx & mask16), nil
	case x86asm.DX:
		return uint64(r.regs.Edx & mask16), nil
	case x86asm.BX:
		return uint64(r.regs.Ebx & mask16), nil
	case x86asm.SP:
		return uint64(r.regs.Esp & mask16), nil
	case x86asm.BP:
		return uint64(r.regs.Ebp & mask16), nil
	case x86asm.SI:
		return uint64(r.regs.Esi & mask16), nil
	case x86asm.DI:
		return uint64(r.regs.Edi & mask16), nil

	// 32-bit
	case x86asm.EAX:
		return uint64(r.regs.Eax), nil
	case x86asm.ECX:
		return uint64(r.regs.Ecx), nil
	case x86asm.EDX:
		return uint64(r.regs.Edx), nil
	case x86asm.EBX:
		return uint64(r.regs.Ebx), nil
	case x86asm.ESP:
		return uint64(r.regs.Esp), nil
	case x86asm.EBP:
		return uint64(r.regs.Ebp), nil
	case x86asm.ESI:
		return uint64(r.regs.Esi), nil
	case x86asm.EDI:
		return uint64(r.regs.Edi), nil
	}

	return 0, proc.UnknownRegisterError
}

func registers(thread *Thread, floatingPoint bool) (proc.Registers, error) {
	var (
		regs sys.PtraceRegs
		err  error
	)
	thread.dbp.execPtraceFunc(func() { err = sys.PtraceGetRegs(thread.ID, &regs) })
	if err != nil {
		return nil, err
	}
	r := &Regs{&regs, nil}
	if floatingPoint {
		r.fpregs, err = thread.fpRegisters()
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

const (
	_X86_XSTATE_MAX_SIZE = 2688
	_NT_X86_XSTATE       = 0x202

	_XSAVE_HEADER_START          = 512
	_XSAVE_HEADER_LEN            = 64
	_XSAVE_EXTENDED_REGION_START = 576
	_XSAVE_SSE_REGION_LEN        = 416
)

func (thread *Thread) fpRegisters() (regs []proc.Register, err error) {
	var fpregs proc.LinuxX86Xstate
	thread.dbp.execPtraceFunc(func() { fpregs, err = PtraceGetRegset(thread.ID) })
	regs = fpregs.Decode()
	if err != nil {
		err = fmt.Errorf("could not get floating point registers: %v", err.Error())
	}
	return
}
