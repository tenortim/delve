package proc

import (
	"github.com/derekparker/delve/pkg/dwarf/frame"
	"github.com/derekparker/delve/pkg/dwarf/op"
)

// Arch defines an interface for representing a
// CPU architecture.
type Arch interface {
	PtrSize() int
	BreakpointInstruction() []byte
	BreakpointSize() int
	DerefTLS() bool
	FixFrameUnwindContext(fctxt *frame.FrameContext, pc uint64, bi *BinaryInfo) *frame.FrameContext
	RegSize(uint64) int
	RegistersToDwarfRegisters(Registers) op.DwarfRegisters
	GoroutineToDwarfRegisters(*G) op.DwarfRegisters
}
