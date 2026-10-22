package symbols

import (
	"github.com/go-delve/delve/pkg/dwarf/frame"
	"testing"
)

func TestCFIWithoutFramePointer(t *testing.T) {
	ctx := &frame.FrameContext{CFA: frame.DWRule{Rule: frame.RuleCFA, Reg: 7, Offset: 8}, RetAddrReg: 16, Regs: map[uint64]frame.DWRule{16: {Rule: frame.RuleOffset, Offset: -8}}}
	regs := map[uint64]uint64{7: 0x1000, 6: 5}
	next, err := unwindRow(ctx, regs, func(addr uint64) (uint64, bool) { return 0x400123, addr == 0x1000 })
	if err != nil || next[16] != 0x400123 || next[7] != 0x1008 || next[6] != 5 {
		t.Fatalf("CFI without RBP failed: %v %v", next, err)
	}
	if _, err = unwindRow(ctx, regs, func(uint64) (uint64, bool) { return 0, false }); err == nil {
		t.Fatal("missing saved memory guessed")
	}
	ctx.CFA.Rule = frame.RuleExpression
	if _, err = unwindRow(ctx, regs, nil); err == nil {
		t.Fatal("unsupported CFI guessed")
	}
}
