package main

import (
	"fmt"
	"gomerkle"
)

const N_ITEMS = 50000
const N_PROOFS = 100

func main() {
	data := make([][]byte, 0)

	for i := range N_ITEMS {
		data = append(data, []byte(fmt.Sprint(i)))
	}

	smt := gomerkle.NewSmt(data)

	for i := range N_PROOFS {
		pf := smt.Prove(data[i])
		// Try to prove that an item doesn't exist
		non_existent_item := []byte{'a'}
		non_existent_item = append(non_existent_item, data[i]...)
		pf_non_incl := smt.ProveNonIncl(non_existent_item)

		pf.Verify(smt.Root(), data[i])
		pf_non_incl.SmtVerifyNonIncl(smt.Root(), non_existent_item)
	}
}
