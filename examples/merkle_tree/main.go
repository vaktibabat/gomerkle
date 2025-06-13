package main

import (
	"fmt"
	"gomerkle"
)

const N_ITEMS = 1000000
const N_PROOFS = 100

func main() {
	data := make([][]byte, 0)

	for i := range N_ITEMS {
		data = append(data, []byte(fmt.Sprint(i)))
	}

	mt := gomerkle.NewMt(data)

	for i := range N_PROOFS {
		pf := mt.Prove(data[i])
		pf.Verify(mt.Root(), data[i])
	}
}
