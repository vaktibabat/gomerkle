package main

import (
	"fmt"
	"gomerkle"
)

const N_ITEMS = 8

func main() {
	data := make([][]byte, 0)

	for i := range N_ITEMS {
		data = append(data, []byte(fmt.Sprint(i)))
	}

	mt := gomerkle.NewMt(data)

	// Print the tree
	mt.Print()
	// Verify a valid proof
	pf := mt.Prove([]byte(fmt.Sprint(5)))
	fmt.Printf("Result for proof: %v\n", pf.Verify(mt.Root(), []byte(fmt.Sprint(5))))
}
