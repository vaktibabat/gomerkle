package gomerkle

import (
	"crypto/sha256"
	"math"
)

// An MMR is composed of a list of peaks, each of which is a complete Merkle tree
type MerkleMountainRange struct {
	peaks []*MerkleTree
}

// MMR proofs are identical to MerkleProofs
type MmrProof MerkleProof

func NewMmr(data [][]byte) *MerkleMountainRange {
	// Let n be the no. items in the data; for each bit in the binary representation of n,
	// there exists a Merkle Tree with that number of leaves only if that bit is set
	// e.g. if we have 7 = 0b111 items, we'll have a tree with 4 leaves, with 2 leaves, and with 1 leaf
	n := len(data)
	peaks := make([]*MerkleTree, 0)

	for i := int(math.Log2(float64(n))); i >= 0; i-- {
		// If the current bit is set
		if n&(1<<i) != 0 {
			// Take the next 2^i items from the data
			items := data[:(1 << i)]
			data = data[(1 << i):]
			// Construct a Merkle tree from them
			tree := NewMt(items)
			peaks = append(peaks, tree)
		}
	}

	return &MerkleMountainRange{peaks}
}

func (mmr *MerkleMountainRange) Insert(items [][]byte) {
	// Construct anew MT containing all of the new elements
	new_tree := NewMt(items)
	mmr.peaks = append(mmr.peaks, new_tree)
	// Keep merging peaks until none can be merged
	for merge_peaks(mmr) {
	}
}

// Iterate over the MMR and merge trees of the same size
func merge_peaks(mmr *MerkleMountainRange) bool {
	// Have we already merged a tree in this iteration?
	merged := false

	for {
		merged = false
		// Store the sizes of the trees we've already seen (maps tree size -> index of first occurence of tree of this size)
		sizes := make(map[int]int, 0)
		// Iterate over the trees
		for i, tree := range mmr.peaks {
			size := tree.root.size()
			j, exists := sizes[size]
			// If we've already encountered a tree of this size
			if exists {
				// Merge the two peaks
				other := mmr.peaks[j]
				// First, remove both of them
				mmr.peaks = append(mmr.peaks[:i], mmr.peaks[i+1:]...)
				mmr.peaks = append(mmr.peaks[:j], mmr.peaks[j+1:]...)
				// Now construct the new tree
				new_tree_data := sha256.Sum256(append(other.root.data[:], tree.root.data[:]...))
				new_tree_root := merkle_node{
					new_tree_data,
					&other.root,
					&tree.root,
				}
				new_tree := MerkleTree{new_tree_root}
				// Append to the list
				mmr.peaks = append(mmr.peaks, &new_tree)

				merged = true
			} else {
				sizes[size] = i
			}
		}

		if !merged {
			break
		}
	}

	return merged
}

// Generate a proof that some item is in the MMR
func (mmr *MerkleMountainRange) Prove(item []byte) *MmrProof {
	// Find the tree where the item is located, and generate a Merkle proof for it
	for _, tree := range mmr.peaks {
		if tree.root.search(item) != nil {
			proof := MmrProof(*tree.Prove(item))

			return &proof
		}
	}

	return nil
}

// Try verifying the proof for every peak in the MMR; return true if at least one verified correctly
func (proof *MmrProof) Verify(peaks [][DIGEST_SIZE]byte, item []byte) bool {
	for _, peak := range peaks {
		merkle_pf := MerkleProof(*proof)

		if merkle_pf.Verify(peak, item) {
			return true
		}
	}

	return false
}

// Return the peaks of the MMR; required for verifying proofs
func (mmr *MerkleMountainRange) Peaks() [][DIGEST_SIZE]byte {
	peaks := make([][DIGEST_SIZE]byte, len(mmr.peaks))

	for i, peak := range mmr.peaks {
		peaks[i] = peak.root.data
	}

	return peaks
}
