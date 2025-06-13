package gomerkle

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"slices"
)

// Default value for empty leaves
const DEFAULT_VAL = ""

var default_digests = compute_default_digests()

type SparseMerkleTree struct {
	root *merkle_node
}

type SparseMerkleProof MerkleProof

// Construct a Merkle Tree using some data
func NewSmt(data [][]byte) *SparseMerkleTree {
	// Hash each piece of data
	hashed_data := make([][DIGEST_SIZE]byte, len(data))

	for i, s := range data {
		hashed_data[i] = sha256.Sum256(s)
	}

	// Sort the resulting hashes so that we know where each item sits within the tree
	slices.SortFunc(hashed_data, func(a, b [DIGEST_SIZE]byte) int { return bytes.Compare(a[:], b[:]) })

	// The entire tree is for values in the range 0 to 2^256 - 1 (all possible SHA256 digests)
	hi := new(big.Int)
	hi.Exp(big.NewInt(2), big.NewInt(8*DIGEST_SIZE), nil)
	hi.Sub(hi, big.NewInt(1))

	root := new_smt_inner(hashed_data, *big.NewInt(0), *hi, 8*DIGEST_SIZE-1)

	return &SparseMerkleTree{root}
}

// Construct the root of an SMT containing the values in the range lo to hi
func new_smt_inner(data [][DIGEST_SIZE]byte, lo big.Int, hi big.Int, height int) *merkle_node {
	// If there's no data in this range, return the default node at this height
	if len(data) == 0 {
		return &merkle_node{
			default_digests[height],
			nil,
			nil,
		}
	}
	// If we got to a height of 0 (the leaf level), we must only have one item, so return the node containing it
	if height == 0 {
		return &merkle_node{data[0], nil, nil}
	}
	// Compute the middle of our current range
	mid := new(big.Int)
	mid.Add(&lo, &hi)
	mid.Div(mid, big.NewInt(2))
	// The values that are <= mid go in the left subtree, and the other ones go in the right subtree
	left_data := make([][DIGEST_SIZE]byte, 0)
	right_data := make([][DIGEST_SIZE]byte, 0)

	for _, h := range data {
		if bytes.Compare(h[:], mid.Bytes()) <= 0 {
			left_data = append(left_data, h)
		} else {
			right_data = append(right_data, h)
		}
	}

	// Construct left and right subtrees recursively and compute this node's data
	left_subtree := new_smt_inner(left_data, lo, *mid, height-1)
	right_subtree := new_smt_inner(right_data, *mid, hi, height-1)

	node_data_preimage := append(left_subtree.data[:], right_subtree.data[:]...)
	node_data := sha256.Sum256(node_data_preimage)

	return &merkle_node{
		node_data,
		left_subtree,
		right_subtree,
	}
}

// Generate a proof that some item is a part of the Merkle tree
func (tree *SparseMerkleTree) Prove(item []byte) *SparseMerkleProof {
	// Hash the item and traverse the tree according to the bits of the hash
	hash := sha256.Sum256(item)
	left := make([]bool, 0)
	hashes := make([][DIGEST_SIZE]byte, 0)
	curr := tree.root

	for i := range 8*DIGEST_SIZE - 1 {
		// Is the current bit 0 or 1?
		curr_byte := hash[i/8]
		// If the current bit is set, go right and add the left sibling to the path
		if curr_byte&(1<<(7-i%8)) != 0 {
			// Add the sibling to the path
			hashes = append(hashes, curr.left.data)
			// Go right
			curr = curr.right
			left = append(left, true)
		} else {
			// Otherwise, go left and add the right sibling to the path
			// Add the sibling to the path
			hashes = append(hashes, curr.right.data)
			// Go left
			curr = curr.left
			left = append(left, false)
		}
	}

	return &SparseMerkleProof{
		hashes,
		left,
	}
}

// Verify a Merkle proof that some item is in the tree
func (proof *SparseMerkleProof) Verify(root [DIGEST_SIZE]byte, item []byte) bool {
	// The hash we get so far -- by the end, this should equal the root hash
	acc := sha256.Sum256(item)

	for i := 8*DIGEST_SIZE - 2; i >= 0; i-- {
		// If the proof's hash is on the left, compute H(proof's hash || accumulator)
		if proof.left[i] {
			cat := append(proof.hashes[i][:], acc[:]...)
			acc = sha256.Sum256(cat)
		} else {
			// Otherwise compute H(accumulator || proof's hash)
			cat := append(acc[:], proof.hashes[i][:]...)
			acc = sha256.Sum256(cat)
		}
	}
	// Accept iff the accumulator equals the root
	return acc == root
}

// Generate a proof that some item is **not** part of the Merkle tree
func (tree *SparseMerkleTree) ProveNonIncl(item []byte) *SparseMerkleProof {
	// Compute the hash of the item
	hash := sha256.Sum256(item)
	left := make([]bool, 0)
	hashes := make([][DIGEST_SIZE]byte, 0)
	curr := tree.root
	// Because the item is not actually in the tree, there *doesn't* exist
	// a path from the root to the leaf containing it.
	// At some point, we'll reach a virtual node, which by definition doesn't have children
	// When we reach that point, stop, and all the remaining virtual nodes to the path
	for i := range 8*DIGEST_SIZE - 1 {
		// Is the current bit 0 or 1?
		curr_bit := hash[i/8]
		is_bit_set := curr_bit&(1<<(7-i%8)) != 0
		// If the current bit is set, go left and add the right sibling to the tree
		if is_bit_set {
			// If our left child is nil, we've reached a virtual ndoe
			if curr.left == nil {
				break
			}
			// Add the sibling to the path
			hashes = append(hashes, curr.left.data)
			// Go right
			curr = curr.right
			left = append(left, true)
		} else {
			// If our right child is nil, we've reached a virtual node
			if curr.right == nil {
				break
			}
			// Add the sibling to the path
			hashes = append(hashes, curr.right.data)
			// Go left
			curr = curr.left
			left = append(left, false)
		}

	}
	// If we've already constructed an entire proof, the item **is** in the tree
	// so return nil
	if len(hashes) >= 8*DIGEST_SIZE-1 {
		return nil
	}
	// Otherwise, add all of the remaining default digests
	for j := 8*DIGEST_SIZE - 1 - len(hashes); j >= 0; j-- {
		i := (8*DIGEST_SIZE - 1) - j
		curr_byte := hash[i/8]
		hashes = append(hashes, default_digests[j-1])
		left = append(left, curr_byte&(1<<(7-i%8)) != 0)
	}

	return &SparseMerkleProof{
		hashes,
		left,
	}
}

// Verify a Merkle proof that some item is not in the tree
// Note that to verify a proof, the verifier doesn't need to know anything about the underlying tree --
// only its root!
func (proof *SparseMerkleProof) SmtVerifyNonIncl(root [DIGEST_SIZE]byte, item []byte) bool {
	// If the item is indeed not in the tree, its leaf should be empty
	acc := default_digests[0]
	// Reconstrcut the path
	for i := 8*DIGEST_SIZE - 2; i >= 0; i-- {
		if proof.left[i] {
			acc = sha256.Sum256(append(proof.hashes[i][:], acc[:]...))
		} else {
			acc = sha256.Sum256(append(acc[:], proof.hashes[i][:]...))
		}
	}

	return acc == root
}

func (tree *SparseMerkleTree) Root() [DIGEST_SIZE]byte {
	return tree.root.data
}

func compute_default_digests() map[int][DIGEST_SIZE]byte {
	out := make(map[int][DIGEST_SIZE]byte)
	// An empty leaf is just the sha256 of an empty value
	out[0] = sha256.Sum256([]byte(DEFAULT_VAL))
	// For every subsequent default node, we hash the concatenation of the two previous ones
	for i := 1; i < 8*DIGEST_SIZE; i++ {
		prev := out[i-1]

		out[i] = sha256.Sum256(append(prev[:], prev[:]...))
	}

	return out
}
