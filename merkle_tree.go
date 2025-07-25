package gomerkle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const DIGEST_SIZE = 32

type merkle_node struct {
	// We hold the hash of some data
	data [DIGEST_SIZE]byte
	// Point to our left and right children
	left  *merkle_node
	right *merkle_node
}

type MerkleTree struct {
	root merkle_node
}

type MerkleProof struct {
	// The list of hashes that constitutes the proof
	hashes [][DIGEST_SIZE]byte
	// The side each hash is on (is it the right child or the left child)
	left []bool
}

// Construct a Merkle Tree using some data
func NewMt(data [][]byte) *MerkleTree {
	// If there's no data here, return nil
	if len(data) == 0 {
		return nil
	}
	// Recursion... if we only have one piece of data, hash it, and return the resulting leaf
	if len(data) == 1 {
		leaf := merkle_node{
			sha256.Sum256(data[0]),
			nil,
			nil,
		}
		tree := MerkleTree{leaf}

		return &tree
	}
	// Otherwise, you construct the Merkle Trees corresponding to the two halves of the data
	left := NewMt(data[:len(data)/2])
	right := NewMt(data[len(data)/2:])
	// and set the data of this node to be H(left.root || right.root)
	combined := append(left.root.data[:], right.root.data[:]...)
	root_data := sha256.Sum256(combined)
	// construct the root from what we just computed
	root := merkle_node{
		root_data,
		&left.root,
		&right.root,
	}
	tree := MerkleTree{root}

	return &tree
}

// Generate a proof that some item is a part of the Merkle tree
func (tree *MerkleTree) Prove(item []byte) *MerkleProof {
	// First, we want to find to find the leaf corresponding to the item inside the tree
	// (and return nil if it isn't in the tree)
	path := tree.root.search(item)
	// Tracks where we are in the tree (TODO: make less ugly)
	node := path[len(path)-1]
	hashes := [][DIGEST_SIZE]byte{}
	left := []bool{}

	for i := len(path) - 2; i >= 0; i-- {
		// The current node in the path
		curr_node := path[i]
		// If this node means "go left", we need to append to the proof the data in the right node
		if node.left.data == curr_node.data {
			hashes = append(hashes, node.right.data)
			left = append(left, false)
		} else if node.right.data == curr_node.data {
			hashes = append(hashes, node.left.data)
			left = append(left, true)
		}

		node = curr_node
	}

	return &MerkleProof{
		hashes,
		left,
	}
}

// Verify a Merkle proof that some item is in the tree
func (proof *MerkleProof) Verify(root [DIGEST_SIZE]byte, item []byte) bool {
	// The hash we get so far -- by the end, this should equal the root hash
	acc := sha256.Sum256(item)
	// Reconstruct the path
	for i := len(proof.hashes) - 1; i >= 0; i-- {
		if proof.left[i] {
			cat := append(proof.hashes[i][:], acc[:]...)
			acc = sha256.Sum256(cat)
		} else {
			cat := append(acc[:], proof.hashes[i][:]...)
			acc = sha256.Sum256(cat)
		}
	}

	return acc == root
}

func (tree *MerkleTree) Root() [DIGEST_SIZE]byte {
	return tree.root.data
}

// Find a path from the root of the provided Merkle tree to the leaf containing the hash of the item
func (root *merkle_node) search(item []byte) []*merkle_node {
	// Base case -- the provided tree is a leaf
	if root.left == nil && root.right == nil {
		// If the leaf contains the hash of the item: great
		if root.data == sha256.Sum256(item) {
			return []*merkle_node{root}
		} else {
			return nil
		}
	}
	// Search in the left and right subtrees
	left := root.left.search(item)
	right := root.right.search(item)
	// If the left is not nil, we append the current root to the path it found
	if left != nil {
		path := append(left, root)

		return path
	} else if right != nil {
		// Same thing for right
		path := append(right, root)

		return path
	}
	// If it doesn't exist in either subtree, it isn't in the tree at all
	return nil
}

// count no. leaves in the tree rooted at some node
func (root *merkle_node) size() int {
	// a leaf has 1 leaf
	if root.left == nil && root.right == nil {
		return 1
	}
	// otherwise return no. leaves in left subtree + right subtree
	return root.left.size() + root.right.size()
}

func (tree *MerkleTree) Print() {
	tree.root.print(0)
}

func (root *merkle_node) print(depth int) {
	if root == nil {
		return
	}

	root.left.print(depth + 1)

	fmt.Printf("%s%s\n", strings.Repeat("    ", depth), hex.EncodeToString(root.data[:]))

	root.right.print(depth + 1)
}
