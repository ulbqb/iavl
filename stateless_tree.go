package iavl

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	ics23 "github.com/confio/ics23/go"
	dbm "github.com/tendermint/tm-db"
)

const (
	// lengthByte is the length prefix prepended to each of the sha256 sub-hashes
	lengthByte byte = 0x20
)

// Represents a IAVL Deep Subtree that can contain
// a subset of nodes of an IAVL tree
type StatelessTree struct {
	*MutableTree
	initialRootHash []byte // Initial Root Hash when Deep Subtree is initialized for an already existing tree
}

func NewStatelessTree(db dbm.DB, cacheSize int, skipFastStorageUpgrade bool, version int64, oracleClient OracleClientI, storeName string) *StatelessTree {
	ndb := newNodeDB(db, cacheSize, nil)
	xoc := NewOracleClient(oracleClient, storeName)
	ndb.oracle = xoc
	head := &ImmutableTree{ndb: ndb, version: version, skipFastStorageUpgrade: skipFastStorageUpgrade}
	mutableTree := &MutableTree{
		ImmutableTree:            head,
		lastSaved:                head.clone(),
		orphans:                  map[string]int64{},
		versions:                 map[int64]bool{},
		allRootLoaded:            false,
		unsavedFastNodeAdditions: make(map[string]*FastNode),
		unsavedFastNodeRemovals:  make(map[string]interface{}),
		ndb:                      ndb,
		skipFastStorageUpgrade:   skipFastStorageUpgrade,
	}
	rootHash := xoc.GetRootHash()
	return &StatelessTree{MutableTree: mutableTree, initialRootHash: rootHash}
}

// Returns the initial root hash if it is initialized and Deep Subtree root is nil.
// Otherwise, returns the Deep Subtree working hash is considered the initial root hash.
func (dst *StatelessTree) GetInitialRootHash() ([]byte, error) {
	if dst.root == nil && dst.initialRootHash != nil {
		return dst.initialRootHash, nil
	}
	return dst.WorkingHash()
}

func (dst *StatelessTree) addProofs(key []byte) error {
	nodes, accessed := dst.ndb.oracle.GetNodesWithKey(key)

	if accessed {
		return nil
	}

	err := dst.saveNodes(nodes)
	if err != nil {
		return err
	}

	if dst.root == nil {
		rootHash, err := dst.GetInitialRootHash()
		if err != nil {
			return err
		}
		root, err := dst.ndb.GetNode(rootHash)
		if err != nil {
			return err
		}
		dst.root = root
	}

	err = dst.recursiveNodeLink(dst.root)

	if err != nil {
		return err
	}

	return nil
}

// Verifies the Set operation with witness data and perform the given write operation
func (dst *StatelessTree) Set(key []byte, value []byte) (updated bool, err error) {
	err = dst.addProofs(key)
	if err != nil {
		return false, err
	}

	return dst.set(key, value)
}

// Sets a key in the working tree with the given value.
func (dst *StatelessTree) set(key []byte, value []byte) (updated bool, err error) {
	if value == nil {
		return updated, fmt.Errorf("attempt to store nil value at key '%s'", key)
	}

	if dst.root == nil {
		dst.root = NewNode(key, value, dst.version+1)
		return updated, nil
	}

	dst.root, updated, err = dst.recursiveSet(dst.root, key, value)
	if err != nil {
		return updated, err
	}
	err = recomputeHash(dst.root)
	return updated, err
}

// Helper method for set to traverse and find the node with given key
// recursively.
func (dst *StatelessTree) recursiveSet(node *Node, key []byte, value []byte) (
	newSelf *Node, updated bool, err error,
) {
	version := dst.version + 1

	if node.isLeaf() {
		switch bytes.Compare(key, node.key) {
		case -1:
			// Create a new inner node with the left node as a new leaf node with
			// given key and right node as the existing leaf node
			return &Node{
				key:       node.key,
				height:    1,
				size:      2,
				leftNode:  NewNode(key, value, version),
				rightNode: node,
				version:   version,
			}, false, nil
		case 1:
			// Create a new inner node with the left node as the existing leaf node
			// and right node as a new leaf node with given key
			return &Node{
				key:       key,
				height:    1,
				size:      2,
				leftNode:  node,
				rightNode: NewNode(key, value, version),
				version:   version,
			}, false, nil
		default:
			// Key already exists so create a new leaf node with updated value
			return NewNode(key, value, version), true, nil
		}
	}
	// Otherwise, node is inner node
	node.version = version
	leftNode, rightNode := node.leftNode, node.rightNode
	if leftNode == nil && rightNode == nil {
		return nil, false, fmt.Errorf("inner node must have at least one child node set")
	}
	compare := bytes.Compare(key, node.key)
	switch {
	case leftNode != nil && (compare < 0 || rightNode == nil):
		node.leftNode, updated, err = dst.recursiveSet(leftNode, key, value)
		if err != nil {
			return nil, updated, err
		}
		hashErr := recomputeHash(node.leftNode)
		if hashErr != nil {
			return nil, updated, hashErr
		}
		node.leftHash = node.leftNode.hash
	case rightNode != nil && (compare >= 0 || leftNode == nil):
		node.rightNode, updated, err = dst.recursiveSet(rightNode, key, value)
		if err != nil {
			return nil, updated, err
		}
		hashErr := recomputeHash(node.rightNode)
		if hashErr != nil {
			return nil, updated, hashErr
		}
		node.rightHash = node.rightNode.hash
	default:
		return nil, false, fmt.Errorf("inner node does not have key set correctly")
	}
	if updated {
		return node, updated, nil
	}
	err = node.calcHeightAndSize(dst.ImmutableTree)
	if err != nil {
		return nil, false, err
	}
	orphans := dst.prepareOrphansSlice()
	node.persisted = false
	newNode, err := dst.balance(node, &orphans)
	if err != nil {
		return nil, false, err
	}
	node.persisted = true
	return newNode, updated, err
}

// Verifies the Get operation with witness data and perform the given read operation
func (dst *StatelessTree) Get(key []byte) (value []byte, err error) {
	err = dst.addProofs(key)
	if err != nil {
		return nil, err
	}
	return dst.get(key)
}

// Get returns the value of the specified key if it exists, or nil otherwise.
// The returned value must not be modified, since it may point to data stored within IAVL.
func (dst *StatelessTree) get(key []byte) ([]byte, error) {
	if dst.root == nil {
		return nil, nil
	}

	return dst.ImmutableTree.Get(key)
}

// Verifies the Remove operation with witness data and perform the given delete operation
func (dst *StatelessTree) Remove(key []byte) (value []byte, removed bool, err error) {
	err = dst.addProofs(key)
	if err != nil {
		return nil, false, err
	}

	return dst.remove(key)
}

// Remove tries to remove a key from the tree and if removed, returns its
// value, and 'true'.
func (dst *StatelessTree) remove(key []byte) (value []byte, removed bool, err error) {
	if dst.root == nil {
		return nil, false, nil
	}
	orphans := dst.prepareOrphansSlice()
	newRootHash, newRoot, _, value, err := dst.recursiveRemove(dst.root, key, &orphans)
	if err != nil {
		return nil, false, err
	}

	if !dst.skipFastStorageUpgrade {
		dst.addUnsavedRemoval(key)
	}

	if newRoot == nil && newRootHash != nil {
		dst.root, err = dst.ndb.GetNode(newRootHash)
		if err != nil {
			return nil, false, err
		}
	} else {
		dst.root = newRoot
		dst.WorkingHash()
	}

	return value, true, nil
}

// removes the node corresponding to the passed key and balances the tree.
// It returns:
// - the hash of the new node (or nil if the node is the one removed)
// - the node that replaces the orig. node after remove
// - the removed value
func (dst *StatelessTree) recursiveRemove(node *Node, key []byte, orphans *[]*Node) (newHash []byte, newSelf *Node, newKey []byte, newValue []byte, err error) {
	version := dst.version + 1

	if node.isLeaf() {
		if bytes.Equal(key, node.key) {
			*orphans = append(*orphans, node)
			return nil, nil, nil, node.value, nil
		}
		return node.hash, node, nil, nil, nil
	}

	// node.key < key; we go to the left to find the key:
	if bytes.Compare(key, node.key) < 0 {
		leftNode, err := node.getLeftNode(dst.ImmutableTree)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		newLeftHash, newLeftNode, newKey, value, err := dst.recursiveRemove(leftNode, key, orphans)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		if len(*orphans) == 0 {
			return node.hash, node, nil, value, nil
		}
		*orphans = append(*orphans, node)
		if newLeftHash == nil && newLeftNode == nil { // left node held value, was removed
			return node.rightHash, node.rightNode, node.key, value, nil
		}

		newNode, err := node.clone(version)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		newNode.leftHash, newNode.leftNode = newLeftHash, newLeftNode
		err = newNode.calcHeightAndSize(dst.ImmutableTree)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		newNode, err = dst.balance(newNode, orphans)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		return newNode.hash, newNode, newKey, value, nil
	} else {
		rightNode, err := node.getRightNode(dst.ImmutableTree)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		newRightHash, newRightNode, newKey, value, err := dst.recursiveRemove(rightNode, key, orphans)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if len(*orphans) == 0 {
			return node.hash, node, nil, value, nil
		}
		*orphans = append(*orphans, node)
		if newRightHash == nil && newRightNode == nil { // right node held value, was removed
			return node.leftHash, node.leftNode, nil, value, nil
		}

		newNode, err := node.clone(version)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		newNode.rightHash, newNode.rightNode = newRightHash, newRightNode
		if newKey != nil {
			newNode.key = newKey
		}
		err = newNode.calcHeightAndSize(dst.ImmutableTree)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		newNode, err = dst.balance(newNode, orphans)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		return newNode.hash, newNode, nil, value, nil
	}
}

func recomputeHash(node *Node) error {
	if node.leftHash == nil && node.leftNode != nil {
		leftHash, err := node.leftNode._hash()
		if err != nil {
			return err
		}
		node.leftHash = leftHash
	}
	if node.rightHash == nil && node.rightNode != nil {
		rightHash, err := node.rightNode._hash()
		if err != nil {
			return err
		}
		node.rightHash = rightHash
	}
	node.hash = nil
	_, err := node._hash()
	if err != nil {
		return err
	}
	return nil
}

func fromLeafOp(lop *ics23.LeafOp, key, value []byte) (*Node, error) {
	r := bytes.NewReader(lop.Prefix)
	height, err := binary.ReadVarint(r)
	if err != nil {
		return nil, err
	}
	if height != 0 {
		return nil, errors.New("height should be 0 in the leaf")
	}
	size, err := binary.ReadVarint(r)
	if err != nil {
		return nil, err
	}
	if size != 1 {
		return nil, errors.New("size should be 1 in the leaf")
	}
	version, err := binary.ReadVarint(r)
	if err != nil {
		return nil, err
	}
	node := &Node{
		key:     key,
		value:   value,
		size:    size,
		version: version,
	}

	_, err = node._hash()
	if err != nil {
		return nil, err
	}

	return node, nil
}

func fromInnerOp(iop *ics23.InnerOp, prevHash []byte) (*Node, error) {
	r := bytes.NewReader(iop.Prefix)
	height, err := binary.ReadVarint(r)
	if err != nil {
		return nil, err
	}
	size, err := binary.ReadVarint(r)
	if err != nil {
		return nil, err
	}
	version, err := binary.ReadVarint(r)
	if err != nil {
		return nil, err
	}

	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if b != lengthByte {
		return nil, errors.New("expected length byte (0x20")
	}
	var left, right []byte
	// if left is empty, skip to right
	if r.Len() != 0 {
		left = make([]byte, lengthByte)
		n, err := r.Read(left)
		if err != nil {
			return nil, err
		}
		if n != 32 {
			return nil, errors.New("couldn't read left hash")
		}
		b, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b != lengthByte {
			return nil, errors.New("expected length byte (0x20")
		}
	}

	if len(iop.Suffix) > 0 {
		right = make([]byte, lengthByte)
		r = bytes.NewReader(iop.Suffix)
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b != lengthByte {
			return nil, errors.New("expected length byte (0x20")
		}

		n, err := r.Read(right)
		if err != nil {
			return nil, err
		}
		if n != 32 {
			return nil, errors.New("couldn't read right hash")
		}
	}

	if left == nil {
		left = prevHash
	} else if right == nil {
		right = prevHash
	}

	node := &Node{
		leftHash:  left,
		rightHash: right,
		version:   version,
		size:      size,
		height:    int8(height),
	}

	_, err = node._hash()
	if err != nil {
		return nil, err
	}

	return node, nil
}

func (dst *ImmutableTree) saveNode(node *Node) error {
	has, err := dst.ndb.Has(node.hash)
	if err != nil {
		return err
	}
	if !has {
		err = dst.ndb.SaveNode(node)
		if err != nil {
			return err
		}
	}

	err = dst.ndb.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (dst *ImmutableTree) saveNodes(nodes []*Node) error {
	for i := range nodes {
		n := nodes[i]
		has, err := dst.ndb.Has(n.hash)
		if err != nil {
			return err
		}
		if !has {
			err = dst.ndb.SaveNode(n)
			if err != nil {
				return err
			}
		}
	}

	err := dst.ndb.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (dst *ImmutableTree) recursiveNodeLink(node *Node) error {
	if node == nil {
		return nil
	}

	if len(node.key) == 0 {
		fmt.Println("development only validation")
		fmt.Printf("key: %s\nvalue: %x\nhash: %x\nleftHash: %x\nrightHash: %x\nheight: %d\nleftNode: %v\nrightNode:%v\n\n", node.key, node.value, node.hash, node.leftHash, node.rightHash, node.height, node.leftNode != nil, node.rightNode != nil)
		panic("something wrong")
	}

	if node.isLeaf() {
		return nil
	}

	if node.leftNode == nil {
		has, err := dst.ndb.Has(node.leftHash)
		if err != nil {
			return err
		}
		if has {
			node.leftNode, err = dst.ndb.GetNode(node.leftHash)
			if err != nil {
				return err
			}
		}
	}

	if node.rightNode == nil {
		has, err := dst.ndb.Has(node.rightHash)
		if err != nil {
			return err
		}
		if has {
			node.rightNode, err = dst.ndb.GetNode(node.rightHash)
			if err != nil {
				return err
			}
		}
	}

	err := dst.recursiveNodeLink(node.leftNode)
	if err != nil {
		return err
	}
	err = dst.recursiveNodeLink(node.rightNode)
	if err != nil {
		return err
	}
	return nil
}

func (node *Node) getNodeKey() []byte {
	if node.isLeaf() {
		return node.key
	}
	buf := node.rightNode
	for {
		if buf.leftNode == nil {
			break
		}
		buf = buf.leftNode
	}
	return buf.key
}

func PrintNode(n *Node) {
	fmt.Printf("key: %v\nvalue: %x\nhash: %x\nleftHash: %x\nrightHash: %x\nheight: %d\nleftNode: %v\nrightNode:%v\n\n", n.key, n.value, n.hash, n.leftHash, n.rightHash, n.height, n.leftNode != nil, n.rightNode != nil)
}

func PrintTreeForMermaid(node *Node) {
	fmt.Println("graph TD;")
	recursivePrintTree(node)
}

func recursivePrintTree(node *Node) {
	if node == nil {
		return
	}
	if node.isLeaf() {
		return
	}
	fmt.Printf("	%x-->%x;\n", node.hash, node.leftHash)
	fmt.Printf("	%x-->%x;\n", node.hash, node.rightHash)
	recursivePrintTree(node.leftNode)
	recursivePrintTree(node.rightNode)
}
