package iavl

import (
	"bytes"
	"fmt"

	dbm "github.com/tendermint/tm-db"
)

// Represents a IAVL Deep Subtree that can contain
// a subset of nodes of an IAVL tree
type WitnessTree struct {
	*MutableTree
	initialRootHash []byte // Initial Root Hash when Deep Subtree is initialized for an already existing tree
	// new
	oracle    *OracleClient
	storeName string
}

func NewWitnessTree(db dbm.DB, cacheSize int, skipFastStorageUpgrade bool, version int64, oracleClient OracleClientI, storeName string) *WitnessTree {
	ndb := newNodeDB(db, cacheSize, nil)
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
	xOracleClient := NewOracleClient(oracleClient)
	rootHash := xOracleClient.GetRootHash(storeName)
	return &WitnessTree{MutableTree: mutableTree, initialRootHash: rootHash, oracle: xOracleClient, storeName: storeName}
}

// Returns the initial root hash if it is initialized and Deep Subtree root is nil.
// Otherwise, returns the Deep Subtree working hash is considered the initial root hash.
func (dst *WitnessTree) GetInitialRootHash() ([]byte, error) {
	if dst.root == nil && dst.initialRootHash != nil {
		return dst.initialRootHash, nil
	}
	return dst.WorkingHash()
}

func (dst *WitnessTree) addProofs(key []byte, value []byte) error {
	nodes, accessed := dst.oracle.GetPathWithKey(dst.storeName, key)

	if accessed {
		return nil
	}

	err := dst.addProofNodes(nodes)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}

// Verifies the Set operation with witness data and perform the given write operation
func (dst *WitnessTree) Set(key []byte, value []byte) (updated bool, err error) {
	err = dst.addProofs(key, value)
	if err != nil {
		return false, err
	}
	return dst.set(key, value)
}

// Sets a key in the working tree with the given value.
func (dst *WitnessTree) set(key []byte, value []byte) (updated bool, err error) {
	if value == nil {
		return updated, fmt.Errorf("attempt to store nil value at key '%s'", key)
	}

	if dst.root == nil {
		dst.root = NewNode(key, value, dst.version+1)
		return updated, nil
	}

	dst.root, updated, err = dst.recursiveSet(dst.root, key, value)
	if err != nil {
		fmt.Println(err)
		return updated, err
	}
	return updated, recomputeHash(dst.root)
}

// Helper method for set to traverse and find the node with given key
// recursively.
func (dst *WitnessTree) recursiveSet(node *Node, key []byte, value []byte) (
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
func (dst *WitnessTree) Get(key []byte) (value []byte, err error) {
	err = dst.addProofs(key, value)
	if err != nil {
		return nil, err
	}
	return dst.get(key)
}

// Get returns the value of the specified key if it exists, or nil otherwise.
// The returned value must not be modified, since it may point to data stored within IAVL.
func (dst *WitnessTree) get(key []byte) ([]byte, error) {
	if dst.root == nil {
		return nil, nil
	}

	return dst.ImmutableTree.Get(key)
}

// Verifies the Remove operation with witness data and perform the given delete operation
func (dst *WitnessTree) Remove(key []byte) (value []byte, removed bool, err error) {
	err = dst.addProofs(key, value)
	if err != nil {
		return nil, false, err
	}
	return dst.remove(key)
}

// Remove tries to remove a key from the tree and if removed, returns its
// value, and 'true'.
func (dst *WitnessTree) remove(key []byte) (value []byte, removed bool, err error) {
	if dst.root == nil {
		return nil, false, nil
	}
	newRootHash, newRoot, value, err := dst.recursiveRemove(dst.root, key)
	if err != nil {
		return nil, false, err
	}

	if !dst.skipFastStorageUpgrade {
		dst.addUnsavedRemoval(key)
	}

	if newRoot == nil && newRootHash != nil {
		newRoot, err = dst.ndb.GetNode(newRootHash)
		if err != nil {
			return nil, false, err
		}
	}
	dst.root = newRoot

	return value, true, nil
}

// removes the node corresponding to the passed key and balances the tree.
// It returns:
// - the hash of the new node (or nil if the node is the one removed)
// - the node that replaces the orig. node after remove
// - the removed value
func (dst *WitnessTree) recursiveRemove(node *Node, key []byte) (newHash []byte, newSelf *Node, newValue []byte, err error) {
	version := dst.version + 1

	if node.isLeaf() {
		if bytes.Equal(key, node.key) {
			return nil, nil, nil, nil
		}
		return node.hash, node, nil, nil
	}

	// Otherwise, node is inner node
	node.version = version
	leftNode, rightNode := node.leftNode, node.rightNode
	if leftNode == nil && rightNode == nil {
		return nil, nil, nil, fmt.Errorf("inner node must have at least one child node set")
	}
	compare := bytes.Compare(key, node.key)

	// node.key < key; we go to the left to find the key:
	if leftNode != nil && (compare < 0 || rightNode == nil) {
		leftNode, err := node.getLeftNode(dst.ImmutableTree)
		if err != nil {
			return nil, nil, nil, err
		}
		newLeftHash, newLeftNode, newKey, err := dst.recursiveRemove(leftNode, key)
		if err != nil {
			return nil, nil, nil, err
		}

		if newLeftHash == nil && newLeftNode == nil { // left node held value, was removed
			return node.rightHash, node.rightNode, node.key, nil
		}

		newNode, err := node.clone(version)
		if err != nil {
			return nil, nil, nil, err
		}

		newNode.leftHash, newNode.leftNode = newLeftHash, newLeftNode
		err = newNode.calcHeightAndSize(dst.ImmutableTree)
		if err != nil {
			return nil, nil, nil, err
		}
		orphans := dst.prepareOrphansSlice()
		newNode, err = dst.balance(newNode, &orphans)
		if err != nil {
			return nil, nil, nil, err
		}

		return newNode.hash, newNode, newKey, nil
	} else if rightNode != nil && (compare >= 0 || leftNode == nil) {
		newRightHash, newRightNode, newKey, err := dst.recursiveRemove(rightNode, key)
		if err != nil {
			return nil, nil, nil, err
		}
		if newRightHash == nil && newRightNode == nil { // right node held value, was removed
			return node.leftHash, node.leftNode, nil, nil
		}

		newNode, err := node.clone(version)
		if err != nil {
			return nil, nil, nil, err
		}

		newNode.rightHash, newNode.rightNode = newRightHash, newRightNode
		if newKey != nil {
			newNode.key = newKey
		}
		err = newNode.calcHeightAndSize(dst.ImmutableTree)
		if err != nil {
			return nil, nil, nil, err
		}
		orphans := dst.prepareOrphansSlice()
		newNode, err = dst.balance(newNode, &orphans)
		if err != nil {
			return nil, nil, nil, err
		}

		return newNode.hash, newNode, nil, nil
	}
	return nil, nil, nil, fmt.Errorf("node with key: %s not found", key)
}

func (dst *WitnessTree) addProofNodes(nodes []*Node) error {
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

	dst.recursiveNodeLink(dst.root)

	return nil
}

func (dst *WitnessTree) recursiveNodeLink(node *Node) error {
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
