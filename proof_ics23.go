package iavl

import (
	"bytes"
	"encoding/binary"
	"fmt"

	ics23 "github.com/confio/ics23/go"
)

/*
GetMembershipProof will produce a CommitmentProof that the given key (and queries value) exists in the iavl tree.
If the key doesn't exist in the tree, this will return an error.
*/
func (t *ImmutableTree) GetMembershipProof(key []byte) (*ics23.CommitmentProof, error) {
	exist, err := createExistenceProof(t, key)
	if err != nil {
		return nil, err
	}
	proof := &ics23.CommitmentProof{
		Proof: &ics23.CommitmentProof_Exist{
			Exist: exist,
		},
	}
	return proof, nil
}

/*
GetNonMembershipProof will produce a CommitmentProof that the given key doesn't exist in the iavl tree.
If the key exists in the tree, this will return an error.
*/
func (t *ImmutableTree) GetNonMembershipProof(key []byte) (*ics23.CommitmentProof, error) {
	// idx is one node right of what we want....
	var err error
	idx, val, err := t.GetWithIndex(key)
	if err != nil {
		return nil, err
	}

	if val != nil {
		return nil, fmt.Errorf("cannot create NonExistanceProof when Key in State")
	}

	nonexist := &ics23.NonExistenceProof{
		Key: key,
	}

	if idx >= 1 {
		leftkey, _, err := t.GetByIndex(idx - 1)
		if err != nil {
			return nil, err
		}

		nonexist.Left, err = createExistenceProof(t, leftkey)
		if err != nil {
			return nil, err
		}
	}

	// this will be nil if nothing right of the queried key
	rightkey, _, err := t.GetByIndex(idx)
	if err != nil {
		return nil, err
	}

	if rightkey != nil {
		nonexist.Right, err = createExistenceProof(t, rightkey)
		if err != nil {
			return nil, err
		}
	}

	proof := &ics23.CommitmentProof{
		Proof: &ics23.CommitmentProof_Nonexist{
			Nonexist: nonexist,
		},
	}
	return proof, nil
}

func createExistenceProof(tree *ImmutableTree, key []byte) (*ics23.ExistenceProof, error) {
	value, proof, err := tree.GetWithProof(key)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, fmt.Errorf("cannot create ExistanceProof when Key not in State")
	}
	return convertExistenceProof(proof, key, value)
}

// convertExistenceProof will convert the given proof into a valid
// existence proof, if that's what it is.
//
// This is the simplest case of the range proof and we will focus on
// demoing compatibility here
func convertExistenceProof(p *RangeProof, key, value []byte) (*ics23.ExistenceProof, error) {
	if len(p.Leaves) != 1 {
		return nil, fmt.Errorf("existence proof requires RangeProof to have exactly one leaf")
	}
	return &ics23.ExistenceProof{
		Key:   key,
		Value: value,
		Leaf:  convertLeafOp(p.Leaves[0].Version),
		Path:  convertInnerOps(p.LeftPath),
	}, nil
}

func convertLeafOp(version int64) *ics23.LeafOp {
	var varintBuf [binary.MaxVarintLen64]byte
	// this is adapted from iavl/proof.go:proofLeafNode.Hash()
	prefix := convertVarIntToBytes(0, varintBuf)
	prefix = append(prefix, convertVarIntToBytes(1, varintBuf)...)
	prefix = append(prefix, convertVarIntToBytes(version, varintBuf)...)

	return &ics23.LeafOp{
		Hash:         ics23.HashOp_SHA256,
		PrehashValue: ics23.HashOp_SHA256,
		Length:       ics23.LengthOp_VAR_PROTO,
		Prefix:       prefix,
	}
}

// we cannot get the proofInnerNode type, so we need to do the whole path in one function
func convertInnerOps(path PathToLeaf) []*ics23.InnerOp {
	steps := make([]*ics23.InnerOp, 0, len(path))

	// lengthByte is the length prefix prepended to each of the sha256 sub-hashes
	var lengthByte byte = 0x20

	var varintBuf [binary.MaxVarintLen64]byte

	// we need to go in reverse order, iavl starts from root to leaf,
	// we want to go up from the leaf to the root
	for i := len(path) - 1; i >= 0; i-- {
		// this is adapted from iavl/proof.go:proofInnerNode.Hash()
		prefix := convertVarIntToBytes(int64(path[i].Height), varintBuf)
		prefix = append(prefix, convertVarIntToBytes(path[i].Size, varintBuf)...)
		prefix = append(prefix, convertVarIntToBytes(path[i].Version, varintBuf)...)

		var suffix []byte
		if len(path[i].Left) > 0 {
			// length prefixed left side
			prefix = append(prefix, lengthByte)
			prefix = append(prefix, path[i].Left...)
			// prepend the length prefix for child
			prefix = append(prefix, lengthByte)
		} else {
			// prepend the length prefix for child
			prefix = append(prefix, lengthByte)
			// length-prefixed right side
			suffix = []byte{lengthByte}
			suffix = append(suffix, path[i].Right...)
		}

		op := &ics23.InnerOp{
			Hash:   ics23.HashOp_SHA256,
			Prefix: prefix,
			Suffix: suffix,
		}
		steps = append(steps, op)
	}
	return steps
}

func convertVarIntToBytes(orig int64, buf [binary.MaxVarintLen64]byte) []byte {
	n := binary.PutVarint(buf[:], orig)
	return buf[:n]
}

// GetProof gets the proof for the given key.
func (t *ImmutableTree) GetProofWithKey(key []byte) ([]*ics23.CommitmentProof, error) {
	if t.root == nil {
		return nil, fmt.Errorf("cannot generate the proof with nil root")
	}

	exist, err := t.Has(key)
	if err != nil {
		return nil, err
	}

	if exist {
		return t.GetMembershipProofWithKey(key)
	} else {
		return t.GetNonMembershipProofWithKey(key)
	}
}

// GetProof gets the proof for the given key.
func (t *ImmutableTree) GetMembershipProofWithKey(key []byte) ([]*ics23.CommitmentProof, error) {
	proofs := []*ics23.CommitmentProof{}

	exist, keys, err := t.createExistenceProofWithKey(key)
	if err != nil {
		return nil, err
	}

	proofs = append(proofs, &ics23.CommitmentProof{
		Proof: &ics23.CommitmentProof_Exist{
			Exist: exist,
		},
	})

	for i := range keys {
		if bytes.Equal(key, keys[i]) {
			continue
		}
		p, err := t.GetMembershipProof(keys[i])
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, p)
	}

	return proofs, nil
}

func (t *ImmutableTree) GetNonMembershipProofWithKey(key []byte) ([]*ics23.CommitmentProof, error) {
	proofs := []*ics23.CommitmentProof{}

	// idx is one node right of what we want....
	var err error
	idx, val, err := t.GetWithIndex(key)
	if err != nil {
		return nil, err
	}

	if val != nil {
		return nil, fmt.Errorf("cannot create NonExistanceProof when Key in State")
	}

	nonexist := &ics23.NonExistenceProof{
		Key: key,
	}

	dupkey := KeysMap{}
	keys := KeysMap{}
	if idx >= 1 {
		leftkey, _, err := t.GetByIndex(idx - 1)
		if err != nil {
			return nil, err
		}
		var pkeys [][]byte
		nonexist.Left, pkeys, err = t.createExistenceProofWithKey(leftkey)
		if err != nil {
			return nil, err
		}
		dupkey.Set(leftkey)
		keys.SetKeys(pkeys)
	}

	// this will be nil if nothing right of the queried key
	rightkey, _, err := t.GetByIndex(idx)
	if err != nil {
		return nil, err
	}

	if rightkey != nil {
		var pkeys [][]byte
		nonexist.Right, pkeys, err = t.createExistenceProofWithKey(rightkey)
		if err != nil {
			return nil, err
		}
		dupkey.Set(rightkey)
		keys.SetKeys(pkeys)
	}

	proofs = append(proofs, &ics23.CommitmentProof{
		Proof: &ics23.CommitmentProof_Nonexist{
			Nonexist: nonexist,
		},
	})

	for _, k := range keys.List() {
		if dupkey.Has(k) {
			continue
		}
		p, err := t.GetMembershipProof(k)
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, p)
	}

	return proofs, nil
}

func (t *ImmutableTree) createExistenceProofWithKey(key []byte) (*ics23.ExistenceProof, [][]byte, error) {
	_, err := t.Hash()
	if err != nil {
		return nil, nil, err
	}
	path, node, keys, err := t.root.PathToLeafWithKeys(t, key)
	if err != nil {
		return nil, nil, err
	}

	return &ics23.ExistenceProof{
		Key:   node.key,
		Value: node.value,
		Leaf:  convertLeafOp(node.version),
		Path:  convertInnerOps(path),
	}, keys, err
}
