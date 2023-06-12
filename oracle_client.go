package iavl

import (
	"bytes"
	"encoding/hex"
	"fmt"

	ics23 "github.com/confio/ics23/go"
)

type OracleClientI interface {
	GetProof(string, string) []*ics23.CommitmentProof
}

type OracleClient struct {
	oracle      OracleClientI
	accessedKey AccessedKey
	storeName   string
}

func NewOracleClient(oracle OracleClientI, storeName string) *OracleClient {
	return &OracleClient{
		oracle:      oracle,
		accessedKey: AccessedKey{},
		storeName:   storeName,
	}
}

func (c *OracleClient) GetProof(path, data string) ([]*ics23.CommitmentProof, bool) {
	if c.accessedKey.Has(path, data) {
		return nil, true
	}
	c.accessedKey.Set(path, data)
	return c.oracle.GetProof(path, data), false
}

func (c *OracleClient) GetRootHash() []byte {
	proofs, _ := c.GetProof(c.keyPath(), dataString([]byte("roothash")))
	rootHash := proofs[len(proofs)-1].GetExist().Value
	return rootHash
}

func (c *OracleClient) GetNodesWithKey(key []byte) ([]*Node, bool) {
	ps, accessed := c.GetProof(c.keysPath(), dataString(key))
	if accessed {
		return nil, accessed
	}

	ps = ps[:len(ps)-1]
	eps := []*ics23.ExistenceProof{}
	pnk := 0
	ns := NodeSet{}
	pns := NodeSet{}

	for i := range ps {
		eps = append(eps, getExistenceProof(ps[i])...)
		if i == 0 {
			pnk = len(eps)
		}
	}

	for i := range eps {
		ep := eps[i]

		leaf, err := fromLeafOp(ep.GetLeaf(), ep.Key, ep.Value)
		if err != nil {
			panic(err)
		}
		ns.Set(leaf)
		if i < pnk {
			pns.Set(leaf)
			c.accessedKey.Set(c.keysPath(), dataString(leaf.key))
		}
		prevHash := leaf.hash

		path := ep.GetPath()
		for j := range path {
			inner, err := fromInnerOp(path[j], prevHash)
			if err != nil {
				panic(err)
			}
			ns.Set(inner)
			if i < pnk {
				pns.Set(inner)
			}

			prevHash = inner.hash
		}
	}

	for i := range ns {
		n := ns[i]
		if len(n.leftHash) > 0 && n.leftNode == nil {
			n.leftNode = ns.Get(n.leftHash)
		}
		if len(n.rightHash) > 0 && n.rightNode == nil {
			n.rightNode = ns.Get(n.rightHash)
		}
	}

	for i := range pns {
		n := pns[i]
		n.key = n.getNodeKey()
	}

	for i := range pns {
		n := pns[i]
		n.leftNode = nil
		n.rightNode = nil
	}

	return pns.List(), false
}

func (c *OracleClient) GetNode(hash []byte) (*Node, bool) {
	proofs, accessed := c.GetProof(c.nodePath(), dataString(hash))
	if accessed {
		return nil, accessed
	}

	proof := proofs[0]
	var node *Node

	ep := getExistenceProof(proof)[0]

	leaf, err := fromLeafOp(ep.GetLeaf(), ep.Key, ep.Value)
	if err != nil {
		panic(err)
	}
	c.accessedKey.Set(c.keysPath(), dataString(leaf.key))
	if bytes.Equal(hash, leaf.hash) {
		node = leaf
	}

	if node == nil {
		prevHash := leaf.hash
		path := ep.GetPath()
		for j := range path {
			inner, err := fromInnerOp(path[j], prevHash)
			if err != nil {
				panic(err)
			}
			if bytes.Equal(hash, inner.hash) {
				node = inner
				break
			}
			prevHash = inner.hash
		}
	}

	if node == nil {
		panic("something wrong")
	} else {
		node.key = leaf.key
	}

	return node, false
}

func getExistenceProof(cp *ics23.CommitmentProof) []*ics23.ExistenceProof {
	eps := []*ics23.ExistenceProof{}
	switch cp.GetProof().(type) {
	case *ics23.CommitmentProof_Exist:
		eps = append(eps, cp.GetExist())
	case *ics23.CommitmentProof_Nonexist:
		nep := cp.GetNonexist()
		if nep.Left != nil {
			eps = append(eps, nep.Left)
		}
		if nep.Right != nil {
			eps = append(eps, nep.Right)
		}
	}
	return eps
}

func (c *OracleClient) keyPath() string {
	return fmt.Sprintf("%s/key", c.storeName)
}

func (c *OracleClient) keysPath() string {
	return fmt.Sprintf("%s/keys", c.storeName)
}

func (c *OracleClient) nodePath() string {
	return fmt.Sprintf("%s/node", c.storeName)
}

func dataString(b []byte) string {
	return hex.EncodeToString(b)
}

type NodeSet map[string]*Node

func (s NodeSet) Set(n *Node) {
	key := fmt.Sprintf("%x", n.hash)
	if s[key] == nil {
		s[key] = n
	}
}

func (s NodeSet) Get(hash []byte) *Node {
	return s[fmt.Sprintf("%x", hash)]
}

func (s NodeSet) Has(hash []byte) bool {
	return s.Get(hash) != nil
}

func (s NodeSet) List() []*Node {
	ns := []*Node{}
	for i := range s {
		ns = append(ns, s[i])
	}
	return ns
}

type AccessedKey map[string]map[string]struct{}

func (ak AccessedKey) Set(k1, k2 string) {
	_, ok := ak[k1]
	if !ok {
		ak[k1] = map[string]struct{}{}
	}
	ak[k1][k2] = struct{}{}
}

func (ak AccessedKey) Has(k1, k2 string) bool {
	_, ok := ak[k1]
	if !ok {
		return false
	}
	_, ok = ak[k1][k2]
	return ok
}
