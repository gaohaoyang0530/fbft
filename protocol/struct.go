package protocol


import "github.com/gaohaoyang0530/onet"

// Name can be used from other packages to refer to this protocol.
const DefaultProtocolName = "FBFT"


type Announce struct {
	Msg []byte
	Digest []byte
	Sig []byte
	Sender string
}

type StructAnnounce struct {
	*onet.TreeNode
	Announce
}


type PrepareSigShare struct {
	Digest []byte
	Sig []byte
	Sender string
}

type StructPrepareSigShare struct {
	*onet.TreeNode
	PrepareSigShare
}

type CommitProof struct {
	Digest []byte
	Sig []byte
	Proof int
	Sender string
}

type StructCommitProof struct {
	*onet.TreeNode
	CommitProof
}

type CommitSigShare struct {
	Digest []byte
	Sig []byte
	Sender string
}

type StructCommitSigShare struct {
	*onet.TreeNode
	CommitSigShare
}

type ExecuteProof struct {
	Digest []byte
	Sig []byte
	Proof int
	Sender string
}

type StructExecuteProof struct {
	*onet.TreeNode
	ExecuteProof
}

type Reply struct {
	Result []byte
	Sig []byte
	Sender string
}

type StructReply struct {
	*onet.TreeNode
	Reply
}
