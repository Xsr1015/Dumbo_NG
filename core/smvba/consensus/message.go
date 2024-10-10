package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/pool"
	"bytes"
	"encoding/gob"
	"reflect"
	"strconv"
)

const (
	SPB_ONE_PHASE int8 = iota
	SPB_TWO_PHASE
)

const (
	VOTE_FLAG_YES int8 = iota
	VOTE_FLAG_NO
)

type Validator interface {
	Verify(core.Committee) bool
}

type Block struct {
	Proposer core.NodeID
	Batch    pool.Batch
	//Epoch    int64
	Height  int64
	PreHash crypto.Digest
}

func NewBlock(proposer core.NodeID, Batch pool.Batch, Height int64, PreHash crypto.Digest) *Block {
	return &Block{
		Proposer: proposer,
		Batch:    Batch,
		Height:   Height,
		PreHash:  PreHash,
	}
}

func (b *Block) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *Block) Decode(data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := gob.NewDecoder(buf).Decode(b); err != nil {
		return err
	}
	return nil
}

func (b *Block) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(b.Proposer), 2))
	hasher.Add(strconv.AppendInt(nil, b.Height, 2))
	hasher.Add(strconv.AppendInt(nil, int64(b.Batch.ID), 2))
	return hasher.Sum256(nil)
}

type BlockMessage struct {
	Author    core.NodeID
	B         *Block
	Height    int64
	Signature crypto.Signature
}

func NewBlockMessage(Author core.NodeID, B *Block, Height int64, sigService *crypto.SigService) (*BlockMessage, error) {
	blockMessage := &BlockMessage{
		Author: Author,
		B:      B,
		Height: Height,
	}
	sig, err := sigService.RequestSignature(blockMessage.Hash())
	if err != nil {
		return nil, err
	}
	blockMessage.Signature = sig
	return blockMessage, nil
}

func (bm *BlockMessage) Verify(committee core.Committee) bool {
	pub := committee.Name(bm.Author)
	return bm.Signature.Verify(pub, bm.Hash())
}

func (bm *BlockMessage) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(bm.Author), 2))
	hasher.Add(strconv.AppendInt(nil, bm.Height, 2))
	if bm.B != nil {
		d := bm.B.Hash()
		hasher.Add(d[:])
	}
	return hasher.Sum256(nil)
}

func (*BlockMessage) MsgType() int {
	return BlockMessageType
}

type VoteforBlock struct {
	Author    core.NodeID
	BlockHash crypto.Digest
	Height    int64
	Signature crypto.Signature
}

func NewVoteforBlock(Author core.NodeID, BlockHash crypto.Digest, Height int64, sigService *crypto.SigService) (*VoteforBlock, error) {
	vote := &VoteforBlock{
		Author:    Author,
		BlockHash: BlockHash,
		Height:    Height,
	}
	sig, err := sigService.RequestSignature(vote.Hash())
	if err != nil {
		return nil, err
	}
	vote.Signature = sig
	return vote, nil
}

func (v *VoteforBlock) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *VoteforBlock) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(v.Author), 2))
	hasher.Add(strconv.AppendInt(nil, v.Height, 2))
	hasher.Add(v.BlockHash[:])
	return hasher.Sum256(nil)
}

func (*VoteforBlock) MsgType() int {
	return VoteforBlockType
}

type CertForBlockData struct {
	Height int64
	Hash   crypto.Digest
}

type SMVBABlock struct {
	Proposer      core.NodeID
	SMVBAProposal map[core.NodeID]*CertForBlockData
	Epoch         int64
}

func NewSMVBABlock(proposer core.NodeID, SMVBAProposal map[core.NodeID]*CertForBlockData, Epoch int64) *SMVBABlock {
	return &SMVBABlock{
		Proposer:      proposer,
		SMVBAProposal: SMVBAProposal,
		Epoch:         Epoch,
	}
}

func (b *SMVBABlock) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *SMVBABlock) Decode(data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := gob.NewDecoder(buf).Decode(b); err != nil {
		return err
	}
	return nil
}

func (b *SMVBABlock) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(b.Proposer), 2))
	hasher.Add(strconv.AppendInt(nil, b.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, int64(b.SMVBAProposal[1].Height), 2))
	hasher.Add(b.SMVBAProposal[1].Hash[:])
	return hasher.Sum256(nil)
}

type SPBProposal struct {
	Author    core.NodeID
	B         *SMVBABlock
	Epoch     int64
	Round     int64
	Phase     int8
	Signature crypto.Signature
}

func NewSPBProposal(Author core.NodeID, B *SMVBABlock, Epoch, Round int64, Phase int8, sigService *crypto.SigService) (*SPBProposal, error) {
	proposal := &SPBProposal{
		Author: Author,
		B:      B,
		Epoch:  Epoch,
		Round:  Round,
		Phase:  Phase,
	}
	sig, err := sigService.RequestSignature(proposal.Hash())
	if err != nil {
		return nil, err
	}
	proposal.Signature = sig
	return proposal, nil
}

func (p *SPBProposal) Verify(committee core.Committee) bool {
	pub := committee.Name(p.Author)
	return p.Signature.Verify(pub, p.Hash())
}

func (p *SPBProposal) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(p.Author), 2))
	hasher.Add(strconv.AppendInt(nil, p.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, p.Round, 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Phase), 2))
	if p.B != nil {
		d := p.B.Hash()
		hasher.Add(d[:])
	}
	return hasher.Sum256(nil)
}

func (*SPBProposal) MsgType() int {
	return SPBProposalType
}

type SPBVote struct {
	Author    core.NodeID
	Proposer  core.NodeID
	BlockHash crypto.Digest
	Epoch     int64
	Round     int64
	Phase     int8
	Signature crypto.Signature
}

func NewSPBVote(Author, Proposer core.NodeID, BlockHash crypto.Digest, Epoch, Round int64, Phase int8, sigService *crypto.SigService) (*SPBVote, error) {
	vote := &SPBVote{
		Author:    Author,
		Proposer:  Proposer,
		BlockHash: BlockHash,
		Epoch:     Epoch,
		Round:     Round,
		Phase:     Phase,
	}
	sig, err := sigService.RequestSignature(vote.Hash())
	if err != nil {
		return nil, err
	}
	vote.Signature = sig
	return vote, nil
}

func (v *SPBVote) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *SPBVote) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(v.Author), 2))
	hasher.Add(strconv.AppendInt(nil, v.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, v.Round, 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Phase), 2))
	hasher.Add(v.BlockHash[:])
	return hasher.Sum256(nil)
}

func (*SPBVote) MsgType() int {
	return SPBVoteType
}

type Finish struct {
	Author    core.NodeID
	BlockHash crypto.Digest
	Epoch     int64
	Round     int64
	Signature crypto.Signature
}

func NewFinish(Author core.NodeID, BlockHash crypto.Digest, Epoch, Round int64, sigService *crypto.SigService) (*Finish, error) {
	finish := &Finish{
		Author:    Author,
		BlockHash: BlockHash,
		Epoch:     Epoch,
		Round:     Round,
	}
	sig, err := sigService.RequestSignature(finish.Hash())
	if err != nil {
		return nil, err
	}
	finish.Signature = sig
	return finish, nil
}

func (f *Finish) Verify(committee core.Committee) bool {
	pub := committee.Name(f.Author)
	return f.Signature.Verify(pub, f.Hash())
}

func (f *Finish) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(f.BlockHash[:])
	hasher.Add(strconv.AppendInt(nil, int64(f.Author), 2))
	hasher.Add(strconv.AppendInt(nil, f.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, f.Round, 2))
	return hasher.Sum256(nil)
}

func (*Finish) MsgType() int {
	return FinishType
}

type Done struct {
	Author    core.NodeID
	Epoch     int64
	Round     int64
	Signature crypto.Signature
}

func NewDone(Author core.NodeID, epoch, round int64, sigService *crypto.SigService) (*Done, error) {
	done := &Done{
		Author: Author,
		Epoch:  epoch,
		Round:  round,
	}
	sig, err := sigService.RequestSignature(done.Hash())
	if err != nil {
		return nil, err
	}
	done.Signature = sig
	return done, nil
}

func (d *Done) Verify(committee core.Committee) bool {
	pub := committee.Name(d.Author)
	return d.Signature.Verify(pub, d.Hash())
}

func (d *Done) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(d.Author), 2))
	hasher.Add(strconv.AppendInt(nil, d.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, d.Round, 2))
	return hasher.Sum256(nil)
}

func (*Done) MsgType() int {
	return DoneType
}

type ElectShare struct {
	Author   core.NodeID
	Epoch    int64
	Round    int64
	SigShare crypto.SignatureShare
}

func NewElectShare(Author core.NodeID, epoch, round int64, sigService *crypto.SigService) (*ElectShare, error) {
	elect := &ElectShare{
		Author: Author,
		Epoch:  epoch,
		Round:  round,
	}
	sig, err := sigService.RequestTsSugnature(elect.Hash())
	if err != nil {
		return nil, err
	}
	elect.SigShare = sig
	return elect, nil
}

func (e *ElectShare) Verify(committee core.Committee) bool {
	_ = committee.Name(e.Author)
	return e.SigShare.Verify(e.Hash())
}

func (e *ElectShare) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, e.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, e.Round, 2))
	return hasher.Sum256(nil)
}

func (*ElectShare) MsgType() int {
	return ElectShareType
}

type Prevote struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Round     int64
	Flag      int8
	BlockHash crypto.Digest
	Signature crypto.Signature
}

func NewPrevote(Author, Leader core.NodeID, Epoch, Round int64, flag int8, BlockHash crypto.Digest, sigService *crypto.SigService) (*Prevote, error) {
	prevote := &Prevote{
		Author:    Author,
		Leader:    Leader,
		Epoch:     Epoch,
		Round:     Round,
		Flag:      flag,
		BlockHash: BlockHash,
	}
	sig, err := sigService.RequestSignature(prevote.Hash())
	if err != nil {
		return nil, err
	}
	prevote.Signature = sig
	return prevote, nil
}

func (p *Prevote) Verify(committee core.Committee) bool {
	pub := committee.Name(p.Author)
	return p.Signature.Verify(pub, p.Hash())
}

func (p *Prevote) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(p.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Leader), 2))
	hasher.Add(strconv.AppendInt(nil, p.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, p.Round, 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Flag), 2))
	hasher.Add(p.BlockHash[:])
	return hasher.Sum256(nil)
}

func (*Prevote) MsgType() int {
	return PrevoteType
}

type FinVote struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Round     int64
	Flag      int8
	BlockHash crypto.Digest
	Signature crypto.Signature
}

func NewFinVote(Author, Leader core.NodeID, Epoch, Round int64, flag int8, BlockHash crypto.Digest, sigService *crypto.SigService) (*FinVote, error) {
	prevote := &FinVote{
		Author:    Author,
		Epoch:     Epoch,
		Round:     Round,
		Flag:      flag,
		BlockHash: BlockHash,
	}
	sig, err := sigService.RequestSignature(prevote.Hash())
	if err != nil {
		return nil, err
	}
	prevote.Signature = sig
	return prevote, nil
}

func (p *FinVote) Verify(committee core.Committee) bool {
	pub := committee.Name(p.Author)
	return p.Signature.Verify(pub, p.Hash())
}

func (p *FinVote) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(p.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Leader), 2))
	hasher.Add(strconv.AppendInt(nil, p.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, p.Round, 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Flag), 2))
	hasher.Add(p.BlockHash[:])
	return hasher.Sum256(nil)
}

func (*FinVote) MsgType() int {
	return FinVoteType
}

type Halt struct {
	Author    core.NodeID
	Epoch     int64
	Round     int64
	Leader    core.NodeID
	BlockHash crypto.Digest
	Signature crypto.Signature
}

func NewHalt(Author, Leader core.NodeID, BlockHash crypto.Digest, Epoch, Round int64, sigService *crypto.SigService) (*Halt, error) {
	h := &Halt{
		Author:    Author,
		Epoch:     Epoch,
		Round:     Round,
		Leader:    Leader,
		BlockHash: BlockHash,
	}
	sig, err := sigService.RequestSignature(h.Hash())
	if err != nil {
		return nil, err
	}
	h.Signature = sig
	return h, nil
}

func (h *Halt) Verify(committee core.Committee) bool {
	pub := committee.Name(h.Author)
	return h.Signature.Verify(pub, h.Hash())
}

func (h *Halt) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(h.Author), 2))
	hasher.Add(strconv.AppendInt(nil, h.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, int64(h.Leader), 2))
	hasher.Add(h.BlockHash[:])
	return hasher.Sum256(nil)
}

func (*Halt) MsgType() int {
	return HaltType
}

const (
	SPBProposalType int = iota
	SPBVoteType
	FinishType
	DoneType
	ElectShareType
	PrevoteType
	FinVoteType
	HaltType
	BlockMessageType
	VoteforBlockType
)

var DefaultMessageTypeMap = map[int]reflect.Type{
	SPBProposalType:  reflect.TypeOf(SPBProposal{}),
	SPBVoteType:      reflect.TypeOf(SPBVote{}),
	FinishType:       reflect.TypeOf(Finish{}),
	DoneType:         reflect.TypeOf(Done{}),
	ElectShareType:   reflect.TypeOf(ElectShare{}),
	PrevoteType:      reflect.TypeOf(Prevote{}),
	FinVoteType:      reflect.TypeOf(FinVote{}),
	HaltType:         reflect.TypeOf(Halt{}),
	BlockMessageType: reflect.TypeOf(BlockMessage{}),
	VoteforBlockType: reflect.TypeOf(VoteforBlock{}),
}
