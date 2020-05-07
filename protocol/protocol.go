package protocol


import (
	"errors"
	"sync"
	"time"
	"bytes"
	"math"
	"fmt"
	"encoding/json"

	"github.com/gaohaoyang0530/onet"
	"github.com/gaohaoyang0530/onet/log"
	"github.com/gaohaoyang0530/onet/network"
	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/sign/schnorr"


	"crypto/sha512"
)


func init() {
	//调用onet/network/lvl.go  
	//SetDebugVisible set the global debug output level in a go-rountine-safe way
	log.SetDebugVisible(1)
	//调用onet/network/encoding.go
	network.RegisterMessages(Announce{}, PrepareSigShare{}, CommitProof{}, CommitSigShare{}, ExecuteProof{}, Reply{})
	//调用onet/protocol.go
	onet.GlobalProtocolRegister(DefaultProtocolName, NewProtocol)
}


type VerificationFn func(msg []byte, data []byte) bool

var defaultTimeout = 60 * time.Second

type FbftProtocol struct {
	*onet.TreeNodeInstance

	Msg					[]byte
	Data 				[]byte
	nNodes				int

	FinalReply 			chan []byte
	startChan       	chan bool
	stoppedOnce    		sync.Once
	verificationFn  	VerificationFn
	Timeout 			time.Duration
	PubKeysMap			map[string]kyber.Point

	ChannelAnnounce             chan StructAnnounce
	ChannelPrepareSigShare 		chan StructPrepareSigShare
	ChannelCommitProof		    chan StructCommitProof
	ChannelCommitSigShare		chan StructCommitSigShare
	ChannelExecuteProof		    chan StructExecuteProof
	ChannelReply		        chan StructReply

}

// Check that *FbftProtocol implements onet.ProtocolInstance
var _ onet.ProtocolInstance = (*FbftProtocol)(nil)

// NewProtocol initialises the structure for use in one round
func NewProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	pubKeysMap := make(map[string]kyber.Point)
	for _, node := range n.Tree().List() {
		//fmt.Println(node.ServerIdentity, node.ServerIdentity.Public, node.ServerIdentity.ID.String())
		pubKeysMap[node.ServerIdentity.ID.String()] = node.ServerIdentity.Public
	}

	vf := func(msg, data []byte) bool {
		// Simulate verification function by sleeping
		b, _ := json.Marshal(msg)
		m := time.Duration(len(b) / (500 * 1024))  //verification of 150ms per 500KB simulated
		waitTime := 150 * time.Millisecond * m
		log.Lvl3("Verifying for", waitTime)
		time.Sleep(waitTime)  

		return true 
	}

	t := &FbftProtocol{
		TreeNodeInstance: 	n,
		nNodes: 			n.Tree().Size(),
		startChan:       	make(chan bool, 1),
		FinalReply:   		make(chan []byte, 1),
		PubKeysMap:			pubKeysMap,
		Data:            	make([]byte, 0),
		verificationFn:		vf,
	}

	for _, channel := range []interface{}{
		&t.ChannelAnnounce,
		&t.ChannelPrepareSigShare,
		&t.ChannelCommitProof,
		&t.ChannelCommitSigShare,
		&t.ChannelExecuteProof,
		&t.ChannelReply,
	} {
		err := t.RegisterChannel(channel)
		if err != nil {
			return nil, errors.New("couldn't register channel: " + err.Error())
		}
	}

	return t, nil
}

// Start sends the Announce-message to all children
func (fbft *FbftProtocol) Start() error {
	// TODO verify args not null

	log.Lvl1("Starting FbftProtocol")
	
	return nil
}

func (fbft *FbftProtocol) Dispatch() error {

	log.Lvl1(fbft.ServerIdentity(), "Started node")

	nRepliesThreshold := int(math.Ceil(float64(fbft.nNodes - 1 ) * (float64(2)/float64(3)))) + 1
	nRepliesThreshold = min(nRepliesThreshold, fbft.nNodes - 1)

	// Verification of the data
	verifyChan := make(chan bool, 1)

	var futureDigest []byte

	// Announce Phase
	if fbft.IsRoot() {
		// Leader sends the announce message to all the replicas
		digest := sha512.Sum512(fbft.Msg) // TODO digest is correct?

		announcesig, err := schnorr.Sign(fbft.Suite(), fbft.Private(), fbft.Msg)
		if err != nil {
			return err
		}

		log.Lvl1(fbft.ServerIdentity(), "Leader is sending the announce message to replicas")
		go func() {
			if errs := fbft.SendToChildrenInParallel(&Announce{Msg:fbft.Msg, Digest:digest[:], Sig:announcesig, Sender:fbft.ServerIdentity().ID.String()}); len(errs) > 0 {
				log.Lvl1(fbft.ServerIdentity(), "failed to send announce message to all replicas")
			}
		}()

		futureDigest = digest[:]

	} else {
		// wait for announce message from leader
		log.Lvl1(fbft.ServerIdentity(), "Waiting for announce message")
		announce, channelOpen := <-fbft.ChannelAnnounce
		if !channelOpen {
			return nil
		}
		log.Lvl1(fbft.ServerIdentity(), "Received Announce message. Verifying...")
		go func() {
			verifyChan <- fbft.verificationFn(announce.Msg, fbft.Data)
		}()

		// Verify the signature for authentication
		err := schnorr.Verify(fbft.Suite(), fbft.PubKeysMap[announce.Sender], announce.Msg, announce.Sig)
		if err != nil {
			return err
		}

		// verify message digest
		digest := sha512.Sum512(announce.Msg)
		if !bytes.Equal(digest[:], announce.Digest) {
			log.Lvl1(fbft.ServerIdentity(), "received Announce digest is not correct")
		}

		futureDigest = announce.Digest

		ok := <-verifyChan
		if !ok {
			return fmt.Errorf("verification failed on node")
		}
	
		// All nodes sign message
		signedDigest, err := schnorr.Sign(fbft.Suite(), fbft.Private(), futureDigest)
		if err != nil {
			return err
		}
		// Send signature share message to leader
		err1 := fbft.SendToParent(&PrepareSigShare{Digest:futureDigest, Sig:signedDigest, Sender:fbft.ServerIdentity().ID.String()})
		if err1 != nil {
			log.Lvl1(fbft.ServerIdentity(), "error while sending prepare signature sharing message to leader")
		}
	}
	
	nReceivedPrepareSigShareMessages := 0
	
	// Prepare phase
	if fbft.IsRoot() {
	log.Lvl1(fbft.ServerIdentity(), "Leader is waiting for prepare signatures from replicas")
	
	PrepareSigShareLoop:	
		for  i := 0; i <= nRepliesThreshold - 1; i++  {
			select {
				case preparesigshare, channelOpen := <-fbft.ChannelPrepareSigShare:
					if !channelOpen {
						return nil
					}

					// Verify the signature for authentication
					err := schnorr.Verify(fbft.Suite(), fbft.PubKeysMap[preparesigshare.Sender], preparesigshare.Digest, preparesigshare.Sig)
					if err != nil {
						return err
					}
					nReceivedPrepareSigShareMessages++
				case <-time.After(defaultTimeout * 2):
					// 超时，结束等待
					break PrepareSigShareLoop
				}
			}

			if !(nReceivedPrepareSigShareMessages >= nRepliesThreshold) {
				log.Lvl1(fbft.ServerIdentity(), "Leader didn't receive enough prepare signature share messages. Stopping.", nReceivedPrepareSigShareMessages, " / ", nRepliesThreshold)
				return errors.New("Leader didn't receive enough prepare signature share messages. Stopping.")
			} else {
				log.Lvl1(fbft.ServerIdentity(), "Received enough prepare signature share messages (> 2/3 + 1):", nReceivedPrepareSigShareMessages, "/", fbft.nNodes)			


				// leader sign message
				signedDigest1, err := schnorr.Sign(fbft.Suite(), fbft.Private(), futureDigest)
				if err != nil {
					return err
				}

				// Send commit proof message to each replica
				log.Lvl1(fbft.ServerIdentity(), "is sending commit proof message to all replicas")
				go func(){
					if errs := fbft.SendToChildrenInParallel(&CommitProof{Digest:futureDigest, Sig:signedDigest1, Proof:nReceivedPrepareSigShareMessages, Sender:fbft.ServerIdentity().ID.String()}); len(errs) > 0 {
						log.Lvl1(fbft.ServerIdentity(), "error while sending commit proof message to leader")
					}
				}()
				
			}
	
	} else {
		// waiting for commit proof message fromm leader
		log.Lvl1(fbft.ServerIdentity(), "Waiting for commit proof message")
		select {
		case commitproof, channelOpen := <-fbft.ChannelCommitProof:
			if !channelOpen {
				return nil
			}
			log.Lvl1(fbft.ServerIdentity(), "Received Commit Proof message. Verifying...")
				
			// Verify the signature for authentication
			err := schnorr.Verify(fbft.Suite(), fbft.PubKeysMap[commitproof.Sender], commitproof.Digest, commitproof.Sig)
			if err != nil {
				return err
			}

			signum := commitproof.Proof

			if(signum < nRepliesThreshold) {
				log.Lvl1("No enough valid signaure, invalid commitproof message.....")
			} else {
				// Send Commit Signature Share message to leader
				futureDigest = commitproof.Digest

				// All nodes sign message
				signedDigest2, err := schnorr.Sign(fbft.Suite(), fbft.Private(), futureDigest)
				if err != nil {
					return err
				}
				// Send signature share message to leader
				log.Lvl1(fbft.ServerIdentity(), "is sending commit signature share message to leader")
				err1 := fbft.SendToParent(&CommitSigShare{Digest:futureDigest, Sig:signedDigest2, Sender:fbft.ServerIdentity().ID.String()})
				if err1 != nil {
					log.Lvl1(fbft.ServerIdentity(), "error while sending commit signature sharing message to leader")
				}
			}

		case <-time.After(defaultTimeout * 2):
			// 超时，结束等待
			log.Lvl3("timeout")
		}
	}


	nReceivedCommitSigShareMessages := 0

	// Commit Phase
	if fbft.IsRoot() {
	CommitSigShareLoop:	
		for  i := 0; i <= nRepliesThreshold - 1; i++  {
			select {
				case commitsigshare, channelOpen := <-fbft.ChannelCommitSigShare:
					if !channelOpen {
						return nil
					}

					// Verify the signature for authentication
					err := schnorr.Verify(fbft.Suite(), fbft.PubKeysMap[commitsigshare.Sender], commitsigshare.Digest, commitsigshare.Sig)
					if err != nil {
						return err
					}
					nReceivedCommitSigShareMessages++
				case <-time.After(defaultTimeout * 2):
					// 超时，结束等待
					break CommitSigShareLoop
				}
			}

			if !(nReceivedCommitSigShareMessages >= nRepliesThreshold) {
				log.Lvl1(fbft.ServerIdentity(), "Leader didn't receive enough commit signature share messages. Stopping.", nReceivedPrepareSigShareMessages, " / ", nRepliesThreshold)
				return errors.New("Leader didn't receive enough commit signature share messages. Stopping.")
			} else {
				log.Lvl1(fbft.ServerIdentity(), "Received enough commit signature share messages (> 2/3 + 1):", nReceivedPrepareSigShareMessages, "/", fbft.nNodes)			

				// leader sign message
				signedDigest3, err := schnorr.Sign(fbft.Suite(), fbft.Private(), futureDigest)
				if err != nil {
					return err
				}

				// Send excute proof message to each replica
				log.Lvl1(fbft.ServerIdentity(), "is sending excute proof message to all replicas")
				if errs := fbft.SendToChildrenInParallel(&ExecuteProof{Digest:futureDigest, Sig:signedDigest3, Proof:nReceivedCommitSigShareMessages, Sender:fbft.ServerIdentity().ID.String()}); len(errs) > 0 {
					log.Lvl1(fbft.ServerIdentity(), "error while sending excute proof message to leader")
				}

			}

	
	} else {
		// wait for excute proof from leader
		log.Lvl1(fbft.ServerIdentity(), "Waiting for excute proof message")
		select {
		case excuteproof, channelOpen := <-fbft.ChannelExecuteProof:
			if !channelOpen {
				return nil
			}
			log.Lvl1(fbft.ServerIdentity(), "Received Excute Proof message. Verifying...")
				
			// Verify the signatures for authentication
			err := schnorr.Verify(fbft.Suite(), fbft.PubKeysMap[excuteproof.Sender], excuteproof.Digest, excuteproof.Sig)
			if err != nil {
				return err
			}

			excutesignum := excuteproof.Proof

			if(excutesignum < nRepliesThreshold) {
				log.Lvl1("No enough valid signaure, invalid excuteproof message.....")
			} else {
				// Send reply message to leader
				futureDigest = excuteproof.Digest

				// All nodes sign message
				signedDigest4, err := schnorr.Sign(fbft.Suite(), fbft.Private(), futureDigest)
				if err != nil {
					return err
				}
				// Send reply message to leader
				log.Lvl1(fbft.ServerIdentity(), "is sending reply message to leader")
				err1 := fbft.SendToParent(&Reply{Result:futureDigest, Sender:fbft.ServerIdentity().ID.String(), Sig:signedDigest4})
				if err1 != nil {
					log.Lvl1(fbft.ServerIdentity(), "error while sending reply message to leader")
				}
			}

		case <-time.After(defaultTimeout * 4):
			// timeout, stop waiting
			log.Lvl1("timeout when waiting for excuteproof")
		}
	
	}

	receivedReplies := 0

	// varify reply
	if fbft.IsRoot() {
	log.Lvl1(fbft.ServerIdentity(), "Leader is waiting for reply message from replicas")
	replyLoop:
		for  i := 0; i <= nRepliesThreshold - 1; i++  {
			select {
				case reply, channelOpen := <-fbft.ChannelReply:
					if !channelOpen {
						return nil
					}

					// Verify the signatures for authentication
					err := schnorr.Verify(fbft.Suite(), fbft.PubKeysMap[reply.Sender], reply.Result, reply.Sig)
					if err != nil {
						return err
					}

					receivedReplies++
					log.Lvl1("Leader got one reply, total received is now", receivedReplies, "out of", nRepliesThreshold, "needed.")
				
				case <-time.After(defaultTimeout * 2):
					// wait a bit longer than the protocol timeout
					log.Lvl1("didn't get reply in time")
					break replyLoop
			}
		}

	fbft.FinalReply <- futureDigest[:]

	} 

	return nil
}

// Shutdown stops the protocol
func (fbft *FbftProtocol) Shutdown() error {
	fbft.stoppedOnce.Do(func() {
		close(fbft.ChannelAnnounce)
		close(fbft.ChannelPrepareSigShare)
		close(fbft.ChannelCommitProof)
		close(fbft.ChannelCommitSigShare)
		close(fbft.ChannelExecuteProof)
		close(fbft.ChannelReply)
	})
	return nil
}


func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}