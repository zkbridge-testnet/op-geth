package polyhedra_signer

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const SAFE_BLOCK_NUM = -4

type PolyhedraSigner struct {
	client *ethclient.Client

	privateKey *ecdsa.PrivateKey
	publicKey  []byte
}

func NewPolyhedraSigner(rpc string) *PolyhedraSigner {
	ctx := context.Background()

	client, err := ethclient.DialContext(ctx, rpc)
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal(errors.New("error casting public key to ECDSA"))
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	return &PolyhedraSigner{
		client:     client,
		privateKey: privateKey,
		publicKey:  publicKeyBytes,
	}
}

func (s *PolyhedraSigner) VerifyAndSignTransaction(txHash common.Hash, signer types.Signer) ([]byte, []byte, error) {
	ctx := context.Background()
	// Pull transaction receipt using hash
	receipt, err := s.client.TransactionReceipt(context.Background(), txHash)
	if err != nil {
		return nil, nil, err
	}
	if receipt == nil {
		return nil, nil, errors.New("transaction is not yet included in any block")
	}

	// check if block level tx is in is greater than safe block level
	safeBlock, err := s.client.BlockByNumber(ctx, big.NewInt(SAFE_BLOCK_NUM))
	if err != nil {
		return nil, nil, errors.New("failed to fetch block")
	}
	txblockNum := receipt.BlockNumber.Uint64()
	mostRecentSafeBlockNumber := safeBlock.Number().Uint64()
	if txblockNum > mostRecentSafeBlockNumber {
		return nil, nil, errors.New("transaction is not yet safe")
	}

	// sign transaction hash
	signedTx, err := crypto.Sign(txHash.Bytes(), s.privateKey)
	if err != nil {
		return nil, nil, errors.New("failed to sign transaction")
	}

	return signedTx, s.publicKey, nil
}
