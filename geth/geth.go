package geth

// 包内对币的操作 都以Wei 为单位

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Marker451/token_base/erc20token"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
	"strings"
)

const GAS_LIMIT = 121000

var invalidAddrErr = errors.New("invalid address")

type TokenClient struct {
	client    *ethclient.Client
	token     erc20token.Erc20token
	tokenAbi  abi.ABI
	tokenAddr string
}

type TransferLog struct {
	From     string
	To       string
	Val      *big.Int
	TxHash   string
	BlockNum uint64
}

func ImprotPrivateKey(pvk string, pwd string) (keyjson []byte, err error) {
	ks := keystore.NewKeyStore("./keystore", keystore.StandardScryptN, keystore.StandardScryptP)
	ecdsaPvk, err := crypto.HexToECDSA(pvk)
	if err != nil {
		return
	}
	account, err := ks.ImportECDSA(ecdsaPvk, pwd)
	if err != nil {
		return
	}
	return ks.Export(account, "", "")
}
func NewEthClient(nodeAddr string) (cli *ethclient.Client, err error) {
	return ethclient.Dial(nodeAddr)
}
func NewTokenClient(token erc20token.Erc20token, nodeAddr string) (cli *TokenClient, err error) {
	c, err := ethclient.Dial(nodeAddr)
	if err != nil {
		return nil, err
	}
	tokenAbiStr := token.GetAbi()
	tokenAbi, err := abi.JSON(strings.NewReader(tokenAbiStr))
	if err != nil {
		return nil, err
	}
	tokenAddr := token.GetTokenAddr()
	return &TokenClient{client: c, token: token, tokenAbi: tokenAbi, tokenAddr: tokenAddr}, nil
}

func (this *TokenClient) NewAccout(pwd string, storeDir string) (keyjson []byte, err error) {

	ks := keystore.NewKeyStore(storeDir, keystore.StandardScryptN, keystore.StandardScryptP)

	account, err := ks.NewAccount(pwd)
	if err != nil {
		return nil, err
	}
	return ks.Export(account, pwd, pwd)
}

func (this *TokenClient) BalanceOfToken(addr string) (balance *big.Int, err error) {
	if this.invalidAddress(addr) {
		return nil, invalidAddrErr
	}
	return this.token.BalanceOf(nil, common.HexToAddress(addr))
}

func (this *TokenClient) ETHBalanceOf(addr string) (balance *big.Int, err error) {
	if this.invalidAddress(addr) {
		return nil, invalidAddrErr
	}
	return this.client.BalanceAt(context.Background(), common.HexToAddress(addr), nil)
}

func (this *TokenClient) invalidAddress(addr string) bool {
	return common.HexToAddress(addr) == common.HexToAddress("some worng data will return 0 address")

}

// keyjson : the accoutn transfer from
func (this *TokenClient) TransferToken(keyjson []byte, pwd string, toAddress string, val *big.Int) (txHash string, err error) {
	if this.invalidAddress(toAddress) {
		return "", invalidAddrErr
	}
	opts, err := bind.NewTransactor(strings.NewReader(string(keyjson)), pwd)
	if err != nil {
		return
	}
	opts.GasLimit = GAS_LIMIT
	tx, err := this.token.Transfer(opts, common.HexToAddress(toAddress), val)
	if err != nil {
		return
	}
	return fmt.Sprintf("%x", tx.Hash()), nil
}

func (this *TokenClient) GetPendingNonce(addr string) {
	nonce, err := this.client.PendingNonceAt(context.Background(), common.HexToAddress(addr))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(nonce)
}

func (this *TokenClient) TransferETH(keyjson []byte, pwd string, toAddress string, val *big.Int) (txHash string, err error) {
	if this.invalidAddress(toAddress) {
		return "", invalidAddrErr
	}
	opts, err := bind.NewTransactor(strings.NewReader(string(keyjson)), pwd)
	if err != nil {
		return
	}
	nonce, err := this.client.PendingNonceAt(context.Background(), opts.From)
	if err != nil {
		return
	}
	gasPrice, err := this.client.SuggestGasPrice(context.Background())
	if err != nil {
		return
	}
	rawTx := types.NewTransaction(nonce, common.HexToAddress(toAddress), val, GAS_LIMIT, gasPrice, nil)
	signedTx, err := opts.Signer(types.HomesteadSigner{}, opts.From, rawTx)
	if err != nil {
		return "", err
	}
	if err := this.client.SendTransaction(context.Background(), signedTx); err != nil {
		return "", err
	}
	return signedTx.Hash().String(), nil
}

func (this *TokenClient) getEventID(eventName string) (id common.Hash, err error) {
	var (
		e  abi.Event
		ok bool
	)
	if e, ok = this.tokenAbi.Events[eventName]; !ok {
		return
	}
	return e.Id(), nil
}

// fromBlockNum: beginning of the queried range, nil means genesis block
// toBlockNum: end of the range, nil means latest block
func (this *TokenClient) GetTransferLog(fromBlockNum *big.Int, toBlockNum *big.Int) (logs []types.Log, err error) {
	eventID, err := this.getEventID("Transfer")
	if err != nil {
		return
	}
	query := ethereum.FilterQuery{
		FromBlock: fromBlockNum,
		ToBlock:   toBlockNum,
		Addresses: []common.Address{common.HexToAddress(this.tokenAddr)},
		Topics:    [][]common.Hash{{eventID}},
	}
	return this.getEventLos(fromBlockNum, toBlockNum, query)
}
func (this *TokenClient) GetAllTransferLogByAddress(fromBlockNum *big.Int, toBlockNum *big.Int, addr string) (logs []types.Log, err error) {
	fromLog, err := this.GetTransferLogByFromAddr(fromBlockNum, toBlockNum, addr)
	if err != nil {
		return
	}
	toLog, err := this.GetTransferLogByToAddr(fromBlockNum, toBlockNum, addr)
	if err != nil {
		return
	}
	returnData := make([]types.Log, len(fromLog)+len(toLog))
	fromLen := len(fromLog)
	toLen := len(toLog)
	fromIndex := 0
	toIndex := 0
	i := 0
	for ; fromIndex < fromLen && toIndex < toLen; i++ {
		if cmpTransferLog(fromLog[fromIndex], toLog[toIndex]) == -1 {
			returnData[i] = fromLog[fromIndex]
			fromIndex++
		} else {
			returnData[i] = toLog[toIndex]
			toIndex++
		}
	}
	if fromIndex >= fromLen {
		copy(returnData[i:], toLog[toIndex:])
	} else {
		copy(returnData[i:], fromLog[fromIndex:])
	}
	return returnData, nil
}

// a > b  return 1
// a < b  -1
// a = b  0
func cmpTransferLog(a types.Log, b types.Log) int {
	if a.BlockNumber > b.BlockNumber {
		return 1
	} else if a.BlockNumber < b.BlockNumber {
		return -1
	}
	if a.TxIndex > b.TxIndex {
		return 1
	} else if a.TxIndex < b.TxIndex {
		return -1
	}
	return 0
}

func (this *TokenClient) GetTransferLogByFromAddr(fromBlockNum *big.Int, toBlockNum *big.Int, from string) (logs []types.Log, err error) {
	eventID, err := this.getEventID("Transfer")
	if err != nil {
		return
	}
	query := ethereum.FilterQuery{
		FromBlock: fromBlockNum,
		ToBlock:   toBlockNum,
		Addresses: []common.Address{common.HexToAddress(this.tokenAddr)},
		Topics:    [][]common.Hash{{eventID}, {common.BytesToHash(common.FromHex(from))}},
	}
	return this.getEventLos(fromBlockNum, toBlockNum, query)
}
func (this *TokenClient) GetTransferLogByToAddr(fromBlockNum *big.Int, toBlockNum *big.Int, to string) (logs []types.Log, err error) {
	eventID, err := this.getEventID("Transfer")
	if err != nil {
		return
	}
	query := ethereum.FilterQuery{
		FromBlock: fromBlockNum,
		ToBlock:   toBlockNum,
		Addresses: []common.Address{common.HexToAddress(this.tokenAddr)},
		Topics:    [][]common.Hash{{eventID}, {}, {common.BytesToHash(common.FromHex(to))}},
	}
	return this.getEventLos(fromBlockNum, toBlockNum, query)
}
func (this *TokenClient) getEventLos(fromBlockNum *big.Int, toBlockNum *big.Int, query ethereum.FilterQuery) (logs []types.Log, err error) {
	return this.client.FilterLogs(context.Background(), query)

}

func (this *TokenClient) GetTxInfoByHash(txHash string) (tx *types.Transaction, isPending bool, err error) {
	return this.client.TransactionByHash(context.Background(), common.HexToHash(txHash))
}

func (this *TokenClient) GetLatestBlockNum() (blockNum uint64, err error) {
	block, err := this.client.BlockByNumber(context.Background(), nil)
	if err != nil {
		return
	}
	return block.NumberU64(), nil
}

func ConvertTransferLog(log types.Log) (lg *TransferLog, err error) {
	lg = &TransferLog{}
	lg.BlockNum = log.BlockNumber

	if len(log.Topics) < 3 {
		return nil, errors.New("not found valid transfer address")
	}
	//to trim the 0000... and add perfix "0x"
	// a little complex....  need be more graceful
	lg.From = "0x" + hex.EncodeToString(math.MustParseBig256(log.Topics[1].String()).Bytes())
	lg.To = "0x" + hex.EncodeToString(math.MustParseBig256(log.Topics[2].String()).Bytes())
	lg.Val = math.MustParseBig256("0x" + hex.EncodeToString(log.Data))
	lg.TxHash = log.TxHash.String()
	fmt.Println(lg.From, lg.To, log.BlockNumber, log.TxIndex)
	return
}
