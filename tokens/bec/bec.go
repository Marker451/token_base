package bec

import (
	"github.com/Marker451/token_base/erc20token"
	"github.com/Marker451/token_base/geth"
	"github.com/ethereum/go-ethereum/common"
)

const TOKEN_ADDRESS = "0xc5d105e63711398af9bbff092d4b6769c82f793d"

type BecToken struct {
	*Token
}

func(t *BecToken)GetAbi()string{
	return TokenABI
}
func(t *BecToken)GetTokenAddr()string{
	return TOKEN_ADDRESS
}

func NewTokenERC20(nodeAddr string)(token erc20token.Erc20token, err error){
	ethCli, err := geth.NewEthClient(nodeAddr)
	if err != nil {
		return
	}
	becToken, err := NewToken(common.HexToAddress(TOKEN_ADDRESS),ethCli)
	if err != nil {
		return nil, err
	}
	token = &BecToken{becToken}
	return
}