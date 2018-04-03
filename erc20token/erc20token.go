package erc20token

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
)

type Erc20token interface{
	TotalSupply(opts *bind.CallOpts) (*big.Int, error)
	BalanceOf(opts *bind.CallOpts, addr common.Address) (*big.Int, error)
	Allowance(opts *bind.CallOpts, addr common.Address, arg1 common.Address) (*big.Int, error)
	Transfer(opts *bind.TransactOpts, to common.Address, value *big.Int) (*types.Transaction, error)
	Approve(opts *bind.TransactOpts, spender common.Address, value *big.Int) (*types.Transaction, error)
	TransferFrom(opts *bind.TransactOpts, from common.Address, to common.Address, value *big.Int) (*types.Transaction, error)

	GetAbi()string
	GetTokenAddr()string
}
