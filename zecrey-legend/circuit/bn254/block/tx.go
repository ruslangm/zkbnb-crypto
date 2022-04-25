/*
 * Copyright © 2021 Zecrey Protocol
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package block

import "github.com/zecrey-labs/zecrey-crypto/zecrey-legend/circuit/bn254/std"

type Tx struct {
	// tx type
	TxType uint8
	// different transactions
	RegisterZnsTxInfo     *RegisterZnsTx
	DepositTxInfo         *DepositTx
	DepositNftTxInfo      *DepositNftTx
	TransferTxInfo        *TransferTx
	SwapTxInfo            *SwapTx
	AddLiquidityTxInfo    *AddLiquidityTx
	RemoveLiquidityTxInfo *RemoveLiquidityTx
	MintNftTxInfo         *MintNftTx
	TransferNftTxInfo     *TransferNftTx
	SetNftPriceTxInfo     *SetNftPriceTx
	BuyNftTxInfo          *BuyNftTx
	WithdrawTxInfo        *WithdrawTx
	WithdrawNftTxInfo     *WithdrawNftTx
	// signature
	Signature *Signature
	// account root before
	AccountRootBefore []byte
	// account before info, size is 4
	AccountsInfoBefore [NbAccountsPerTx]*std.Account
	// before account asset merkle proof
	MerkleProofsAccountAssetsBefore       [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels][]byte
	MerkleProofsHelperAccountAssetsBefore [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleHelperLevels]int
	// before account liquidity merkle proof
	MerkleProofsAccountLiquidityBefore       [NbAccountsPerTx][LiquidityMerkleLevels][]byte
	MerkleProofsHelperAccountLiquidityBefore [NbAccountsPerTx][LiquidityMerkleHelperLevels]int
	// before account nft tree merkle proof
	MerkleProofsAccountNftBefore       [NbAccountsPerTx][NftMerkleLevels][]byte
	MerkleProofsHelperAccountNftBefore [NbAccountsPerTx][NftMerkleHelperLevels]int
	// before account merkle proof
	MerkleProofsAccountBefore       [NbAccountsPerTx][AccountMerkleLevels][]byte
	MerkleProofsHelperAccountBefore [NbAccountsPerTx][AccountMerkleHelperLevels]int
	// account root after
	AccountRootAfter []byte
}
