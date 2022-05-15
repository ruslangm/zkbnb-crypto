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

import (
	"errors"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/zecrey-labs/zecrey-crypto/zecrey-legend/circuit/bn254/std"
	"log"
)

type TxConstraints struct {
	// tx type
	TxType Variable
	// different transactions
	RegisterZnsTxInfo     RegisterZnsTxConstraints
	CreatePairTxInfo      CreatePairTxConstraints
	DepositTxInfo         DepositTxConstraints
	DepositNftTxInfo      DepositNftTxConstraints
	TransferTxInfo        TransferTxConstraints
	SwapTxInfo            SwapTxConstraints
	AddLiquidityTxInfo    AddLiquidityTxConstraints
	RemoveLiquidityTxInfo RemoveLiquidityTxConstraints
	MintNftTxInfo         MintNftTxConstraints
	TransferNftTxInfo     TransferNftTxConstraints
	SetNftPriceTxInfo     SetNftPriceTxConstraints
	BuyNftTxInfo          BuyNftTxConstraints
	WithdrawTxInfo        WithdrawTxConstraints
	WithdrawNftTxInfo     WithdrawNftTxConstraints
	FullExitTxInfo        FullExitTxConstraints
	FullExitNftTxInfo     FullExitNftTxConstraints
	// signature
	Signature SignatureConstraints
	// account root before
	AccountRootBefore Variable
	// account before info, size is 5
	AccountsInfoBefore [NbAccountsPerTx]std.AccountConstraints
	// liquidity root before
	LiquidityRootBefore Variable
	// liquidity before
	LiquidityBefore std.LiquidityConstraints
	// nft root before
	NftRootBefore Variable
	// nft before
	NftBefore std.NftConstraints
	// state root before
	StateRootBefore Variable
	// before account asset merkle proof
	MerkleProofsAccountAssetsBefore [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels]Variable
	// before liquidity merkle proof
	MerkleProofsLiquidityBefore [LiquidityMerkleLevels]Variable
	// before nft tree merkle proof
	MerkleProofsNftBefore [NftMerkleLevels]Variable
	// before account merkle proof
	MerkleProofsAccountBefore [NbAccountsPerTx][AccountMerkleLevels]Variable
	// state root after
	StateRootAfter Variable
}

func (circuit TxConstraints) Define(api API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	pubdataHashFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	err = VerifyTransaction(api, circuit, hFunc, pubdataHashFunc)
	if err != nil {
		return err
	}
	return nil
}

func VerifyTransaction(
	api API,
	tx TxConstraints,
	hFunc MiMC,
	pubdataHashFunc MiMC,
) error {
	// compute tx type
	isEmptyTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeEmptyTx))
	isRegisterZnsTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeRegisterZns))
	isCreatePairTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeCreatePair))
	isDepositTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeDeposit))
	isDepositNftTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeDepositNft))
	isTransferTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeTransfer))
	isSwapTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeSwap))
	isAddLiquidityTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeAddLiquidity))
	isRemoveLiquidityTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeRemoveLiquidity))
	isWithdrawTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeWithdraw))
	isMintNftTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeMintNft))
	isTransferNftTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeTransferNft))
	isSetNftPriceTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeSetNftPrice))
	isBuyNftTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeBuyNft))
	isWithdrawNftTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeWithdrawNft))
	isFullExitTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeFullExit))
	isFullExitNftTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeFullExitNft))

	// no need to verify signature transaction
	notNoSignatureTx := api.IsZero(
		api.Or(
			isEmptyTx,
			api.Or(
				api.Or(
					isRegisterZnsTx,
					isDepositTx,
				),
				api.Or(
					isDepositNftTx,
					api.Or(
						isCreatePairTx,
						api.Or(
							isFullExitTx,
							isFullExitNftTx,
						),
					),
				))))

	// get hash value from tx based on tx type
	// transfer tx
	hashVal := std.ComputeHashFromTransferTx(tx.TransferTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	// swap tx
	hashValCheck := std.ComputeHashFromSwapTx(tx.SwapTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isSwapTx, hashValCheck, hashVal)
	// add liquidity tx
	hashValCheck = std.ComputeHashFromAddLiquidityTx(tx.AddLiquidityTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isAddLiquidityTx, hashValCheck, hashVal)
	// remove liquidity tx
	hashValCheck = std.ComputeHashFromRemoveLiquidityTx(tx.RemoveLiquidityTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isRemoveLiquidityTx, hashValCheck, hashVal)
	// withdraw tx
	hashValCheck = std.ComputeHashFromWithdrawTx(tx.WithdrawTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isWithdrawTx, hashValCheck, hashVal)
	// mint nft tx
	hashValCheck = std.ComputeHashFromMintNftTx(tx.MintNftTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isMintNftTx, hashValCheck, hashVal)
	// transfer nft tx
	hashValCheck = std.ComputeHashFromTransferNftTx(tx.TransferNftTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isTransferNftTx, hashValCheck, hashVal)
	// set nft price tx
	hashValCheck = std.ComputeHashFromSetNftPriceTx(tx.SetNftPriceTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isSetNftPriceTx, hashValCheck, hashVal)
	// buy nft tx
	hashValCheck = std.ComputeHashFromBuyNftTx(tx.BuyNftTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isBuyNftTx, hashValCheck, hashVal)
	// withdraw nft tx
	hashValCheck = std.ComputeHashFromWithdrawNftTx(tx.WithdrawNftTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isWithdrawNftTx, hashValCheck, hashVal)
	hFunc.Reset()
	// verify signature
	err := std.VerifyEddsaSig(
		notNoSignatureTx,
		api,
		hFunc,
		hashVal,
		tx.AccountsInfoBefore[0].AccountPk,
		tx.Signature,
	)
	if err != nil {
		log.Println("[VerifyTx] invalid signature:", err)
		return err
	}

	// verify transactions
	std.VerifyRegisterZNSTx(api, isRegisterZnsTx, tx.RegisterZnsTxInfo, tx.AccountsInfoBefore, &pubdataHashFunc)
	std.VerifyCreatePairTx(api, isCreatePairTx, tx.CreatePairTxInfo, tx.LiquidityBefore, &pubdataHashFunc)
	std.VerifyDepositTx(api, isDepositTx, tx.DepositTxInfo, tx.AccountsInfoBefore, &pubdataHashFunc)
	std.VerifyDepositNftTx(api, isDepositNftTx, tx.DepositNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore, &pubdataHashFunc)
	std.VerifyTransferTx(api, isTransferTx, &tx.TransferTxInfo, tx.AccountsInfoBefore, &pubdataHashFunc)
	std.VerifySwapTx(api, isSwapTx, &tx.SwapTxInfo, tx.AccountsInfoBefore, tx.LiquidityBefore, &pubdataHashFunc)
	std.VerifyAddLiquidityTx(api, isAddLiquidityTx, &tx.AddLiquidityTxInfo, tx.AccountsInfoBefore, tx.LiquidityBefore, &pubdataHashFunc)
	std.VerifyRemoveLiquidityTx(api, isRemoveLiquidityTx, &tx.RemoveLiquidityTxInfo, tx.AccountsInfoBefore, tx.LiquidityBefore, &pubdataHashFunc)
	std.VerifyWithdrawTx(api, isWithdrawTx, &tx.WithdrawTxInfo, tx.AccountsInfoBefore, &pubdataHashFunc)
	std.VerifyMintNftTx(api, isMintNftTx, &tx.MintNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore, &pubdataHashFunc)
	std.VerifyTransferNftTx(api, isTransferNftTx, &tx.TransferNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore, &pubdataHashFunc)
	std.VerifySetNftPriceTx(api, isSetNftPriceTx, &tx.SetNftPriceTxInfo, tx.AccountsInfoBefore, tx.NftBefore, &pubdataHashFunc)
	std.VerifyBuyNftTx(api, isBuyNftTx, &tx.BuyNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore, &pubdataHashFunc)
	std.VerifyWithdrawNftTx(api, isWithdrawNftTx, &tx.WithdrawNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore, &pubdataHashFunc)
	std.VerifyFullExitTx(api, isFullExitTx, tx.FullExitTxInfo, tx.AccountsInfoBefore, &pubdataHashFunc)
	std.VerifyFullExitNftTx(api, isFullExitNftTx, tx.FullExitNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore, &pubdataHashFunc)

	// empty delta
	var (
		assetDeltas    [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints
		liquidityDelta LiquidityDeltaConstraints
		nftDelta       NftDeltaConstraints
	)
	for i := 0; i < NbAccountsPerTx; i++ {
		assetDeltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	liquidityDelta = LiquidityDeltaConstraints{
		AssetAId:    tx.LiquidityBefore.AssetAId,
		AssetBId:    tx.LiquidityBefore.AssetBId,
		AssetADelta: std.ZeroInt,
		AssetBDelta: std.ZeroInt,
		LpDelta:     std.ZeroInt,
	}
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: tx.NftBefore.CreatorAccountIndex,
		OwnerAccountIndex:   tx.NftBefore.OwnerAccountIndex,
		NftContentHash:      tx.NftBefore.NftContentHash,
		NftL1Address:        tx.NftBefore.NftL1Address,
		NftL1TokenId:        tx.NftBefore.NftL1TokenId,
		AssetId:             tx.NftBefore.AssetId,
		AssetAmount:         tx.NftBefore.AssetAmount,
		CreatorTreasuryRate: tx.NftBefore.CreatorTreasuryRate,
	}

	// register
	accountDelta := GetAccountDeltaFromRegisterZNS(tx.RegisterZnsTxInfo)
	// deposit
	assetDeltasCheck := GetAssetDeltasFromDeposit(tx.DepositTxInfo)
	assetDeltas = SelectAssetDeltas(api, isDepositTx, assetDeltasCheck, assetDeltas)
	// create pair
	liquidityDeltaCheck := GetLiquidityDeltaFromCreatePair(tx.CreatePairTxInfo)
	liquidityDelta = SelectLiquidityDelta(api, isSwapTx, liquidityDeltaCheck, liquidityDelta)
	// generic transfer
	assetDeltasCheck = GetAssetDeltasFromTransfer(api, tx.TransferTxInfo)
	assetDeltas = SelectAssetDeltas(api, isTransferTx, assetDeltasCheck, assetDeltas)
	// swap
	assetDeltasCheck, liquidityDeltaCheck = GetAssetDeltasAndLiquidityDeltaFromSwap(api, tx.SwapTxInfo, tx.LiquidityBefore)
	assetDeltas = SelectAssetDeltas(api, isSwapTx, assetDeltasCheck, assetDeltas)
	liquidityDelta = SelectLiquidityDelta(api, isSwapTx, liquidityDeltaCheck, liquidityDelta)
	// add liquidity
	assetDeltasCheck, liquidityDeltaCheck = GetAssetDeltasAndLiquidityDeltaFromAddLiquidity(api, tx.AddLiquidityTxInfo, tx.LiquidityBefore)
	assetDeltas = SelectAssetDeltas(api, isAddLiquidityTx, assetDeltasCheck, assetDeltas)
	liquidityDelta = SelectLiquidityDelta(api, isAddLiquidityTx, liquidityDeltaCheck, liquidityDelta)
	// remove liquidity
	assetDeltasCheck, liquidityDeltaCheck = GetAssetDeltasAndLiquidityDeltaFromRemoveLiquidity(api, tx.RemoveLiquidityTxInfo, tx.LiquidityBefore)
	assetDeltas = SelectAssetDeltas(api, isRemoveLiquidityTx, assetDeltasCheck, assetDeltas)
	liquidityDelta = SelectLiquidityDelta(api, isRemoveLiquidityTx, liquidityDeltaCheck, liquidityDelta)
	// withdraw
	assetDeltasCheck = GetAssetDeltasFromWithdraw(api, tx.WithdrawTxInfo)
	assetDeltas = SelectAssetDeltas(api, isWithdrawTx, assetDeltasCheck, assetDeltas)
	// deposit nft
	nftDeltaCheck := GetNftDeltaFromDepositNft(tx.DepositNftTxInfo)
	nftDelta = SelectNftDeltas(api, isDepositNftTx, nftDeltaCheck, nftDelta)
	// mint nft
	assetDeltasCheck, nftDeltaCheck = GetAssetDeltasAndNftDeltaFromMintNft(api, tx.MintNftTxInfo)
	assetDeltas = SelectAssetDeltas(api, isMintNftTx, assetDeltasCheck, assetDeltas)
	nftDelta = SelectNftDeltas(api, isMintNftTx, nftDeltaCheck, nftDelta)
	// transfer nft
	assetDeltasCheck, nftDeltaCheck = GetAssetDeltasAndNftDeltaFromTransferNft(api, tx.TransferNftTxInfo, tx.NftBefore)
	assetDeltas = SelectAssetDeltas(api, isTransferNftTx, assetDeltasCheck, assetDeltas)
	nftDelta = SelectNftDeltas(api, isTransferNftTx, nftDeltaCheck, nftDelta)
	// set nft price
	assetDeltasCheck, nftDeltaCheck = GetAssetDeltasAndNftDeltaFromSetNftPrice(api, tx.SetNftPriceTxInfo, tx.NftBefore)
	assetDeltas = SelectAssetDeltas(api, isSetNftPriceTx, assetDeltasCheck, assetDeltas)
	nftDelta = SelectNftDeltas(api, isSetNftPriceTx, nftDeltaCheck, nftDelta)
	// buy nft
	assetDeltasCheck, nftDeltaCheck = GetAssetDeltasAndNftDeltaFromBuyNft(api, tx.BuyNftTxInfo, tx.NftBefore)
	assetDeltas = SelectAssetDeltas(api, isBuyNftTx, assetDeltasCheck, assetDeltas)
	nftDelta = SelectNftDeltas(api, isBuyNftTx, nftDeltaCheck, nftDelta)
	// withdraw nft
	assetDeltasCheck, nftDeltaCheck = GetAssetDeltasAndNftDeltaFromWithdrawNft(api, tx.WithdrawNftTxInfo)
	assetDeltas = SelectAssetDeltas(api, isWithdrawNftTx, assetDeltasCheck, assetDeltas)
	nftDelta = SelectNftDeltas(api, isWithdrawNftTx, nftDeltaCheck, nftDelta)
	// full exit
	assetDeltasCheck = GetAssetDeltasFromFullExit(api, tx.FullExitTxInfo)
	assetDeltas = SelectAssetDeltas(api, isFullExitTx, assetDeltasCheck, assetDeltas)
	// full exit nft
	nftDeltaCheck = GetNftDeltaFromFullExitNft()
	nftDelta = SelectNftDeltas(api, isFullExitNftTx, nftDeltaCheck, nftDelta)
	// update accounts
	AccountsInfoAfter := UpdateAccounts(api, tx.AccountsInfoBefore, assetDeltas)
	AccountsInfoAfter[0].AccountNameHash = api.Select(isRegisterZnsTx, accountDelta.AccountNameHash, AccountsInfoAfter[0].AccountNameHash)
	AccountsInfoAfter[0].AccountPk.A.X = api.Select(isRegisterZnsTx, accountDelta.PubKey.A.X, AccountsInfoAfter[0].AccountPk.A.X)
	AccountsInfoAfter[0].AccountPk.A.Y = api.Select(isRegisterZnsTx, accountDelta.PubKey.A.Y, AccountsInfoAfter[0].AccountPk.A.Y)
	// update liquidity
	LiquidityAfter := UpdateLiquidity(api, tx.LiquidityBefore, liquidityDelta)
	// update nft
	NftAfter := UpdateNft(tx.NftBefore, nftDelta)

	// check old state root
	hFunc.Reset()
	hFunc.Write(
		tx.AccountRootBefore,
		tx.LiquidityRootBefore,
		tx.NftRootBefore,
	)
	oldStateRoot := hFunc.Sum()
	std.IsVariableEqual(api, 1, oldStateRoot, tx.StateRootBefore)

	NewAccountRoot := tx.AccountRootBefore
	notEmptyTx := api.IsZero(isEmptyTx)
	for i := 0; i < NbAccountsPerTx; i++ {
		var (
			NewAccountAssetsRoot = tx.AccountsInfoBefore[i].AssetRoot
		)
		// verify account asset node hash
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			assetMerkleHelper := AssetIdToMerkleHelper(api, tx.AccountsInfoBefore[i].AssetsInfo[j].AssetId)
			hFunc.Reset()
			hFunc.Write(
				tx.AccountsInfoBefore[i].AssetsInfo[j].Balance,
				tx.AccountsInfoBefore[i].AssetsInfo[j].LpAmount,
			)
			assetNodeHash := hFunc.Sum()
			// verify account asset merkle proof
			hFunc.Reset()
			std.VerifyMerkleProof(
				api,
				notEmptyTx,
				hFunc,
				tx.AccountsInfoBefore[i].AssetRoot,
				assetNodeHash,
				tx.MerkleProofsAccountAssetsBefore[i][j][:],
				assetMerkleHelper,
			)
			hFunc.Reset()
			hFunc.Write(
				AccountsInfoAfter[i].AssetsInfo[j].Balance,
				AccountsInfoAfter[i].AssetsInfo[j].LpAmount,
			)
			assetNodeHash = hFunc.Sum()
			hFunc.Reset()
			// update merkle proof
			NewAccountAssetsRoot = std.UpdateMerkleProof(
				api, hFunc, assetNodeHash, tx.MerkleProofsAccountAssetsBefore[i][j][:], assetMerkleHelper)
		}
		// verify account node hash
		accountIndexMerkleHelper := AccountIndexToMerkleHelper(api, tx.AccountsInfoBefore[i].AccountIndex)
		hFunc.Reset()
		hFunc.Write(
			tx.AccountsInfoBefore[i].AccountNameHash,
			tx.AccountsInfoBefore[i].AccountPk.A.X,
			tx.AccountsInfoBefore[i].AccountPk.A.Y,
			tx.AccountsInfoBefore[i].Nonce,
			tx.AccountsInfoBefore[i].AssetRoot,
		)
		accountNodeHash := hFunc.Sum()
		// verify account merkle proof
		hFunc.Reset()
		std.VerifyMerkleProof(
			api,
			notEmptyTx,
			hFunc,
			NewAccountRoot,
			accountNodeHash,
			tx.MerkleProofsAccountBefore[i][:],
			accountIndexMerkleHelper,
		)
		hFunc.Reset()
		hFunc.Write(
			AccountsInfoAfter[i].AccountNameHash,
			AccountsInfoAfter[i].AccountPk.A.X,
			AccountsInfoAfter[i].AccountPk.A.Y,
			AccountsInfoAfter[i].Nonce,
			NewAccountAssetsRoot,
		)
		accountNodeHash = hFunc.Sum()
		hFunc.Reset()
		// update merkle proof
		NewAccountRoot = std.UpdateMerkleProof(api, hFunc, accountNodeHash, tx.MerkleProofsAccountBefore[i][:], accountIndexMerkleHelper)
	}

	//// liquidity tree
	NewLiquidityRoot := tx.LiquidityRootBefore
	pairIndexMerkleHelper := PairIndexToMerkleHelper(api, tx.LiquidityBefore.PairIndex)
	hFunc.Write(
		tx.LiquidityBefore.AssetAId,
		tx.LiquidityBefore.AssetA,
		tx.LiquidityBefore.AssetBId,
		tx.LiquidityBefore.AssetB,
		tx.LiquidityBefore.LpAmount,
	)
	liquidityNodeHash := hFunc.Sum()
	// verify account merkle proof
	hFunc.Reset()
	std.VerifyMerkleProof(
		api,
		notEmptyTx,
		hFunc,
		NewLiquidityRoot,
		liquidityNodeHash,
		tx.MerkleProofsLiquidityBefore[:],
		pairIndexMerkleHelper,
	)
	hFunc.Reset()
	hFunc.Write(
		LiquidityAfter.AssetAId,
		LiquidityAfter.AssetA,
		LiquidityAfter.AssetBId,
		LiquidityAfter.AssetB,
		LiquidityAfter.LpAmount,
	)
	liquidityNodeHash = hFunc.Sum()
	hFunc.Reset()
	// update merkle proof
	NewLiquidityRoot = std.UpdateMerkleProof(api, hFunc, liquidityNodeHash, tx.MerkleProofsLiquidityBefore[:], pairIndexMerkleHelper)

	//// nft tree
	NewNftRoot := tx.NftRootBefore
	nftIndexMerkleHelper := NftIndexToMerkleHelper(api, tx.NftBefore.NftIndex)
	hFunc.Reset()
	hFunc.Write(
		tx.NftBefore.CreatorAccountIndex,
		tx.NftBefore.OwnerAccountIndex,
		tx.NftBefore.NftContentHash,
		tx.NftBefore.NftL1Address,
		tx.NftBefore.NftL1TokenId,
		tx.NftBefore.AssetId,
		tx.NftBefore.AssetAmount,
		tx.NftBefore.CreatorTreasuryRate,
	)
	nftNodeHash := hFunc.Sum()
	// verify account merkle proof
	hFunc.Reset()
	std.VerifyMerkleProof(
		api,
		notEmptyTx,
		hFunc,
		NewNftRoot,
		nftNodeHash,
		tx.MerkleProofsNftBefore[:],
		nftIndexMerkleHelper,
	)
	hFunc.Reset()
	hFunc.Write(
		NftAfter.CreatorAccountIndex,
		NftAfter.OwnerAccountIndex,
		NftAfter.NftContentHash,
		NftAfter.NftL1Address,
		NftAfter.NftL1TokenId,
		NftAfter.AssetId,
		NftAfter.AssetAmount,
		NftAfter.CreatorTreasuryRate,
	)
	nftNodeHash = hFunc.Sum()
	hFunc.Reset()
	// update merkle proof
	NewNftRoot = std.UpdateMerkleProof(api, hFunc, nftNodeHash, tx.MerkleProofsNftBefore[:], nftIndexMerkleHelper)

	// check state root
	hFunc.Reset()
	hFunc.Write(
		NewAccountRoot,
		NewLiquidityRoot,
		NewNftRoot,
	)
	newStateRoot := hFunc.Sum()
	std.IsVariableEqual(api, 1, newStateRoot, tx.StateRootAfter)

	return nil
}

func SetTxWitness(oTx *Tx) (witness TxConstraints, err error) {
	witness.RegisterZnsTxInfo = std.EmptyRegisterZnsTxWitness()
	witness.CreatePairTxInfo = std.EmptyCreatePairTxWitness()
	witness.DepositTxInfo = std.EmptyDepositTxWitness()
	witness.DepositNftTxInfo = std.EmptyDepositNftTxWitness()
	witness.TransferTxInfo = std.EmptyTransferTxWitness()
	witness.SwapTxInfo = std.EmptySwapTxWitness()
	witness.AddLiquidityTxInfo = std.EmptyAddLiquidityTxWitness()
	witness.RemoveLiquidityTxInfo = std.EmptyRemoveLiquidityTxWitness()
	witness.MintNftTxInfo = std.EmptyMintNftTxWitness()
	witness.TransferNftTxInfo = std.EmptyTransferNftTxWitness()
	witness.SetNftPriceTxInfo = std.EmptySetNftPriceTxWitness()
	witness.BuyNftTxInfo = std.EmptyBuyNftTxWitness()
	witness.WithdrawTxInfo = std.EmptyWithdrawTxWitness()
	witness.WithdrawNftTxInfo = std.EmptyWithdrawNftTxWitness()
	witness.FullExitTxInfo = std.EmptyFullExitTxWitness()
	witness.FullExitNftTxInfo = std.EmptyFullExitNftTxWitness()
	switch oTx.TxType {
	case std.TxTypeEmptyTx:
		break
	case std.TxTypeRegisterZns:
		witness.RegisterZnsTxInfo = std.SetRegisterZnsTxWitness(oTx.RegisterZnsTxInfo)
		break
	case std.TxTypeCreatePair:
		witness.CreatePairTxInfo = std.SetCreatePairTxWitness(oTx.CreatePairTxInfo)
		break
	case std.TxTypeDeposit:
		witness.DepositTxInfo = std.SetDepositTxWitness(oTx.DepositTxInfo)
		break
	case std.TxTypeDepositNft:
		witness.DepositNftTxInfo = std.SetDepositNftTxWitness(oTx.DepositNftTxInfo)
		break
	case std.TxTypeTransfer:
		witness.TransferTxInfo = std.SetTransferTxWitness(oTx.TransferTxInfo)
		break
	case std.TxTypeSwap:
		witness.SwapTxInfo = std.SetSwapTxWitness(oTx.SwapTxInfo)
		break
	case std.TxTypeAddLiquidity:
		witness.AddLiquidityTxInfo = std.SetAddLiquidityTxWitness(oTx.AddLiquidityTxInfo)
		break
	case std.TxTypeRemoveLiquidity:
		witness.RemoveLiquidityTxInfo = std.SetRemoveLiquidityTxWitness(oTx.RemoveLiquidityTxInfo)
		break
	case std.TxTypeWithdraw:
		witness.WithdrawTxInfo = std.SetWithdrawTxWitness(oTx.WithdrawTxInfo)
		break
	case std.TxTypeMintNft:
		witness.MintNftTxInfo = std.SetMintNftTxWitness(oTx.MintNftTxInfo)
		break
	case std.TxTypeTransferNft:
		witness.TransferNftTxInfo = std.SetTransferNftTxWitness(oTx.TransferNftTxInfo)
		break
	case std.TxTypeSetNftPrice:
		witness.SetNftPriceTxInfo = std.SetSetNftPriceTxWitness(oTx.SetNftPriceTxInfo)
		break
	case std.TxTypeBuyNft:
		witness.BuyNftTxInfo = std.SetBuyNftTxWitness(oTx.BuyNftTxInfo)
		break
	case std.TxTypeWithdrawNft:
		witness.WithdrawNftTxInfo = std.SetWithdrawNftTxWitness(oTx.WithdrawNftTxInfo)
		break
	case std.TxTypeFullExit:
		witness.FullExitTxInfo = std.SetFullExitTxWitness(oTx.FullExitTxInfo)
		break
	case std.TxTypeFullExitNft:
		witness.FullExitNftTxInfo = std.SetFullExitNftTxWitness(oTx.FullExitNftTxInfo)
		break
	default:
		log.Println("[SetTxWitness] invalid oTx type")
		return witness, errors.New("[SetTxWitness] invalid oTx type")
	}
	// set common account & merkle parts
	// account root before
	witness.AccountRootBefore = oTx.AccountRootBefore
	witness.LiquidityRootBefore = oTx.LiquidityBefore
	witness.NftRootBefore = oTx.NftRootBefore
	witness.StateRootAfter = oTx.StateRootAfter
	// account before info, size is 4
	for i := 0; i < NbAccountsPerTx; i++ {
		// accounts info before
		witness.AccountsInfoBefore[i], err = std.SetAccountWitness(oTx.AccountsInfoBefore[i])
		if err != nil {
			log.Println("[SetTxWitness] err info:", err)
			return witness, err
		}
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			for k := 0; k < AssetMerkleLevels; k++ {
				// account assets before
				witness.MerkleProofsAccountAssetsBefore[i][j][k] = oTx.MerkleProofsAccountAssetsBefore[i][j][k]
			}
		}
		for j := 0; j < AccountMerkleLevels; j++ {
			// account before
			witness.MerkleProofsAccountBefore[i][j] = oTx.MerkleProofsAccountBefore[i][j]
		}
	}
	for i := 0; i < LiquidityMerkleLevels; i++ {
		// nft assets before
		witness.MerkleProofsLiquidityBefore[i] = oTx.MerkleProofsLiquidityBefore[i]
	}
	for i := 0; i < NftMerkleLevels; i++ {
		// nft assets before
		witness.MerkleProofsNftBefore[i] = oTx.MerkleProofsNftBefore[i]
	}
	return witness, nil
}