/*
 * Copyright © 2022 ZkBNB Protocol
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

package circuit

import (
	"errors"
	"github.com/consensys/gnark/std/hash/poseidon"
	"log"

	"github.com/consensys/gnark/std/hash/mimc"

	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
)

type TxConstraints struct {
	// tx type
	TxType Variable
	// different transactions
	RegisterZnsTxInfo      RegisterZnsTxConstraints
	DepositTxInfo          DepositTxConstraints
	DepositNftTxInfo       DepositNftTxConstraints
	TransferTxInfo         TransferTxConstraints
	CreateCollectionTxInfo CreateCollectionTxConstraints
	MintNftTxInfo          MintNftTxConstraints
	TransferNftTxInfo      TransferNftTxConstraints
	AtomicMatchTxInfo      AtomicMatchTxConstraints
	CancelOfferTxInfo      CancelOfferTxConstraints
	WithdrawTxInfo         WithdrawTxConstraints
	WithdrawNftTxInfo      WithdrawNftTxConstraints
	FullExitTxInfo         FullExitTxConstraints
	FullExitNftTxInfo      FullExitNftTxConstraints
	// nonce
	Nonce Variable
	// expired at
	ExpiredAt Variable
	// signature
	Signature SignatureConstraints
	// account root before
	AccountRootBefore Variable
	// account before info, size is 4
	AccountsInfoBefore [NbAccountsPerTx]types.AccountConstraints
	// nft root before
	NftRootBefore Variable
	// nft before
	NftBefore types.NftConstraints
	// state root before
	StateRootBefore Variable
	// before account asset merkle proof
	MerkleProofsAccountAssetsBefore [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels]Variable
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

	_, _, _, _, err = VerifyTransaction(api, circuit, hFunc, 1633400952228, []int64{0}, [types.NbRoots]Variable{Variable(0), Variable(0)})
	if err != nil {
		return err
	}
	return nil
}

func VerifyTransaction(
	api API,
	tx TxConstraints,
	hFunc MiMC,
	blockCreatedAt Variable,
	gasAssetIds []int64,
	oldRoots [types.NbRoots]Variable,
) (isOnChainOp Variable, pubData [types.PubDataBitsSizePerTx]Variable, roots [types.NbRoots]Variable,
	gasDeltas [NbGasAssetsPerTx]GasDeltaConstraints, err error) {
	// compute tx type
	isEmptyTx := api.IsZero(api.Sub(tx.TxType, types.TxTypeEmptyTx))
	isRegisterZnsTx := api.IsZero(api.Sub(tx.TxType, types.TxTypeRegisterZns))
	isDepositTx := api.IsZero(api.Sub(tx.TxType, types.TxTypeDeposit))
	isDepositNftTx := api.IsZero(api.Sub(tx.TxType, types.TxTypeDepositNft))
	isTransferTx := api.IsZero(api.Sub(tx.TxType, types.TxTypeTransfer))
	isWithdrawTx := api.IsZero(api.Sub(tx.TxType, types.TxTypeWithdraw))
	isCreateCollectionTx := api.IsZero(api.Sub(tx.TxType, types.TxTypeCreateCollection))
	isMintNftTx := api.IsZero(api.Sub(tx.TxType, types.TxTypeMintNft))
	isTransferNftTx := api.IsZero(api.Sub(tx.TxType, types.TxTypeTransferNft))
	isAtomicMatchTx := api.IsZero(api.Sub(tx.TxType, types.TxTypeAtomicMatch))
	isCancelOfferTx := api.IsZero(api.Sub(tx.TxType, types.TxTypeCancelOffer))
	isWithdrawNftTx := api.IsZero(api.Sub(tx.TxType, types.TxTypeWithdrawNft))
	isFullExitTx := api.IsZero(api.Sub(tx.TxType, types.TxTypeFullExit))
	isFullExitNftTx := api.IsZero(api.Sub(tx.TxType, types.TxTypeFullExitNft))

	// verify nonce
	isLayer2Tx := api.Add(
		isTransferTx,
		isWithdrawTx,
		isCreateCollectionTx,
		isMintNftTx,
		isTransferNftTx,
		isAtomicMatchTx,
		isCancelOfferTx,
		isWithdrawNftTx,
	)

	isOnChainOp = api.Add(
		isRegisterZnsTx,
		isDepositTx,
		isDepositNftTx,
		isWithdrawTx,
		isWithdrawNftTx,
		isFullExitTx,
		isFullExitNftTx,
	)

	// get hash value from tx based on tx type
	// transfer tx
	hashVal := types.ComputeHashFromTransferTx(api, tx.TransferTxInfo, tx.Nonce, tx.ExpiredAt)
	// withdraw tx
	hashValCheck := types.ComputeHashFromWithdrawTx(api, tx.WithdrawTxInfo, tx.Nonce, tx.ExpiredAt)
	hashVal = api.Select(isWithdrawTx, hashValCheck, hashVal)
	// createCollection tx
	hashValCheck = types.ComputeHashFromCreateCollectionTx(api, tx.CreateCollectionTxInfo, tx.Nonce, tx.ExpiredAt)
	hashVal = api.Select(isCreateCollectionTx, hashValCheck, hashVal)
	// mint nft tx
	hashValCheck = types.ComputeHashFromMintNftTx(api, tx.MintNftTxInfo, tx.Nonce, tx.ExpiredAt)
	hashVal = api.Select(isMintNftTx, hashValCheck, hashVal)
	// transfer nft tx
	hashValCheck = types.ComputeHashFromTransferNftTx(api, tx.TransferNftTxInfo, tx.Nonce, tx.ExpiredAt)
	hashVal = api.Select(isTransferNftTx, hashValCheck, hashVal)
	// set nft price tx
	hashValCheck = types.ComputeHashFromAtomicMatchTx(api, tx.AtomicMatchTxInfo, tx.Nonce, tx.ExpiredAt)
	hashVal = api.Select(isAtomicMatchTx, hashValCheck, hashVal)
	// buy nft tx
	hashValCheck = types.ComputeHashFromCancelOfferTx(api, tx.CancelOfferTxInfo, tx.Nonce, tx.ExpiredAt)
	hashVal = api.Select(isCancelOfferTx, hashValCheck, hashVal)
	// withdraw nft tx
	hashValCheck = types.ComputeHashFromWithdrawNftTx(api, tx.WithdrawNftTxInfo, tx.Nonce, tx.ExpiredAt)
	hashVal = api.Select(isWithdrawNftTx, hashValCheck, hashVal)
	hFunc.Reset()

	types.IsVariableEqual(api, isLayer2Tx, tx.AccountsInfoBefore[0].Nonce, tx.Nonce)
	// verify signature
	err = types.VerifyEddsaSig(
		isLayer2Tx,
		api,
		hFunc,
		hashVal,
		tx.AccountsInfoBefore[0].AccountPk,
		tx.Signature,
	)
	if err != nil {
		log.Println("[VerifyTx] invalid signature:", err)
		return nil, pubData, roots, gasDeltas, err
	}

	// verify transactions
	for i := 0; i < types.PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	pubDataCheck := types.VerifyRegisterZNSTx(api, isRegisterZnsTx, tx.RegisterZnsTxInfo, tx.AccountsInfoBefore)
	pubData = SelectPubData(api, isRegisterZnsTx, pubDataCheck, pubData)
	pubDataCheck = types.VerifyDepositTx(api, isDepositTx, tx.DepositTxInfo, tx.AccountsInfoBefore)
	pubData = SelectPubData(api, isDepositTx, pubDataCheck, pubData)
	pubDataCheck = types.VerifyDepositNftTx(api, isDepositNftTx, tx.DepositNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore)
	pubData = SelectPubData(api, isDepositNftTx, pubDataCheck, pubData)
	pubDataCheck = types.VerifyTransferTx(api, isTransferTx, &tx.TransferTxInfo, tx.AccountsInfoBefore)
	pubData = SelectPubData(api, isTransferTx, pubDataCheck, pubData)
	pubDataCheck = types.VerifyCreateCollectionTx(api, isCreateCollectionTx, &tx.CreateCollectionTxInfo, tx.AccountsInfoBefore)
	pubData = SelectPubData(api, isCreateCollectionTx, pubDataCheck, pubData)
	pubDataCheck = types.VerifyWithdrawTx(api, isWithdrawTx, &tx.WithdrawTxInfo, tx.AccountsInfoBefore)
	pubData = SelectPubData(api, isWithdrawTx, pubDataCheck, pubData)
	pubDataCheck = types.VerifyMintNftTx(api, isMintNftTx, &tx.MintNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore)
	pubData = SelectPubData(api, isMintNftTx, pubDataCheck, pubData)
	pubDataCheck = types.VerifyTransferNftTx(api, isTransferNftTx, &tx.TransferNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore)
	pubData = SelectPubData(api, isTransferNftTx, pubDataCheck, pubData)
	hFunc.Reset()
	pubDataCheck, err = types.VerifyAtomicMatchTx(
		api, isAtomicMatchTx, &tx.AtomicMatchTxInfo, tx.AccountsInfoBefore, tx.NftBefore, blockCreatedAt,
		hFunc,
	)
	if err != nil {
		return nil, pubData, roots, gasDeltas, err
	}
	pubData = SelectPubData(api, isAtomicMatchTx, pubDataCheck, pubData)
	pubDataCheck = types.VerifyCancelOfferTx(api, isCancelOfferTx, &tx.CancelOfferTxInfo, tx.AccountsInfoBefore)
	pubData = SelectPubData(api, isCancelOfferTx, pubDataCheck, pubData)
	pubDataCheck = types.VerifyWithdrawNftTx(api, isWithdrawNftTx, &tx.WithdrawNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore)
	pubData = SelectPubData(api, isWithdrawNftTx, pubDataCheck, pubData)
	pubDataCheck = types.VerifyFullExitTx(api, isFullExitTx, tx.FullExitTxInfo, tx.AccountsInfoBefore)
	pubData = SelectPubData(api, isFullExitTx, pubDataCheck, pubData)
	pubDataCheck = types.VerifyFullExitNftTx(api, isFullExitNftTx, tx.FullExitNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore)
	pubData = SelectPubData(api, isFullExitNftTx, pubDataCheck, pubData)

	// verify timestamp
	types.IsVariableLessOrEqual(api, isLayer2Tx, blockCreatedAt, tx.ExpiredAt)

	// empty delta
	var (
		assetDeltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints
		nftDelta    NftDeltaConstraints
	)
	for i := 0; i < NbAccountsPerTx; i++ {
		assetDeltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: tx.NftBefore.CreatorAccountIndex,
		OwnerAccountIndex:   tx.NftBefore.OwnerAccountIndex,
		NftContentHash:      tx.NftBefore.NftContentHash,
		CreatorTreasuryRate: tx.NftBefore.CreatorTreasuryRate,
		CollectionId:        tx.NftBefore.CollectionId,
	}
	for i := 0; i < NbGasAssetsPerTx; i++ {
		gasDeltas[i] = EmptyGasDeltaConstraints(gasAssetIds[0])
	}

	// register
	accountDelta := GetAccountDeltaFromRegisterZNS(tx.RegisterZnsTxInfo)
	// deposit
	assetDeltasCheck := GetAssetDeltasFromDeposit(tx.DepositTxInfo)
	assetDeltas = SelectAssetDeltas(api, isDepositTx, assetDeltasCheck, assetDeltas)
	// generic transfer
	assetDeltasCheck, gasDeltasCheck := GetAssetDeltasFromTransfer(api, tx.TransferTxInfo)
	assetDeltas = SelectAssetDeltas(api, isTransferTx, assetDeltasCheck, assetDeltas)
	gasDeltas = SelectGasDeltas(api, isTransferTx, gasDeltasCheck, gasDeltas)
	// withdraw
	assetDeltasCheck, gasDeltasCheck = GetAssetDeltasFromWithdraw(api, tx.WithdrawTxInfo)
	assetDeltas = SelectAssetDeltas(api, isWithdrawTx, assetDeltasCheck, assetDeltas)
	gasDeltas = SelectGasDeltas(api, isWithdrawTx, gasDeltasCheck, gasDeltas)
	// deposit nft
	nftDeltaCheck := GetNftDeltaFromDepositNft(tx.DepositNftTxInfo)
	nftDelta = SelectNftDeltas(api, isDepositNftTx, nftDeltaCheck, nftDelta)
	// create collection
	assetDeltasCheck, gasDeltasCheck = GetAssetDeltasFromCreateCollection(api, tx.CreateCollectionTxInfo)
	assetDeltas = SelectAssetDeltas(api, isCreateCollectionTx, assetDeltasCheck, assetDeltas)
	gasDeltas = SelectGasDeltas(api, isCreateCollectionTx, gasDeltasCheck, gasDeltas)
	// mint nft
	assetDeltasCheck, nftDeltaCheck, gasDeltasCheck = GetAssetDeltasAndNftDeltaFromMintNft(api, tx.MintNftTxInfo)
	assetDeltas = SelectAssetDeltas(api, isMintNftTx, assetDeltasCheck, assetDeltas)
	nftDelta = SelectNftDeltas(api, isMintNftTx, nftDeltaCheck, nftDelta)
	gasDeltas = SelectGasDeltas(api, isMintNftTx, gasDeltasCheck, gasDeltas)
	// transfer nft
	assetDeltasCheck, nftDeltaCheck, gasDeltasCheck = GetAssetDeltasAndNftDeltaFromTransferNft(api, tx.TransferNftTxInfo, tx.NftBefore)
	assetDeltas = SelectAssetDeltas(api, isTransferNftTx, assetDeltasCheck, assetDeltas)
	nftDelta = SelectNftDeltas(api, isTransferNftTx, nftDeltaCheck, nftDelta)
	gasDeltas = SelectGasDeltas(api, isTransferNftTx, gasDeltasCheck, gasDeltas)
	// set nft price
	assetDeltasCheck, nftDeltaCheck, gasDeltasCheck = GetAssetDeltasAndNftDeltaFromAtomicMatch(api, isAtomicMatchTx, tx.AtomicMatchTxInfo, tx.AccountsInfoBefore, tx.NftBefore)
	assetDeltas = SelectAssetDeltas(api, isAtomicMatchTx, assetDeltasCheck, assetDeltas)
	nftDelta = SelectNftDeltas(api, isAtomicMatchTx, nftDeltaCheck, nftDelta)
	gasDeltas = SelectGasDeltas(api, isAtomicMatchTx, gasDeltasCheck, gasDeltas)
	// buy nft
	assetDeltasCheck, gasDeltasCheck = GetAssetDeltasFromCancelOffer(api, isCancelOfferTx, tx.CancelOfferTxInfo, tx.AccountsInfoBefore)
	assetDeltas = SelectAssetDeltas(api, isCancelOfferTx, assetDeltasCheck, assetDeltas)
	gasDeltas = SelectGasDeltas(api, isCancelOfferTx, gasDeltasCheck, gasDeltas)
	// withdraw nft
	assetDeltasCheck, nftDeltaCheck, gasDeltasCheck = GetAssetDeltasAndNftDeltaFromWithdrawNft(api, tx.WithdrawNftTxInfo)
	assetDeltas = SelectAssetDeltas(api, isWithdrawNftTx, assetDeltasCheck, assetDeltas)
	nftDelta = SelectNftDeltas(api, isWithdrawNftTx, nftDeltaCheck, nftDelta)
	gasDeltas = SelectGasDeltas(api, isWithdrawNftTx, gasDeltasCheck, gasDeltas)
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
	// update nonce
	AccountsInfoAfter[0].Nonce = api.Add(AccountsInfoAfter[0].Nonce, isLayer2Tx)
	AccountsInfoAfter[0].CollectionNonce = api.Add(AccountsInfoAfter[0].CollectionNonce, isCreateCollectionTx)
	// update nft
	NftAfter := UpdateNft(tx.NftBefore, nftDelta)

	// check old state root
	oldStateRoot := poseidon.Poseidon(api, tx.AccountRootBefore, tx.NftRootBefore)
	notEmptyTx := api.IsZero(isEmptyTx)
	types.IsVariableEqual(api, notEmptyTx, oldStateRoot, tx.StateRootBefore)

	newAccountRoot := tx.AccountRootBefore
	for i := 0; i < NbAccountsPerTx; i++ {
		var (
			NewAccountAssetsRoot = tx.AccountsInfoBefore[i].AssetRoot
		)
		// verify account asset node hash
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			api.AssertIsLessOrEqual(tx.AccountsInfoBefore[i].AssetsInfo[j].AssetId, LastAccountAssetId)
			assetMerkleHelper := AssetIdToMerkleHelper(api, tx.AccountsInfoBefore[i].AssetsInfo[j].AssetId)
			assetNodeHash := poseidon.Poseidon(api,
				tx.AccountsInfoBefore[i].AssetsInfo[j].Balance,
				tx.AccountsInfoBefore[i].AssetsInfo[j].OfferCanceledOrFinalized)
			// verify account asset merkle proof
			types.VerifyMerkleProof(
				api,
				notEmptyTx,
				NewAccountAssetsRoot,
				assetNodeHash,
				tx.MerkleProofsAccountAssetsBefore[i][j][:],
				assetMerkleHelper,
			)
			assetNodeHash = poseidon.Poseidon(api,
				AccountsInfoAfter[i].AssetsInfo[j].Balance,
				AccountsInfoAfter[i].AssetsInfo[j].OfferCanceledOrFinalized)

			// update merkle proof
			NewAccountAssetsRoot = types.UpdateMerkleProof(
				api, assetNodeHash, tx.MerkleProofsAccountAssetsBefore[i][j][:], assetMerkleHelper)
		}
		// verify account node hash
		api.AssertIsLessOrEqual(tx.AccountsInfoBefore[i].AccountIndex, LastAccountIndex)
		accountIndexMerkleHelper := AccountIndexToMerkleHelper(api, tx.AccountsInfoBefore[i].AccountIndex)
		accountNodeHash := poseidon.Poseidon(api,
			tx.AccountsInfoBefore[i].AccountNameHash,
			tx.AccountsInfoBefore[i].AccountPk.A.X,
			tx.AccountsInfoBefore[i].AccountPk.A.Y,
			tx.AccountsInfoBefore[i].Nonce,
			tx.AccountsInfoBefore[i].CollectionNonce,
			tx.AccountsInfoBefore[i].AssetRoot)
		// verify account merkle proof
		types.VerifyMerkleProof(
			api,
			notEmptyTx,
			newAccountRoot,
			accountNodeHash,
			tx.MerkleProofsAccountBefore[i][:],
			accountIndexMerkleHelper,
		)
		accountNodeHash = poseidon.Poseidon(api,
			AccountsInfoAfter[i].AccountNameHash,
			AccountsInfoAfter[i].AccountPk.A.X,
			AccountsInfoAfter[i].AccountPk.A.Y,
			AccountsInfoAfter[i].Nonce,
			AccountsInfoAfter[i].CollectionNonce,
			NewAccountAssetsRoot)
		// update merkle proof
		newAccountRoot = types.UpdateMerkleProof(api, accountNodeHash, tx.MerkleProofsAccountBefore[i][:], accountIndexMerkleHelper)
		oldRoots[0] = api.Select(isEmptyTx, oldRoots[0], newAccountRoot)
	}

	//// nft tree
	newNftRoot := tx.NftRootBefore
	api.AssertIsLessOrEqual(tx.NftBefore.NftIndex, LastNftIndex)
	nftIndexMerkleHelper := NftIndexToMerkleHelper(api, tx.NftBefore.NftIndex)
	nftNodeHash := poseidon.Poseidon(api, tx.NftBefore.CreatorAccountIndex,
		tx.NftBefore.OwnerAccountIndex,
		tx.NftBefore.NftContentHash,
		tx.NftBefore.CreatorTreasuryRate,
		tx.NftBefore.CollectionId)
	// verify account merkle proof
	types.VerifyMerkleProof(
		api,
		notEmptyTx,
		newNftRoot,
		nftNodeHash,
		tx.MerkleProofsNftBefore[:],
		nftIndexMerkleHelper,
	)
	nftNodeHash = poseidon.Poseidon(api,
		NftAfter.CreatorAccountIndex,
		NftAfter.OwnerAccountIndex,
		NftAfter.NftContentHash,
		NftAfter.CreatorTreasuryRate,
		NftAfter.CollectionId)
	log.Printf("NftBefore: CreatorAccountIndex=%v, OwnerAccountIndex=%v, NftContentHash=%v, CreatorTreasuryRate=%v, CollectionId=%v\n",
		tx.NftBefore.CreatorAccountIndex, tx.NftBefore.OwnerAccountIndex, tx.NftBefore.NftContentHash, tx.NftBefore.CreatorTreasuryRate, tx.NftBefore.CollectionId)
	log.Printf("NftAfter: CreatorAccountIndex=%v, OwnerAccountIndex=%v, NftContentHash=%v, CreatorTreasuryRate=%v, CollectionId=%v\n",
		NftAfter.CreatorAccountIndex, NftAfter.OwnerAccountIndex, NftAfter.NftContentHash, NftAfter.CreatorTreasuryRate, NftAfter.CollectionId)
	// update merkle proof
	newNftRoot = types.UpdateMerkleProof(api, nftNodeHash, tx.MerkleProofsNftBefore[:], nftIndexMerkleHelper)
	oldRoots[1] = api.Select(isEmptyTx, oldRoots[1], newNftRoot)

	// check state root
	newStateRoot := poseidon.Poseidon(api, newAccountRoot, newNftRoot)
	types.IsVariableEqual(api, notEmptyTx, newStateRoot, tx.StateRootAfter)

	roots[0] = oldRoots[0]
	roots[1] = oldRoots[1]
	return isOnChainOp, pubData, roots, gasDeltas, nil
}

func EmptyTx(stateRoot []byte) (oTx *Tx) {
	oTx = &Tx{
		TxType:            types.TxTypeEmptyTx,
		Nonce:             0,
		ExpiredAt:         0,
		Signature:         types.EmptySignature(),
		AccountRootBefore: make([]byte, 32),
		AccountsInfoBefore: [NbAccountsPerTx]*types.Account{
			types.EmptyAccount(0, make([]byte, 32)),
			types.EmptyAccount(0, make([]byte, 32)),
			types.EmptyAccount(0, make([]byte, 32)),
			types.EmptyAccount(0, make([]byte, 32)),
		},
		NftRootBefore:                   make([]byte, 32),
		NftBefore:                       types.EmptyNft(0),
		StateRootBefore:                 stateRoot,
		MerkleProofsAccountAssetsBefore: [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels][]byte{},
		MerkleProofsAccountBefore:       [NbAccountsPerTx][AccountMerkleLevels][]byte{},
		MerkleProofsNftBefore:           [NftMerkleLevels][]byte{},
		StateRootAfter:                  stateRoot,
	}
	for i := 0; i < NbAccountsPerTx; i++ {
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			for k := 0; k < AssetMerkleLevels; k++ {
				oTx.MerkleProofsAccountAssetsBefore[i][j][k] = make([]byte, 32)
			}
		}
		for j := 0; j < AccountMerkleLevels; j++ {
			oTx.MerkleProofsAccountBefore[i][j] = make([]byte, 32)
		}
	}
	for i := 0; i < NftMerkleLevels; i++ {
		oTx.MerkleProofsNftBefore[i] = make([]byte, 32)
	}
	return oTx
}

func SetTxWitness(oTx *Tx) (witness TxConstraints, err error) {
	witness.TxType = int64(oTx.TxType)
	witness.RegisterZnsTxInfo = types.EmptyRegisterZnsTxWitness()
	witness.DepositTxInfo = types.EmptyDepositTxWitness()
	witness.DepositNftTxInfo = types.EmptyDepositNftTxWitness()
	witness.TransferTxInfo = types.EmptyTransferTxWitness()
	witness.CreateCollectionTxInfo = types.EmptyCreateCollectionTxWitness()
	witness.MintNftTxInfo = types.EmptyMintNftTxWitness()
	witness.TransferNftTxInfo = types.EmptyTransferNftTxWitness()
	witness.AtomicMatchTxInfo = types.EmptyAtomicMatchTxWitness()
	witness.CancelOfferTxInfo = types.EmptyCancelOfferTxWitness()
	witness.WithdrawTxInfo = types.EmptyWithdrawTxWitness()
	witness.WithdrawNftTxInfo = types.EmptyWithdrawNftTxWitness()
	witness.FullExitTxInfo = types.EmptyFullExitTxWitness()
	witness.FullExitNftTxInfo = types.EmptyFullExitNftTxWitness()
	witness.Signature = EmptySignatureWitness()
	witness.Nonce = oTx.Nonce
	witness.ExpiredAt = oTx.ExpiredAt
	switch oTx.TxType {
	case types.TxTypeEmptyTx:
		break
	case types.TxTypeRegisterZns:
		witness.RegisterZnsTxInfo = types.SetRegisterZnsTxWitness(oTx.RegisterZnsTxInfo)
		break
	case types.TxTypeDeposit:
		witness.DepositTxInfo = types.SetDepositTxWitness(oTx.DepositTxInfo)
		break
	case types.TxTypeDepositNft:
		witness.DepositNftTxInfo = types.SetDepositNftTxWitness(oTx.DepositNftTxInfo)
		break
	case types.TxTypeTransfer:
		witness.TransferTxInfo = types.SetTransferTxWitness(oTx.TransferTxInfo)
		witness.Signature.R.X = oTx.Signature.R.X
		witness.Signature.R.Y = oTx.Signature.R.Y
		witness.Signature.S = oTx.Signature.S[:]
		break
	case types.TxTypeWithdraw:
		witness.WithdrawTxInfo = types.SetWithdrawTxWitness(oTx.WithdrawTxInfo)
		witness.Signature.R.X = oTx.Signature.R.X
		witness.Signature.R.Y = oTx.Signature.R.Y
		witness.Signature.S = oTx.Signature.S[:]
		break
	case types.TxTypeCreateCollection:
		witness.CreateCollectionTxInfo = types.SetCreateCollectionTxWitness(oTx.CreateCollectionTxInfo)
		witness.Signature.R.X = oTx.Signature.R.X
		witness.Signature.R.Y = oTx.Signature.R.Y
		witness.Signature.S = oTx.Signature.S[:]
		break
	case types.TxTypeMintNft:
		witness.MintNftTxInfo = types.SetMintNftTxWitness(oTx.MintNftTxInfo)
		witness.Signature.R.X = oTx.Signature.R.X
		witness.Signature.R.Y = oTx.Signature.R.Y
		witness.Signature.S = oTx.Signature.S[:]
		break
	case types.TxTypeTransferNft:
		witness.TransferNftTxInfo = types.SetTransferNftTxWitness(oTx.TransferNftTxInfo)
		witness.Signature.R.X = oTx.Signature.R.X
		witness.Signature.R.Y = oTx.Signature.R.Y
		witness.Signature.S = oTx.Signature.S[:]
		break
	case types.TxTypeAtomicMatch:
		witness.AtomicMatchTxInfo = types.SetAtomicMatchTxWitness(oTx.AtomicMatchTxInfo)
		witness.Signature.R.X = oTx.Signature.R.X
		witness.Signature.R.Y = oTx.Signature.R.Y
		witness.Signature.S = oTx.Signature.S[:]
		break
	case types.TxTypeCancelOffer:
		witness.CancelOfferTxInfo = types.SetCancelOfferTxWitness(oTx.CancelOfferTxInfo)
		witness.Signature.R.X = oTx.Signature.R.X
		witness.Signature.R.Y = oTx.Signature.R.Y
		witness.Signature.S = oTx.Signature.S[:]
		break
	case types.TxTypeWithdrawNft:
		witness.WithdrawNftTxInfo = types.SetWithdrawNftTxWitness(oTx.WithdrawNftTxInfo)
		witness.Signature.R.X = oTx.Signature.R.X
		witness.Signature.R.Y = oTx.Signature.R.Y
		witness.Signature.S = oTx.Signature.S[:]
		break
	case types.TxTypeFullExit:
		witness.FullExitTxInfo = types.SetFullExitTxWitness(oTx.FullExitTxInfo)
		break
	case types.TxTypeFullExitNft:
		witness.FullExitNftTxInfo = types.SetFullExitNftTxWitness(oTx.FullExitNftTxInfo)
		break
	default:
		log.Println("[SetTxWitness] invalid oTx type")
		return witness, errors.New("[SetTxWitness] invalid oTx type")
	}
	// set common account & merkle parts
	// account root before
	witness.AccountRootBefore = oTx.AccountRootBefore
	witness.NftRootBefore = oTx.NftRootBefore
	witness.StateRootBefore = oTx.StateRootBefore
	witness.StateRootAfter = oTx.StateRootAfter

	// before
	witness.NftBefore, err = types.SetNftWitness(oTx.NftBefore)
	if err != nil {
		log.Println("[SetTxWitness] unable to set nft witness:", err.Error())
		return witness, err
	}

	// account before info, size is 4
	for i := 0; i < NbAccountsPerTx; i++ {
		// accounts info before
		witness.AccountsInfoBefore[i], err = types.SetAccountWitness(oTx.AccountsInfoBefore[i])
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
	for i := 0; i < NftMerkleLevels; i++ {
		// nft assets before
		witness.MerkleProofsNftBefore[i] = oTx.MerkleProofsNftBefore[i]
	}
	return witness, nil
}
