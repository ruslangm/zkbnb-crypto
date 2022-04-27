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

package zecrey_legend

import (
	"bytes"
	"encoding/json"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/ethereum/go-ethereum/common"
	"hash"
	"log"
	"math/big"
)

type WithdrawNftSegmentFormat struct {
	AccountIndex      int64  `json:"account_index"`
	NftIndex          int64  `json:"nft_index"`
	NftContentHash    string `json:"nft_content_hash"`
	ToAddress         string `json:"to_address"`
	ProxyAddress      string `json:"proxy_address"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount int64  `json:"gas_fee_asset_amount"`
	Nonce             int64  `json:"nonce"`
}

func ConstructWithdrawNftTxInfo(sk *PrivateKey, segmentStr string) (txInfo *WithdrawNftTxInfo, err error) {
	var segmentFormat *WithdrawNftSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructWithdrawNftTxInfo] err info:", err)
		return nil, err
	}
	txInfo = &WithdrawNftTxInfo{
		AccountIndex:      segmentFormat.AccountIndex,
		NftIndex:          segmentFormat.NftIndex,
		NftContentHash:    segmentFormat.NftContentHash,
		ToAddress:         segmentFormat.ToAddress,
		ProxyAddress:      segmentFormat.ProxyAddress,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: segmentFormat.GasFeeAssetAmount,
		Nonce:             segmentFormat.Nonce,
		Sig:               nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash := ComputeWithdrawNftMsgHash(txInfo, hFunc)
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructWithdrawNftTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type WithdrawNftTxInfo struct {
	AccountIndex int64
	// TODO not sure if we need to add it here
	AccountNameHash   string
	NftIndex          int64
	NftContentHash    string
	NftL1Address      string
	NftL1TokenId      *big.Int
	Amount            int64
	ToAddress         string
	ProxyAddress      string
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
	Nonce             int64
	Sig               []byte
}

func ComputeWithdrawNftMsgHash(txInfo *WithdrawNftTxInfo, hFunc hash.Hash) (msgHash []byte) {
	/*
		hFunc.Write(
			tx.AccountIndex,
			tx.NftIndex,
			tx.ToAddress,
			tx.ProxyAddress,
			tx.GasAccountIndex,
			tx.GasFeeAssetId,
			tx.GasFeeAssetAmount,
		)
		hFunc.Write(nonce)
	*/
	hFunc.Reset()
	var buf bytes.Buffer
	writeInt64IntoBuf(&buf, txInfo.AccountIndex)
	writeInt64IntoBuf(&buf, txInfo.NftIndex)
	buf.Write(common.FromHex(txInfo.NftContentHash))
	buf.Write(PaddingStringToBytes32(txInfo.ToAddress))
	buf.Write(PaddingStringToBytes32(txInfo.ProxyAddress))
	writeInt64IntoBuf(&buf, txInfo.GasAccountIndex)
	writeInt64IntoBuf(&buf, txInfo.GasFeeAssetId)
	writeInt64IntoBuf(&buf, txInfo.GasFeeAssetAmount)
	writeInt64IntoBuf(&buf, txInfo.Nonce)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}
