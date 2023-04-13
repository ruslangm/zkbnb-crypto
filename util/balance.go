package util

import (
	"errors"
	"fmt"
	"log"
	"math/big"
	"strconv"

	"github.com/bnb-chain/zkbnb-crypto/ffmath"
)

var (
	// 2^35 - 1
	PackedAmountMaxMantissa = big.NewInt(34359738367)
	// 2^11 - 1
	PackedFeeMaxMantissa  = big.NewInt(2047)
	PackedAmountMaxAmount = ffmath.Multiply(big.NewInt(34359738367), new(big.Int).Exp(big.NewInt(10), big.NewInt(31), nil))
	PackedFeeMaxAmount    = ffmath.Multiply(big.NewInt(2047), new(big.Int).Exp(big.NewInt(10), big.NewInt(31), nil))
	ZeroBigInt            = big.NewInt(0)
)

/*
ToPackedAmount: convert big int to 40 bit, 5 bits for 10^x, 35 bits for a * 10^x
*/
func ToPackedAmount(amount *big.Int) (res int64, err error) {
	if amount.Cmp(ZeroBigInt) < 0 || amount.Cmp(PackedAmountMaxAmount) > 0 {
		log.Println("[ToPackedAmount] invalid amount")
		return -1, errors.New("[ToPackedAmount] invalid amount")
	}
	oAmount := new(big.Int).Set(amount)
	exponent := int64(0)
	for oAmount.Cmp(PackedAmountMaxMantissa) > 0 {
		oAmount = ffmath.Div(oAmount, big.NewInt(10))
		exponent++
	}
	exponentBits := strconv.FormatInt(exponent, 2)
	for len(exponentBits) < 5 {
		exponentBits = "0" + exponentBits
	}
	mantissaBits := strconv.FormatInt(oAmount.Int64(), 2)
	packedAmountBits := mantissaBits + exponentBits
	packedAmount, err := strconv.ParseInt(packedAmountBits, 2, 41)
	if err != nil {
		log.Println("[ToPackedAmount] unable to convert to packed amount", err.Error())
		return -1, err
	}
	return packedAmount, nil
}

func CleanPackedAmount(amount *big.Int) (nAmount *big.Int, err error) {
	if amount.Cmp(ZeroBigInt) < 0 || amount.Cmp(PackedAmountMaxAmount) > 0 {
		log.Println("[ToPackedAmount] invalid amount")
		return nil, errors.New("[ToPackedAmount] invalid amount")
	}
	oAmount := new(big.Int).Set(amount)
	exponent := int64(0)
	for oAmount.Cmp(PackedAmountMaxMantissa) > 0 {
		oAmount = ffmath.Div(oAmount, big.NewInt(10))
		exponent++
	}
	nAmount = ffmath.Multiply(oAmount, new(big.Int).Exp(big.NewInt(10), big.NewInt(exponent), nil))
	return nAmount, nil
}

/*
ToPackedFee: convert big int to 16 bit, 5 bits for 10^x, 11 bits for a * 10^x
*/
func ToPackedFee(amount *big.Int) (res int64, err error) {
	if amount.Cmp(ZeroBigInt) < 0 || amount.Cmp(PackedFeeMaxAmount) > 0 {
		log.Println("[ToPackedFee] invalid amount")
		return 0, errors.New("[ToPackedFee] invalid amount")
	}
	oAmount := new(big.Int).Set(amount)
	exponent := int64(0)
	for oAmount.Cmp(PackedFeeMaxMantissa) > 0 {
		oAmount = ffmath.Div(oAmount, big.NewInt(10))
		exponent++
	}
	exponentBits := strconv.FormatInt(exponent, 2)
	for len(exponentBits) < 5 {
		exponentBits = "0" + exponentBits
	}
	mantissaBits := strconv.FormatInt(oAmount.Int64(), 2)
	packedFeeBits := mantissaBits + exponentBits
	packedFee, err := strconv.ParseInt(packedFeeBits, 2, 17)
	if err != nil {
		log.Println("[ToPackedFee] unable to convert to packed fee", err.Error())
		return 0, err
	}
	return packedFee, nil
}

func CleanPackedFee(amount *big.Int) (nAmount *big.Int, err error) {
	if amount.Cmp(ZeroBigInt) < 0 || amount.Cmp(PackedFeeMaxAmount) > 0 {
		log.Println("[ToPackedFee] invalid amount")
		return nil, errors.New("[ToPackedFee] invalid amount")
	}
	oAmount := new(big.Int).Set(amount)
	exponent := int64(0)
	for oAmount.Cmp(PackedFeeMaxMantissa) > 0 {
		oAmount = ffmath.Div(oAmount, big.NewInt(10))
		exponent++
	}
	nAmount = ffmath.Multiply(oAmount, new(big.Int).Exp(big.NewInt(10), big.NewInt(exponent), nil))
	return nAmount, nil
}

func UnpackAmount(packedAmount *big.Int) (nAmount *big.Int, err error) {
	if packedAmount.Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(0), nil
	}
	amountBits := fmt.Sprintf("%b", packedAmount)
	mantissa, success := new(big.Int).SetString(amountBits[:len(amountBits)-5], 2)
	if !success {
		return nil, fmt.Errorf("[UnpackAmount] failed to convert to bigint，%s", packedAmount.String())
	}
	exponentBigInt, success := new(big.Int).SetString(amountBits[len(amountBits)-5:], 2)
	if !success {
		return nil, fmt.Errorf("[UnpackAmount] failed to convert to bigint，%s", packedAmount.String())
	}
	exponent := exponentBigInt.Int64()
	for i := 0; i < 32; i++ {
		isRemain := exponent != 0
		if isRemain {
			mantissa = ffmath.Multiply(mantissa, new(big.Int).SetInt64(10))
			exponent = exponent - 1
		}
	}
	return mantissa, nil
}

func UnpackFee(packedFee *big.Int) (nAmount *big.Int, err error) {
	return UnpackAmount(packedFee)
}
