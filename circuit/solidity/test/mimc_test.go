package mimc

import (
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
)

func TestPreimage(t *testing.T) {
	preImage := "16130099170765464552823636852555369511329944820189892919423002775646948828469"
	mimcHash := "8674594860895598770446879254410848023850744751986836044725552747672873438975"

	var mimcCircuit Circuit

	// 1. Convert a circuit definition into an arithmetic representation for proof generation and verification.
	cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &mimcCircuit)

	// 2. Setup
	pk, vk, err := groth16.Setup(cs)

	// 3. Create private witness
	witness, err := frontend.NewWitness(&Circuit{Hash: mimcHash, PreImage: preImage}, ecc.BN254)

	// 4. Create public witness
	pWitness, err := frontend.NewWitness(&Circuit{Hash: mimcHash}, ecc.BN254, frontend.PublicOnly())

	// 5. Proof creation
	proof, err := groth16.Prove(cs, pk, witness)

	// 6. Proof verification
	err = groth16.Verify(proof, vk, pWitness)

	// 7. Write verifier solidity smart contract into a file
	f, err := os.Create("MimcVerifier.sol")
	err = vk.ExportSolidity(f)

	if err != nil {
		panic(err)
	}
}
