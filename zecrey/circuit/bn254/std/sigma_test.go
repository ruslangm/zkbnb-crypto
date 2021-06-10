package std

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"math/big"
	"testing"
)

func TestSchnorrProof(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness SchnorrProofCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	// generate witness data
	witness.G.X.Assign("9671717474070082183213120605117400219616337014328744928644933853176787189663")
	witness.G.Y.Assign("16950150798460657717958625567821834550301663161624707787222815936182638968203")
	witness.A.X.Assign("1805826214268140062109789454888545380426720994127895546120718277293486808528")
	witness.A.Y.Assign("1992424522915255363820795818666870149715470888958691910097484002003697548446")
	witness.Pk.X.Assign("20062244510347148272446781100879286480638585431533684331180269070589632792928")
	witness.Pk.Y.Assign("1270552922097600254906946530389401056931473037205902458907582592439177824778")
	z, _ := new(big.Int).SetString("56457306562257122565246154685424300206626160564298072980723270873916373234", 10)
	c, _ := new(big.Int).SetString("12570305820242045194614329830538401576680239494304591206526835130365207477516", 10)
	witness.Z.Assign(z)
	witness.C.Assign(c)

	assert.SolvingSucceeded(r1cs, &witness)

}

func TestOwnershipCircuit(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness OwnershipCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	/**
	G Point
	YDivT, A_YDivT, H, T,
	A_T, Pk, A_pk, CLprimeInv,
	TCRprimeInv, A_TCRprimeInv Point
	C                                               Variable
	Z_rstarSubrbar, Z_rbar, Z_bprime, Z_sk, Z_skInv Variable
	*/
	witness.G.X.Assign("9671717474070082183213120605117400219616337014328744928644933853176787189663")
	witness.G.Y.Assign("16950150798460657717958625567821834550301663161624707787222815936182638968203")
	// Y/T
	witness.YDivT.X.Assign("18489365844613966889162359804171601626208916117359124828574848125862479242348")
	witness.YDivT.Y.Assign("20675866704069102908818603727333826796582229729222327923598761040117356481071")
	// A_Y / T
	witness.A_YDivT.X.Assign("12880651902657644835221622074138338028921981671918651840236840655341295836272")
	witness.A_YDivT.Y.Assign("13123994615784597566607819591675199791858661480963579954987236259776042848792")
	// H
	witness.H.X.Assign("19843132008705182383524593512377323181208938069977784352990768375941636129043")
	witness.H.Y.Assign("1424962496956403694866513262744390851176749772810717397211030275710635902220")
	// T
	witness.T.X.Assign("6359455892390808172880876989725514807434536071465339271291561810901355670640")
	witness.T.Y.Assign("11801909855539297695396853512908154643879562992161792902386914823488866144474")
	// A_T
	witness.A_T.X.Assign("6982213579123158543334108309963120007707362191951589503243857896383330864348")
	witness.A_T.Y.Assign("6780421154673572676977312386888384948187496470314802727956885219672756885880")
	// Pk
	witness.Pk.X.Assign("13142384266011523672668872912129647363879116558552932029285631874845590901678")
	witness.Pk.Y.Assign("1379136652626711719512670974315508537824055127654411976494473213331979711860")
	// A_pk
	witness.A_pk.X.Assign("6105898836878134680926723773770512660720007950422817869994956277242386126095")
	witness.A_pk.Y.Assign("16312145713215062655944991123749243541596715933481835356182606264200833306493")
	// C_L^{-1}'
	witness.CLprimeInv.X.Assign("12253359875697454200416773491113949250526801042978955145722995755248547859512")
	witness.CLprimeInv.Y.Assign("10630292837545985663376504017761626606790843007283943317310505592652878567895")
	// T/C_R'
	witness.TCRprimeInv.X.Assign("6015121858496252251231501190065500809740609315255499315263705263138746424452")
	witness.TCRprimeInv.Y.Assign("10544402093529590167438350696024599537357340545066406425118877945852438733106")
	// A_T/C_R'
	witness.A_TCRprimeInv.X.Assign("15643098515742688497351030262874935823035194685201288791914707845262700551326")
	witness.A_TCRprimeInv.Y.Assign("6678914624897497804227030032096499560143570890174108071299344080391541181772")
	c, _ := new(big.Int).SetString("11892137101595333503558200865754023767468061988440101834526030800076805887915", 10)
	z_rstarSubrbar, _ := new(big.Int).SetString("1087114553809167762577358494546638882967518574595929124628688288311021612964", 10)
	z_rbar, _ := new(big.Int).SetString("2651075508803472280573043358544629325714962226288733553307252073082585112323", 10)
	z_bprime, _ := new(big.Int).SetString("2515942587245290551877815469971759213782196467610612713784988153328553256708", 10)
	z_sk, _ := new(big.Int).SetString("1160564582402997358221180661640606025802688638967489769358801365026769583711", 10)
	z_skInv, _ := new(big.Int).SetString("662861981625711240035892241607544252033209248516165727545278288581146481182", 10)
	witness.C.Assign(c)
	witness.Z_rstarSubrbar.Assign(z_rstarSubrbar)
	witness.Z_rbar.Assign(z_rbar)
	witness.Z_bprime.Assign(z_bprime)
	witness.Z_sk.Assign(z_sk)
	witness.Z_skInv.Assign(z_skInv)
	fmt.Println("constraints:", r1cs.GetNbConstraints())

	assert.SolvingSucceeded(r1cs, &witness)

}
