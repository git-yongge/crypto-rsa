package crypto_rsa

import (
	"encoding/hex"
	"io/ioutil"
	"testing"
)

func TestGenerateKey(t *testing.T) {

	prv, _ := GenerateKey(1024)
	ciphertext, err := PubkeyEnc(&prv.PublicKey, []byte("123456"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("ciphertext: ", hex.EncodeToString(ciphertext))

	data, err := PrvkeyDec(prv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("data: ", string(data))
}

func TestPubEncToBase64(t *testing.T) {

	stream, err := ioutil.ReadFile("testkey/pub.key")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("pubkey: ", string(stream))

	base64, err := PubEncToBase64(string(stream), "123")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("base64: ", base64)

	prvSteam, err := ioutil.ReadFile("testkey/pri.key")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("prvkey: ", string(prvSteam))

	data, err := PrvDecForBase64(string(prvSteam), base64)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("data: ", data)
}

func TestSign(t *testing.T) {
	prvSteam, err := ioutil.ReadFile("testkey/pri.key")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("prvkey: ", string(prvSteam))

	sign, err := Sign(string(prvSteam), "123456")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("sign: ", sign)

	stream, err := ioutil.ReadFile("testkey/pub.key")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("pubkey: ", string(stream))
	err = VerifySign(string(stream), "123456", sign)
	t.Log("err: ", err)
}