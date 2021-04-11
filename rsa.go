package crypto_rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
)

// GenerateKey 生成私钥
func GenerateKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// PubEncToBase64 加密成base64
func PubEncToBase64(pubkey, data string) (string, error) {
	rsaPub, err := byte2PubKey([]byte(pubkey))
	if err != nil {
		return "", err
	}
	ciphertext, err := PubkeyEnc(rsaPub, []byte(data))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// PrvDecForBase64 base64密文解密
func PrvDecForBase64(prvkey, base64Ciphertext string) (string, error) {
	rsaPrv, err := byte2PriKey([]byte(prvkey))
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(base64Ciphertext)
	if err != nil {
		return "", err
	}

	data, err := PrvkeyDec(rsaPrv, []byte(ciphertext))
	if err != nil {
		return "", err
	}
	return string(data), err
}

// PubkeyEnc 公钥加密
func PubkeyEnc(pubkey *rsa.PublicKey, data []byte) ([]byte, error) {
	output := bytes.NewBuffer(nil)
	err := pubKeyIO(pubkey, bytes.NewReader(data), output, true)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(output)
}

// PrvkeyDec 私钥解密
func PrvkeyDec(prvkey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	output := bytes.NewBuffer(nil)
	err := priKeyIO(prvkey, bytes.NewReader(ciphertext), output, false)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(output)
}

// PrivKeyEnc 私钥加密
func PrivKeyEnc(prvkey *rsa.PrivateKey, data []byte) ([]byte, error) {
	output := bytes.NewBuffer(nil)
	err := priKeyIO(prvkey, bytes.NewReader(data), output, true)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(output)
}

// PubkeyDec 公钥解密
func PubkeyDec(pubkey *rsa.PublicKey, ciphertext []byte) ([]byte, error) {
	output := bytes.NewBuffer(nil)
	err := pubKeyIO(pubkey, bytes.NewReader(ciphertext), output, false)
	if err != nil {
		return []byte(""), err
	}
	return ioutil.ReadAll(output)
}

// Sign SHA256签名
func Sign(prvkey, data string) (string, error) {
	rsaPrv, err := byte2PriKey([]byte(prvkey))
	if err != nil {
		return "", err
	}

	sha256Hash := sha256.New()
	s_data := []byte(data)
	sha256Hash.Write(s_data)
	hashed := sha256Hash.Sum(nil)
	signByte, err := rsa.SignPKCS1v15(rand.Reader, rsaPrv, crypto.SHA256, hashed)
	return base64.StdEncoding.EncodeToString(signByte), err
}

// VerifySign 验签
func VerifySign(pubkey, data string, signData string) error {
	rsaPub, err := byte2PubKey([]byte(pubkey))
	if err != nil {
		return err
	}

	sign, err := base64.StdEncoding.DecodeString(signData)
	if err != nil {
		return err
	}
	hash := sha256.New()
	hash.Write([]byte(data))
	return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash.Sum(nil), sign)
}