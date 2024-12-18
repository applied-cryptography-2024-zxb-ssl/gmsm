package main

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/smx509"
)

func main() {
	fmt.Println(" ===========  SM2 Demo ===========")
	SM2_test()

	fmt.Println("\n\n ===========  SM3 Demo ===========")
	SM3_test()

	fmt.Println("\n\n ===========  SM4 Demo ===========")
	SM4_test()
}

func save_PrivateKey_To_File(priv_key *sm2.PrivateKey, filePath string) error {
	fmt.Printf("%T", priv_key)
	privKeyBytes, err := smx509.MarshalPKCS8PrivateKey(priv_key)
	if err != nil {
		return fmt.Errorf("err in get bytes of priv_key: %w", err)

	}

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	err = os.WriteFile(filePath, privKeyPEM, 0644)
	if err != nil {
		return fmt.Errorf("err in write priv_key into pem file: %w", err)
	}
	return nil
}

func save_PublicKey_To_File(priv_key *sm2.PrivateKey, filePath string) error {
	pubKey := priv_key.PublicKey
	ecdh_key, err := sm2.PublicKeyToECDH(&pubKey)
	if err != nil {
		return fmt.Errorf("error in turn pub key to ecdh: %w", err)
	}

	pubBytes, err := smx509.MarshalPKIXPublicKey(ecdh_key)

	if err != nil {
		return fmt.Errorf("err in get bytes of pub_key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	pemData := pem.EncodeToMemory(pemBlock)

	err = os.WriteFile(filePath, pemData, 0644)

	if err != nil {
		return fmt.Errorf("err in write pub_key into pem file: %w", err)
	}
	return nil

}

func ReadPEMFileAsBytes(filePath string) ([]byte, error) {
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("无法读取文件 %s: %w", filePath, err)
	}

	block, _ := pem.Decode(fileContent)
	if block == nil {
		return nil, fmt.Errorf("无效的 PEM 文件内容")
	}

	return block.Bytes, nil
}

// <Requirement(import)>: "github.com/emmansun/gmsm/sm2"
// Sign and verify etc. could be found from the doc
func SM2_test() {
	// [1] Input: plain_text to be encrypted.
	plain_text := "你所学的“应用随机过程(60420094-0)”课程中,作业“第十三次作业”还有1天将截止提交。截止时间为:2024-12-17 23:59。"

	// [2] <Func> Gnerate key pair , just like RSA.

	// <Requirement(import)>: "crypto/rand"
	// <Input>: 	rand.Reader
	// <Output>: 	class *PrivateKey <&&> class error; guarantee one is nil
	//				class PrivateKey extends ecdsa.PrivateKey("crypto/ecdsa")
	priv_ori, _ := sm2.GenerateKey(rand.Reader)

	// [2-1] Use Above function to save private key to a given file
	err := save_PrivateKey_To_File(priv_ori, "./hello_priv.pem")
	if err != nil {
		fmt.Println(err)
		return
	}

	// [2-2] Use Above function to save public key to a given file
	err = save_PublicKey_To_File(priv_ori, "hello_pub.pem")
	if err != nil {
		fmt.Println(err)
		return
	}

	// [2-3] Retrieve public key
	pub_pem, err := ReadPEMFileAsBytes("./hello_pub.pem")
	if err != nil {
		fmt.Println(err)
		return
	}

	ori_pub, err := smx509.ParsePKIXPublicKey(pub_pem)
	if err != nil {
		fmt.Println(err)
		return
	}

	pub_key, ok := ori_pub.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("Err in retrieve pub key")
		return
	}

	// [2-4] Retrieve priv key
	priv_pem, err := ReadPEMFileAsBytes("./hello_priv.pem")
	if err != nil {
		fmt.Println(err)
		return
	}

	ori_priv, err := smx509.ParsePKCS8PrivateKey(priv_pem)
	if err != nil {
		fmt.Println(err)
		return
	}

	priv, ok := ori_priv.(*sm2.PrivateKey)
	if !ok {
		fmt.Println("Err in retrieve pub key")
		return
	}
	priv.PublicKey = *pub_key

	// [3] <Func> Use the pre-generated priv to [encrypt] the byte stream
	// <Input>:		rand.Reader, *priv.PublicKey
	// <Input>:		byte stream(or use []byte(string) as below, turn string to byte stream)
	// <Input>:		class sm2.NewPlainEncrypterOpts [TODO]: Optional - C1C3C2 || C1C2C3 || ASN.1
	// <Output>:	byte stream cipher-text

	ciphertext, _ := sm2.Encrypt(rand.Reader, &priv.PublicKey, []byte(plain_text), sm2.NewPlainEncrypterOpts(sm2.MarshalUncompressed, sm2.C1C2C3))
	fmt.Printf("type of cipher-text: %T\n", ciphertext)

	// [4] <Func> Use the pre-generated priv to [decrypt] the byte stream
	// <Owner> class PrivateKey
	// <Input> Just like Encrypt, except the PublicKey
	// <Output>:	byte stream plain-text retrieved
	re_plain_text, _ := priv.Decrypt(rand.Reader, ciphertext, sm2.NewPlainDecrypterOpts(sm2.C1C2C3))

	fmt.Printf("type of rtrieve plain-text: %T\n", re_plain_text)
	fmt.Println("[retrieve plain text]")
	fmt.Println(string(re_plain_text))
	fmt.Println("---------------------------------")

	if plain_text != string(re_plain_text) {
		fmt.Println("Err")
	} else {
		fmt.Println("Eq in C1C2C3 , PASS")
	}

	ciphertext, _ = sm2.Encrypt(rand.Reader, &priv.PublicKey, []byte(plain_text), sm2.NewPlainEncrypterOpts(sm2.MarshalUncompressed, sm2.C1C3C2))
	re_plain_text, _ = priv.Decrypt(rand.Reader, ciphertext, sm2.NewPlainDecrypterOpts(sm2.C1C3C2))
	if plain_text != string(re_plain_text) {
		fmt.Println("Err")
	} else {
		fmt.Println("Eq in C1C3C2 , PASS")
	}

	ciphertext, _ = sm2.Encrypt(rand.Reader, &priv.PublicKey, []byte(plain_text), sm2.ASN1EncrypterOpts)
	re_plain_text, _ = priv.Decrypt(rand.Reader, ciphertext, sm2.ASN1EncrypterOpts)
	if plain_text != string(re_plain_text) {
		fmt.Println("Err")
	} else {
		fmt.Println("Eq in ASN.1 , PASS")
	}

	ciphertext, _ = sm2.Encrypt(rand.Reader, &priv.PublicKey, []byte(plain_text), sm2.NewPlainEncrypterOpts(sm2.MarshalUncompressed, sm2.C1C2C3))
	re_plain_text, _ = priv.Decrypt(rand.Reader, ciphertext, sm2.NewPlainDecrypterOpts(sm2.C1C3C2))
	if plain_text != string(re_plain_text) {
		fmt.Println("[Could ^^^ NOT ^^^ use different options in encrypt and decrypt]")
	} else {
		fmt.Println("Two different encoding leads to the same reasults?")
	}

}

// <Requirement(import)>: "github.com/emmansun/gmsm/sm3"
func SM3_test() {
	// [1] Use sm3.Sum to caculate the 'hash' of the given byte stream, or turn the string to the stream
	res_1 := sm3.Sum([]byte("你所学的“应用随机过程(60420094-0)”课程中,作业“第十三次作业”还有1天将截止提交。截止时间为:2024-12-17 23:59。"))
	fmt.Printf("The type of res of 1st method is: %T\n", res_1)

	// [2] Create an instance of sm3 class, then could put text to it "step by step", i.e. incremetally change string and get its hash
	// 		(1) Create a new sm3 instance
	calculator := sm3.New()
	//		(2) For <string> <Requirement(import)>: io, Use io.WriteString to the instance
	io.WriteString(calculator, "你所学的“应用随机过程(60420094-0)”课程中,")
	res_2_mid := calculator.Sum(nil)

	//		(3) The byte stream in caculator could be changed, and get 'hash' when you want
	fmt.Printf("The type of res of 2nd method is: %T\n", res_2_mid)

	//		(4) For <byte stream>, Use instance.Write() method
	calculator.Write([]byte("作业“第十三次作业”还有1天将截止提交。截止时间为:2024-12-17 23:59。"))

	res_2 := calculator.Sum(nil)
	if string(res_1[:]) == string(res_2) {
		fmt.Println("Pass, two methods are equal")
	}

	// [Note]: TWO methods return different type. 1st returns byte[32], and 2nd returns byte[]
}

// [Note]:
//
//	Below is the same as ./sm4/exmaple_test line:87-114 Example_encryptGCM and line 116-145 decrypt_GCM
//	SM4 and AES could be seen as the combination of the cipherblock algorithm.
//	and it is needed to combime with the 'group' algorithm
//	See utls/cipher_suites.go, AES is always combined with CBC/GCM, also supported in gmsm.
//

// I found GCM was selected, so I use GCM
// <Requirement(import)>: "github.com/emmansun/gmsm/sm4"
func SM4_test() {
	// [1] key is a <byte stream>, and in SM4 it is 128-bit, which can be generated by a random number generator.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")

	// [2] Input: plain_text to be encrypted.
	plain_text := []byte("你所学的“应用随机过程(60420094-0)”课程中,作业“第十三次作业”还有1天将截止提交。截止时间为:2024-12-17 23:59。")

	// [3] creates and returns a new cipher.Block.
	// block is the cipher.block, which is defined in the standard of go language, it is an I/O (分组加密器)
	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("block type is %T\n", block)

	// [4] Use a CTR(counter) to avoid repeat cipher-text(?)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	// [5] Define an AEAD（Authenticated Encryption with Associated Data）
	sm4gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// [6] AEAD has Seal and Open method, use seal to encrypt
	cipher_text := sm4gcm.Seal(nil, nonce, plain_text, nil)

	// [7] 	To decrypt, need key(the same as before)
	// 		nounce(must be the same as the before one in generate)
	block_2, err := sm4.NewCipher(key)

	if err != nil {
		panic(err.Error())
	}

	// [5] Define an AEAD（Authenticated Encryption with Associated Data）
	sm4gcm_2, err := cipher.NewGCM(block_2)
	if err != nil {
		panic(err.Error())
	}

	// [6] Decrypt use the Open method in AEAD
	re_plain_text, err := sm4gcm_2.Open(nil, nonce, cipher_text, nil)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("type of rtrieve plain-text: %T\n", re_plain_text)
	fmt.Println("[retrieve plain text]")
	fmt.Println(string(re_plain_text))
	fmt.Println("---------------------------------")
	if string(plain_text) != string(re_plain_text) {
		fmt.Println("Err")
	} else {
		fmt.Println("Eq in GCM , PASS")
	}
}
