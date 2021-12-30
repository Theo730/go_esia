package main

import (
    "fmt"
    "crypto/x509"
    "encoding/base64"
    "errors"
    "math/rand"
    crand	"crypto/rand"
    "time"
    "github.com/Theo730/pkcs7"
    "github.com/Theo730/gogost/gost3410"
    "github.com/Theo730/gogost/gost34112012256"
)

type OutURL struct{
    ClientSecret	string		`json:"client_secret"`  // подписанная строка
    State		string		`json:"state"`     // state клиента (уникальный номер сессии клиента)
    Data		string		`json:"data"`     // data
}

type esia struct{
    ClientID		string
    Scopes		string
    Interface		string
    Port		int
    Key 		*gost3410.PrivateKey
    Cert		*x509.Certificate
}

func (esia esia) SignMessage(message string)(signedMessage string, err error){
    
    hasher := gost34112012256.New()
    _, err = hasher.Write([]byte(message))
    if err != nil {
	return "", err
    }
    dgst := hasher.Sum(nil)
    
    var prvKey gost3410.PrivateKeyReverseDigest = gost3410.PrivateKeyReverseDigest{}
    
    prvKey.Prv = Esia.Key

    signature, err := prvKey.Sign(crand.Reader, dgst, nil)
    if err != nil {
	return "", err
    }

    signedData, err := pkcs7.NewSignedData()
    if err != nil {
	return "", errors.New(fmt.Sprintf("Cannot initialize signed data: %v", err))
    }

    if err := signedData.AddSigner(Esia.Cert, Esia.Key, signature); err != nil {
	return "", errors.New(fmt.Sprintf("Cannot add signer: %v", err))
    }

    data, err := signedData.Finish()
    if err != nil {
	return "", errors.New(fmt.Sprintf("Cannot signing data: %v", err))
    }
    return base64.RawURLEncoding.EncodeToString(data), nil
}

func getState() string{

    rand.Seed(time.Now().UnixNano())
    return fmt.Sprintf("%04X%04x-%04x-%04x-%04x-%04x%04x%04x", 
	rand.Int31n(65000), 
	rand.Int31n(65000), 
	rand.Int31n(65000), 
	rand.Int31n(65000) | 0x4000, 
	rand.Int31n(65000) | 0x8000, 
	rand.Int31n(65000), 
	rand.Int31n(65000), 
	rand.Int31n(65000))
}

func getData() string{
    tm := time.Now()
    return tm.Format("2006.01.02 15:04:05 -0700")
}

func getMessage(esia esia, strTime string, state string) string{
    return fmt.Sprintf("%s%s%s%s", esia.Scopes, strTime, esia.ClientID, state)
}
