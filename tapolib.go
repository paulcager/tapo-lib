package tapo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"
)

type switchState struct {
	DeviceOn bool `json:"device_on"`
}

func generateKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, &privateKey.PublicKey, nil
}

type handshake struct {
	Key string `json:"key,omitempty"`
}
type message struct {
	Method string      `json:"method,omitempty"`
	Params interface{} `json:"params,omitempty"`
}
type handshakeResponse struct {
	ErrorCode int       `json:"error_code,omitempty"`
	Result    handshake `json:"result"`
}

type deviceResponse struct {
	ErrorCode int `json:"error_code,omitempty"`
	Result    struct {
		Response string `json:"response,omitempty"`
	} `json:"result"`
}

type passthroughMessage struct {
	Method string `json:"method,omitempty"`
	Params struct {
		Request string `json:"request,omitempty"`
	} `json:"params"`
}

func (session *Session) handshake() error {
	b, err := makeHandshake(session)
	if err != nil {
		return err
	}

	request, err := http.NewRequest("POST", "http://"+session.address+"/app", bytes.NewReader(b))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	var hsResp handshakeResponse
	err = json.NewDecoder(resp.Body).Decode(&hsResp)
	if err != nil {
		return err
	}

	session.cookies = resp.Cookies()
	session.timestamp = time.Now()

	return decodeTapoKey(session, hsResp.Result.Key)
}

func (session *Session) login() error {
	type Login struct {
		Method string `json:"method,omitempty"`
		Params struct {
			Password string `json:"password,omitempty"`
			Username string `json:"username,omitempty"`
		} `json:"params"`
		RequestTimeMillis int `json:"requestTimeMillis"`
	}

	type LoginResponse struct {
		ErrorCode int `json:"error_code,omitempty"`
		Result    struct {
			Token string `json:"token,omitempty"`
		} `json:"result"`
	}

	login := Login{Method: "login_device"}
	loginResponse := LoginResponse{}

	// The username passed is base64(hex(sha1(username))).
	// Note that we base64 encode the hex, even though it is printable.
	sha1Username := sha1.Sum([]byte(session.username))
	hexSha1 := make([]byte, 2*len(sha1Username))
	hex.Encode(hexSha1, sha1Username[:])
	login.Params.Username = base64.StdEncoding.EncodeToString(hexSha1)
	b64Password := base64.StdEncoding.EncodeToString([]byte(session.password))
	login.Params.Password = b64Password

	err := session.doPost(&login, &loginResponse)

	if err == nil && loginResponse.Result.Token != "" {
		session.token = loginResponse.Result.Token
	}

	return err
}

func (session *Session) encodeJson(obj interface{}) ([]byte, error) {
	b := new(bytes.Buffer)
	encoder := json.NewEncoder(b)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(obj)
	return b.Bytes(), err
}

func (session *Session) decodeJson(r io.Reader, obj interface{}) error {
	decoder := json.NewDecoder(r)
	return decoder.Decode(obj)
}

func makeHandshake(session *Session) ([]byte, error) {
	pubKey := session.public
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	pemPublic := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		},
	))

	h := message{
		Method: "handshake",
		Params: handshake{Key: pemPublic},
	}

	return session.encodeJson(h)
}

func decodeTapoKey(session *Session, key string) error {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return err
	}
	keyFromTapo, err := rsa.DecryptPKCS1v15(nil, session.private, b)

	if len(keyFromTapo) != 32 {
		return fmt.Errorf("invalid session key %X", keyFromTapo)
	}

	session.aesKey = keyFromTapo[:16]
	session.aesIv = keyFromTapo[16:]

	return err
}

func (session *Session) requiresHandshake() bool {
	if session.timestamp.IsZero() || session.timestamp.Add(23*time.Hour).Before(time.Now()) {
		return true
	}
	if len(session.aesKey) == 0 || len(session.cookies) == 0 {
		return true
	}

	for _, cookie := range session.cookies {
		if !cookie.Expires.IsZero() && cookie.Expires.Before(time.Now()) {
			return true
		}
	}

	return false
}

func (session *Session) encrypt(b []byte) ([]byte, error) {
	aesCipher, err := aes.NewCipher(session.aesKey)
	if err != nil {
		return nil, err
	}

	// PKCS7 Padding
	padLen := aes.BlockSize - len(b)%aes.BlockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	padded := append(b, padding...)
	encrypted := make([]byte, len(padded))

	cbc := cipher.NewCBCEncrypter(aesCipher, session.aesIv)
	cbc.CryptBlocks(encrypted, padded)

	return encrypted, nil
}

func (session *Session) decrypt(b []byte) ([]byte, error) {
	aesCipher, err := aes.NewCipher(session.aesKey)
	if err != nil {
		return nil, err
	}

	length := len(b)
	if length == 0 || length%aes.BlockSize != 0 {
		return nil, fmt.Errorf("unexpected data length %d", length)
	}

	cbc := cipher.NewCBCDecrypter(aesCipher, session.aesIv)
	decrypted := make([]byte, length)
	cbc.CryptBlocks(decrypted, b)

	// The number of padding bytes is written into each padding byte.
	padLen := int(decrypted[length-1])
	return decrypted[:length-padLen], nil
}

type securePassthrough struct {
	Method string `json:"method,omitempty"`
	Params struct {
		Request string `json:"request,omitempty"`
	} `json:"params"`
}

func (session *Session) doPost(body interface{}, response interface{}) error {
	jsonIn, err := session.encodeJson(body)
	if err != nil {
		return err
	}

	encrypted, err := session.encrypt(jsonIn)
	if err != nil {
		return err
	}

	msg := securePassthrough{}
	msg.Method = "securePassthrough"
	msg.Params.Request = base64.StdEncoding.EncodeToString(encrypted)

	jsonInEncoded, err := session.encodeJson(msg)
	if err != nil {
		return err
	}

	url := "http://" + session.address + "/app"
	if session.token != "" {
		url += "?token=" + session.token
	}
	request, err := http.NewRequest("POST", url, bytes.NewReader(jsonInEncoded))
	if err != nil {
		return err
	}

	for _, cookie := range session.cookies {
		request.AddCookie(cookie)
	}

	resp, err := session.Client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if len(resp.Cookies()) > 0 {
		session.cookies = resp.Cookies()
	}

	var deviceResponse deviceResponse
	err = session.decodeJson(resp.Body, &deviceResponse)
	if err != nil {
		return err
	}

	if deviceResponse.ErrorCode != 0 {
		// Most likely device doesn't understand our encryption - possibly
		// due to restart.
		session.Invalidate()
		return fmt.Errorf("deviceResponse: %+v", deviceResponse)
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(deviceResponse.Result.Response)
	if err != nil {
		return err
	}

	decrypted, err := session.decrypt(encryptedBytes)
	if err != nil {
		return err
	}

	//fmt.Println("in:  ", string(jsonIn))
	//fmt.Println("out: ", string(decrypted))

	return json.Unmarshal(decrypted, response)
}
