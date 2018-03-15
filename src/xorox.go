package main

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/segmentio/go-prompt"
)

func xor(a, b byte) byte {
	return a ^ b
}

func reverse(a []byte) []byte {
	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]
	}
	return a
}

func xorSlice(g []byte) []byte {
	n := len(g)
	r := make([]byte, n)
	copy(r, g)
	r = reverse(r)
	x := make([]byte, n)
	for i := 0; i < n; i++ {
		xored := xor(g[i], r[i])
		x[i] = xored
	}
	return x
}

func trim(y []byte) []byte {
	if len(y) > 0 {
		y = y[:len(y)-1]
	}
	return y
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func length() (int, error) {
	str := prompt.String("length\t")
	length, err := strconv.Atoi(str)
	return length, err
}

func getInfo() ([]string, int) {
	url := prompt.String("url\t")
	user := prompt.String("user\t")
	length, err := length()
	if err != nil {
		log.Fatalf("incorrect input - failed to parse int")
	}
	cTime :=
		base64.URLEncoding.EncodeToString([]byte(time.Now().String()))
	pass := []string{url, user, cTime}
	return pass, length
}

func main() {
	iter := rand.Intn(8192)
	pass, length := getInfo()
	strPass := strings.Join(pass, "+")
	bPass := []byte(strPass)
	salt, _ := randomBytes(4)
	sha512 := sha512.New
	newPass := trim(pbkdf2.Key(bPass, salt, iter, length, sha512))
	fmt.Printf("pass for %s@%s: %s",
		pass[1],
		pass[0],
		base64.URLEncoding.EncodeToString(newPass))
}
