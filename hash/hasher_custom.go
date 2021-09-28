package hash

import (
	"context"
	"crypto/md5"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/x"
)

type Custom struct {
	c CustomConfiguration
}

type CustomConfiguration interface {
	config.Provider
}

func NewHasherCustom(c CustomConfiguration) *Custom {
	return &Custom{c: c}
}

func (h *Custom) Generate(ctx context.Context, password []byte) ([]byte, error) {
	hash := md5.New()
	io.WriteString(hash, x.NewUUID().String()+strconv.FormatInt(time.Now().UnixMilli(), 10))
	salt := hex.EncodeToString(hash.Sum(nil))[:4]

	sha := sha512.New()
	sha.Write([]byte(string(password) + salt))
	encodedPass := hex.EncodeToString(sha.Sum(nil))[:20]
	return []byte(strings.Join([]string{salt, encodedPass}, "@")), nil
}
