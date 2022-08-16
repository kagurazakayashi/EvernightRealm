package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// secretBytes 是会话秘密的随机熵源长度（位元组）。
//
// 32 位元組＝256 位元，取自 crypto/rand（作业系统的密码学随机源）：
// 秘密的可预测性是唯一真正要防的属性——math/rand 可复现、时间派生可猜测，
// 都不满足「拿到若干历史秘密也推不出下一个」。长度同时对齐 SHA-256 的输出宽度，
// 让哈希查找不引入额外的安全余量假设。
const secretBytes = 32

// secretEncoding 是秘密对外的传输形态：base64url、无填充。
//
// 选 base64url 而不是标准 base64：秘密要放得进 Cookie 值与 URL 而不需二次转义，
// '_'、'-' 与字母数字是安全字符集，'+/' 和 '=' 不是。
var secretEncoding = base64.RawURLEncoding

// secretTextLen 是编码后的字串长度（RawURLEncoding 对 32 位元組恒为 43 字元）。
const secretTextLen = 43

// newSecret 产生一枚新的不透明会话秘密。
//
// 回传值的允许露出点只有 Store.Create 的成功回传：调用端把它交给客户端一次，
// 服务端此后只认识它的哈希（见 hashSecret）。随机源失败时回传错误而不降级
// ——「换一种随机继续发会话」正是最不该静默发生的替换。
func newSecret(reader io.Reader) (string, error) {
	if reader == nil {
		reader = rand.Reader
	}
	buf := make([]byte, secretBytes)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return "", fmt.Errorf("session: 產生會話秘密失敗: %w", err)
	}
	return secretEncoding.EncodeToString(buf), nil
}

// hashSecret 把秘密明文换成落库与查找用的哈希（SHA-256 小写十六进位）。
//
// 用 SHA-256 而不是 Argon2id 是有明确前提的：被哈希的对象是一枚 256 位元、
// 密码学安全的随机值，不是人想出来的口令——离线暴破它的成本与暴破「直接从库里
// 读出的哈希」同级，而库里的哈希不可反推，所以慢哈希换不来任何东西；
// 反过来，每次请求验证都跑一遍 Argon2id 会把登录成本搬上每一个请求。
// 口令侧的 Argon2id 在 internal/credential，两件事不互相顶替。
//
// 形状不合格的输入（非 base64url、长度不对、含填充或安全集外字符）不送进哈希：
// 当场回传 ErrInvalidSecret。这不只是省一次计算——「任何字串都能进查找」会让
// 短字典值的碰撞尝试与库失败混在一起，拒绝在门前比拒绝在门后说得清。
func hashSecret(secret string) (string, error) {
	if len(secret) != secretTextLen {
		return "", ErrInvalidSecret
	}
	raw, err := secretEncoding.DecodeString(secret)
	if err != nil || len(raw) != secretBytes {
		return "", ErrInvalidSecret
	}
	// 再编码一次比对，挡掉同一明文的非正规写法（RawURLEncoding 的解码不保证唯一往返）：
	// 查找键必须只有一种形状，否则两个不同字串能命中同一哈希，等于自创第二条认证通路。
	if secretEncoding.EncodeToString(raw) != secret {
		return "", ErrInvalidSecret
	}
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:]), nil
}

// tokenHashLen 是哈希十六进位表示的长度，与迁移 0004 的 CHECK 同值。
const tokenHashLen = 64
