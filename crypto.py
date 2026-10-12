"""
crypto.py —— 本项目用到的全部密码学工具（只依赖 Python 标准库）

包含：
1. sha256 / 双重 sha256（比特币里区块哈希、交易ID 都是 sha256(sha256(x))）
2. secp256k1 椭圆曲线 + ECDSA 签名/验签（比特币真实使用的曲线）
3. 由公钥生成“地址”

注意：这里的 ECDSA 是为了学习而手写的“教科书实现”，没有做防侧信道等处理，
千万不要用在真实资金上。
"""
import hashlib
import secrets
import sys

# Windows 控制台默认编码可能不是 UTF-8，统一改成 UTF-8，防止中文输出乱码/报错
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


# ---------------------------------------------------------------------------
# 哈希
# ---------------------------------------------------------------------------
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def double_sha256_hex(data: bytes) -> str:
    """比特币风格的哈希：做两次 sha256，返回 16 进制字符串。"""
    return hashlib.sha256(hashlib.sha256(data).digest()).hexdigest()


# ---------------------------------------------------------------------------
# secp256k1 椭圆曲线参数：y^2 = x^3 + 7  (mod P)
# ---------------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # 有限域的素数
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # 基点 G 的阶
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _point_add(p1, p2):
    """椭圆曲线上两点相加。None 表示“无穷远点”（相当于加法里的 0）。"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None  # P + (-P) = 0
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P  # 切线斜率（点倍乘）
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P  # 割线斜率
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _point_mul(k: int, point=G):
    """标量乘法 k*point，用“倍加法”实现（类似快速幂）。"""
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


# ---------------------------------------------------------------------------
# 密钥、签名、验签
# ---------------------------------------------------------------------------
class PrivateKey:
    """私钥就是一个 [1, N-1] 之间的随机大整数；公钥 = 私钥 * G。"""

    def __init__(self, secret: int = None):
        self.secret = secret if secret is not None else secrets.randbelow(N - 1) + 1
        self.public_key = _point_mul(self.secret)

    def public_key_hex(self) -> str:
        return pubkey_to_hex(self.public_key)

    def address(self) -> str:
        return pubkey_to_address(self.public_key_hex())

    def sign(self, msg_hash: bytes) -> str:
        """ECDSA 签名，返回 r||s 的 16 进制字符串。"""
        z = int.from_bytes(msg_hash, "big")
        while True:
            k = secrets.randbelow(N - 1) + 1  # 每次签名必须用新的随机数 k！重复使用会泄露私钥
            r = _point_mul(k)[0] % N
            if r == 0:
                continue
            s = pow(k, -1, N) * (z + r * self.secret) % N
            if s == 0:
                continue
            if s > N // 2:  # 比特币要求 “low-s”，避免签名可塑性
                s = N - s
            return f"{r:064x}{s:064x}"


def pubkey_to_hex(pub) -> str:
    """压缩公钥格式：02/03 前缀（表示 y 的奇偶）+ x 坐标。"""
    x, y = pub
    return ("02" if y % 2 == 0 else "03") + f"{x:064x}"


def hex_to_pubkey(h: str):
    """把压缩公钥还原成曲线上的点：已知 x，解出 y。"""
    prefix, x = h[:2], int(h[2:], 16)
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)  # secp256k1 的 P ≡ 3 (mod 4)，可以这样开平方
    if (y % 2 == 0) != (prefix == "02"):
        y = P - y
    return (x, y)


def verify(pubkey_hex: str, msg_hash: bytes, signature_hex: str) -> bool:
    """ECDSA 验签：只用公钥就能确认“这条消息确实是对应私钥的持有者签的”。"""
    try:
        pub = hex_to_pubkey(pubkey_hex)
        r, s = int(signature_hex[:64], 16), int(signature_hex[64:], 16)
    except (ValueError, IndexError):
        return False
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = int.from_bytes(msg_hash, "big")
    w = pow(s, -1, N)
    point = _point_add(_point_mul(z * w % N), _point_mul(r * w % N, pub))
    return point is not None and point[0] % N == r


def pubkey_to_address(pubkey_hex: str) -> str:
    """
    地址 = 公钥的哈希。
    真实比特币是 Base58Check(RIPEMD160(SHA256(pubkey)))，这里简化为 sha256 后取前 20 字节，
    道理一样：地址比公钥短，而且在花钱之前不暴露公钥。
    """
    return sha256(bytes.fromhex(pubkey_hex))[:20].hex()


if __name__ == "__main__":
    # 小自测：签名 -> 验签 -> 篡改消息后验签失败
    key = PrivateKey()
    h = sha256(b"hello bitcoin")
    sig = key.sign(h)
    print("地址:", key.address())
    print("签名验证（正确消息）:", verify(key.public_key_hex(), h, sig))
    print("签名验证（篡改消息）:", verify(key.public_key_hex(), sha256(b"hello bitcoiN"), sig))
