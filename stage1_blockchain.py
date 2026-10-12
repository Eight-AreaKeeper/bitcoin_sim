"""
阶段 1：区块结构、哈希链、工作量证明（PoW）挖矿、链校验

运行：python stage1_blockchain.py

要点：
- 每个区块记录上一个区块的哈希（prev_hash），区块之间就串成了一条“哈希链”。
- 改动任何一个历史区块，它的哈希就变了，后面所有区块的 prev_hash 都对不上。
- PoW：必须找到一个 nonce，使区块哈希 < 目标值（target）。找起来很难，验证只要算一次哈希。
"""
import json
import time

from crypto import double_sha256_hex


class Block:
    def __init__(self, index, prev_hash, data, difficulty_bits, timestamp=None, nonce=0):
        self.index = index                      # 区块高度
        self.prev_hash = prev_hash              # 上一个区块的哈希 —— 把区块“链”起来的关键
        self.data = data                        # 区块内容（阶段 1 先用一段文字，阶段 2 换成交易）
        self.difficulty_bits = difficulty_bits  # 难度：要求哈希前面至少有这么多个 0 比特
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.nonce = nonce                      # 挖矿时不断改变的随机数
        self.hash = self.compute_hash()

    def header_bytes(self) -> bytes:
        """区块头序列化。哈希覆盖了所有字段，改任何一个字段哈希都会变。"""
        header = {
            "index": self.index,
            "prev_hash": self.prev_hash,
            "data": self.data,
            "difficulty_bits": self.difficulty_bits,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
        }
        return json.dumps(header, sort_keys=True).encode()

    def compute_hash(self) -> str:
        return double_sha256_hex(self.header_bytes())

    @property
    def target(self) -> int:
        """哈希（看作 256 位整数）必须小于 target。前导 0 越多，target 越小，越难。"""
        return 2 ** (256 - self.difficulty_bits)

    def meets_pow(self) -> bool:
        return int(self.hash, 16) < self.target

    def mine(self) -> int:
        """工作量证明：暴力尝试 nonce 直到哈希满足难度。返回尝试次数。"""
        attempts = 0
        while True:
            self.hash = self.compute_hash()
            attempts += 1
            if self.meets_pow():
                return attempts
            self.nonce += 1

    def __repr__(self):
        return f"Block#{self.index} hash={self.hash[:16]}… prev={self.prev_hash[:16]}… nonce={self.nonce}"


class Blockchain:
    def __init__(self, difficulty_bits=16):
        self.difficulty_bits = difficulty_bits
        # 创世区块：第一个区块，没有前驱，prev_hash 全 0
        genesis = Block(0, "0" * 64, "创世区块", difficulty_bits, timestamp=0)
        genesis.mine()
        self.chain = [genesis]

    @property
    def tip(self) -> Block:
        return self.chain[-1]

    def add_block(self, data) -> Block:
        block = Block(len(self.chain), self.tip.hash, data, self.difficulty_bits)
        start = time.time()
        attempts = block.mine()
        cost = time.time() - start
        print(f"  挖出区块 #{block.index}: 尝试 {attempts:>7} 次, 用时 {cost:.2f}s, hash={block.hash[:20]}…")
        self.chain.append(block)
        return block

    def is_valid(self, verbose=True) -> bool:
        """
        链校验，逐块检查三件事：
        1. 区块存的 hash 是否等于重新计算出的 hash（内容有没有被改）
        2. 哈希是否满足难度（有没有真的做过工作量）
        3. prev_hash 是否等于上一个区块的 hash（链有没有断）
        """
        for i, block in enumerate(self.chain):
            if block.hash != block.compute_hash():
                if verbose:
                    print(f"  ✗ 区块 #{i} 内容被篡改：存储的哈希和重新计算的不一致")
                return False
            if not block.meets_pow():
                if verbose:
                    print(f"  ✗ 区块 #{i} 没有满足工作量证明")
                return False
            if i > 0 and block.prev_hash != self.chain[i - 1].hash:
                if verbose:
                    print(f"  ✗ 区块 #{i} 的 prev_hash 和区块 #{i-1} 的哈希对不上，链断了")
                return False
        return True


def demo():
    print("=" * 70)
    print("阶段 1 演示：哈希链 + 工作量证明")
    print("=" * 70)

    bits = 16  # 平均需要尝试 2^16 = 65536 次
    print(f"\n[1] 以难度 {bits} 比特（平均尝试 {2**bits} 次）挖 5 个区块：")
    bc = Blockchain(difficulty_bits=bits)
    for i in range(1, 6):
        bc.add_block(f"Alice 给 Bob 转了 {i} 个币")
    for b in bc.chain:
        print("   ", b)

    print("\n[2] 校验整条链：", "通过 ✓" if bc.is_valid() else "失败")

    print("\n[3] 难度越高越难：同一个区块用不同难度挖，比较尝试次数")
    for d in (8, 12, 16, 18):
        b = Block(99, "0" * 64, "test", d)
        n = b.mine()
        print(f"    难度 {d:>2} 比特: 尝试 {n:>8} 次 (期望约 {2**d})")

    print("\n[4] 攻击者篡改区块 #2 的内容：")
    bc.chain[2].data = "Alice 给 Mallory 转了 1000 个币"
    print("    只改数据不改哈希 →", "通过" if bc.is_valid() else "校验失败（见上）")

    print("\n    攻击者重新计算区块 #2 的哈希（但不做 PoW）：")
    bc.chain[2].hash = bc.chain[2].compute_hash()
    print("    →", "通过" if bc.is_valid() else "校验失败（见上）")

    print("\n    攻击者老老实实重挖区块 #2：")
    bc.chain[2].nonce = 0
    bc.chain[2].mine()
    print("    →", "通过" if bc.is_valid() else "校验失败（见上）")

    print("\n    所以攻击者必须把 #2 之后的所有区块全部重挖一遍：")
    start = time.time()
    for i in range(3, len(bc.chain)):
        bc.chain[i].prev_hash = bc.chain[i - 1].hash
        bc.chain[i].nonce = 0
        bc.chain[i].mine()
    print(f"    重挖 #3~#{len(bc.chain)-1} 用时 {time.time()-start:.2f}s →",
          "通过" if bc.is_valid() else "失败")
    print("""
    结论：单机上重挖当然能成功；但在真实网络里，诚实节点同时在往后延长链，
    攻击者的算力不够 51% 就永远追不上 —— 这就是阶段 4 要演示的“最长链规则”。""")


if __name__ == "__main__":
    demo()
