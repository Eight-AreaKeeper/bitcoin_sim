"""
阶段 3：难度调整、区块奖励（减半）

运行：python stage3_difficulty.py

要点：
- 难度用 target（目标值）表示：区块哈希必须 < target。target 越小越难。
  “难度” = 2^256 / target ≈ 平均要尝试多少次哈希才能出一个块。
- 每隔 retarget_interval 个块调整一次：
      新 target = 旧 target × (实际用时 / 期望用时)
  出块太快 → target 变小（变难）；太慢 → target 变大（变易）。单次最多调整 4 倍（和比特币一样）。
- 区块奖励每 halving_interval 个块减半。总量因此有上限：
      上限 = 初始奖励 × 减半间隔 × (1 + 1/2 + 1/4 + …) ≈ 初始奖励 × 减半间隔 × 2
  比特币：50 × 210000 × 2 = 2100 万。
- 矿工的 coinbase 可领取 = 区块奖励 + 本块全部交易手续费。

本文件里的 Blockchain 是“完整版”的链：支持分叉（保存一棵区块树）、按累计工作量选主链、
链重组。阶段 4 的多节点网络直接复用它。
"""
from stage2_utxo import (COIN, TxError, UTXOSet, Wallet, fmt, make_coinbase, merkle_root,
                         validate_transaction)
from crypto import double_sha256_hex


class Params:
    """共识参数：所有节点必须使用完全相同的参数，否则彼此会认为对方的区块无效。"""

    def __init__(self, target_block_time=10.0, retarget_interval=10, halving_interval=20,
                 initial_reward=50 * COIN, initial_difficulty=2 ** 11, max_adjust=4):
        self.target_block_time = target_block_time   # 期望出块间隔（秒）
        self.retarget_interval = retarget_interval   # 每多少个块调整一次难度（比特币 2016）
        self.halving_interval = halving_interval     # 每多少个块奖励减半（比特币 210000）
        self.initial_reward = initial_reward         # 初始区块奖励（比特币 50 BTC）
        self.max_adjust = max_adjust                 # 单次难度调整的最大倍数
        self.initial_target = 2 ** 256 // initial_difficulty
        self.max_target = 2 ** 256 // 16             # 最低难度，target 不能比这更大


def difficulty_of(target: int) -> float:
    """难度 = 平均需要尝试的哈希次数。"""
    return 2 ** 256 / target


class Block:
    def __init__(self, height, prev_hash, txs, target, timestamp, nonce=0, miner=""):
        self.height = height
        self.prev_hash = prev_hash
        self.txs = txs
        self.merkle_root = merkle_root([t.txid for t in txs])
        self.target = target          # 本块的难度目标，必须等于按规则算出来的值
        self.timestamp = timestamp    # 出块时间（模拟时钟，单位秒）
        self.nonce = nonce
        self.miner = miner            # 只是给人看的标签，不参与哈希
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        header = (f"{self.height}|{self.prev_hash}|{self.merkle_root}|{self.target:064x}|"
                  f"{self.timestamp:.3f}|{self.nonce}")
        return double_sha256_hex(header.encode())

    def meets_pow(self) -> bool:
        return int(self.hash, 16) < self.target

    @property
    def work(self) -> int:
        """这个块代表的工作量（期望哈希次数）。主链 = 累计工作量最大的链。"""
        return 2 ** 256 // (self.target + 1)

    def mine(self) -> int:
        """固定时间戳，暴力搜索 nonce。返回尝试次数。"""
        attempts = 1
        while not self.meets_pow():
            self.nonce += 1
            self.hash = self.compute_hash()
            attempts += 1
        return attempts

    def mine_with_clock(self, start_time: float, hashrate: float) -> int:
        """
        模拟“算力”：矿机每秒能算 hashrate 次哈希。
        每尝试一次，模拟时钟前进 1/hashrate 秒，时间戳随之更新（真实矿工也会不断更新时间戳）。
        这样“出块用了多久”就由真实的尝试次数决定，难度调整也就有了依据。
        """
        attempts = 0
        while True:
            attempts += 1
            self.timestamp = round(start_time + attempts / hashrate, 3)
            self.hash = self.compute_hash()
            if self.meets_pow():
                return attempts
            self.nonce += 1


_genesis_cache = {}


def make_genesis(params: Params) -> Block:
    """创世区块是写死在代码里的，所有节点一模一样。奖励发到一个没人有私钥的地址。"""
    key = id(params)
    if key not in _genesis_cache:
        cb = make_coinbase("0" * 40, params.initial_reward, 0)
        g = Block(0, "0" * 64, [cb], params.initial_target, timestamp=0.0, miner="创世")
        g.mine()
        _genesis_cache[key] = g
    return _genesis_cache[key]


class Blockchain:
    def __init__(self, params: Params, genesis: Block):
        self.params = params
        self.blocks = {genesis.hash: genesis}            # 见过的所有有效区块（包括分叉上的）
        self.chainwork = {genesis.hash: genesis.work}    # 从创世到该块的累计工作量
        utxo = UTXOSet()
        utxo.apply(genesis.txs[0])
        self.utxo_after = {genesis.hash: utxo}           # 每个区块之后的 UTXO 快照（简化：直接存副本）
        self.tip = genesis.hash                          # 当前主链的链尾

    # ---------------- 查询 ----------------
    @property
    def tip_block(self) -> Block:
        return self.blocks[self.tip]

    @property
    def utxo(self) -> UTXOSet:
        return self.utxo_after[self.tip]

    def ancestor(self, block_hash: str, height: int) -> Block:
        b = self.blocks[block_hash]
        while b.height > height:
            b = self.blocks[b.prev_hash]
        return b

    def main_chain(self):
        chain, b = [], self.tip_block
        while True:
            chain.append(b)
            if b.height == 0:
                return chain[::-1]
            b = self.blocks[b.prev_hash]

    def in_main_chain(self, block_hash: str) -> bool:
        b = self.blocks.get(block_hash)
        return b is not None and b.height <= self.tip_block.height and \
            self.ancestor(self.tip, b.height).hash == block_hash

    # ---------------- 共识规则 ----------------
    def block_reward(self, height: int) -> int:
        """奖励减半：每 halving_interval 个块右移一位（÷2）。"""
        halvings = height // self.params.halving_interval
        return self.params.initial_reward >> halvings if halvings < 64 else 0

    def next_target(self, parent: Block) -> int:
        """计算 parent 的下一个块应该用的 target。"""
        p = self.params
        height = parent.height + 1
        if height % p.retarget_interval != 0:
            return parent.target  # 不在调整点，沿用上一个块的难度

        first = self.ancestor(parent.hash, max(0, height - p.retarget_interval - 1))
        expected = (parent.height - first.height) * p.target_block_time
        actual = parent.timestamp - first.timestamp
        # 限制单次调整幅度，防止时间戳作假造成难度剧烈波动
        actual = min(max(actual, expected / p.max_adjust), expected * p.max_adjust)
        new_target = parent.target * int(actual * 1000) // int(expected * 1000)
        return min(new_target, p.max_target)

    def check_block(self, block: Block) -> UTXOSet:
        """全节点对区块的完整校验。通过则返回应用该块之后的 UTXO 集合，否则抛 TxError。"""
        parent = self.blocks[block.prev_hash]
        if block.hash != block.compute_hash():
            raise TxError("区块哈希不正确")
        if not block.meets_pow():
            raise TxError("没有满足工作量证明")
        if block.height != parent.height + 1:
            raise TxError("高度不对")
        if block.target != self.next_target(parent):
            raise TxError("难度目标不符合调整规则")
        if block.timestamp <= parent.timestamp:
            raise TxError("时间戳必须晚于父块（比特币实际用的是“过去 11 块中位数”规则）")
        if block.merkle_root != merkle_root([t.txid for t in block.txs]):
            raise TxError("默克尔根与交易不符")
        if not block.txs or not block.txs[0].is_coinbase:
            raise TxError("第一笔必须是 coinbase")

        utxo = self.utxo_after[parent.hash].copy()
        fees = 0
        for tx in block.txs[1:]:
            fees += validate_transaction(tx, utxo)
            utxo.apply(tx)
        allowed = self.block_reward(block.height) + fees
        if block.txs[0].total_out() > allowed:
            raise TxError(f"coinbase 领取 {fmt(block.txs[0].total_out())}，超过允许的 {fmt(allowed)}")
        utxo.apply(block.txs[0])
        return utxo

    def add_block(self, block: Block) -> dict:
        """
        收到一个区块：
        - 父块未知 → orphan（交给调用方处理）
        - 校验失败 → invalid
        - 累计工作量超过当前主链 → 切换主链（extend 直接延长 / reorg 发生重组）
        - 否则 → side（保存在侧链，暂不切换；工作量相同时坚持先收到的那条）
        """
        if block.hash in self.blocks:
            return {"status": "duplicate"}
        if block.prev_hash not in self.blocks:
            return {"status": "orphan"}
        try:
            utxo = self.check_block(block)
        except TxError as e:
            return {"status": "invalid", "reason": str(e)}

        self.blocks[block.hash] = block
        self.utxo_after[block.hash] = utxo
        self.chainwork[block.hash] = self.chainwork[block.prev_hash] + block.work

        if self.chainwork[block.hash] <= self.chainwork[self.tip]:
            return {"status": "side"}

        old_tip = self.tip
        fork = self._fork_point(old_tip, block.hash)
        disconnected = self._path(fork, old_tip)   # 被抛弃的旧主链区块
        connected = self._path(fork, block.hash)   # 新主链上新增的区块
        self.tip = block.hash
        return {
            "status": "extend" if block.prev_hash == old_tip else "reorg",
            "disconnected": disconnected,
            "connected": connected,
        }

    def _fork_point(self, a: str, b: str) -> Block:
        ba, bb = self.blocks[a], self.blocks[b]
        while ba.hash != bb.hash:
            if ba.height >= bb.height:
                ba = self.blocks[ba.prev_hash]
            else:
                bb = self.blocks[bb.prev_hash]
        return ba

    def _path(self, ancestor: Block, tip_hash: str):
        """从 ancestor（不含）到 tip（含）的区块列表，按高度升序。"""
        path, b = [], self.blocks[tip_hash]
        while b.hash != ancestor.hash:
            path.append(b)
            b = self.blocks[b.prev_hash]
        return path[::-1]

    # ---------------- 挖矿 ----------------
    def build_block_template(self, miner_address, candidate_txs, timestamp, miner=""):
        """矿工组装候选区块：从候选交易里挑出依次有效的，加上 coinbase（奖励 + 手续费）。"""
        parent = self.tip_block
        utxo = self.utxo.copy()
        chosen, fees = [], 0
        for tx in candidate_txs:
            try:
                fees += validate_transaction(tx, utxo)
            except TxError:
                continue  # 无效/冲突的交易直接跳过
            utxo.apply(tx)
            chosen.append(tx)
        height = parent.height + 1
        coinbase = make_coinbase(miner_address, self.block_reward(height) + fees, height)
        return Block(height, parent.hash, [coinbase] + chosen, self.next_target(parent),
                     timestamp, miner=miner)


# ---------------------------------------------------------------------------
# 演示：单个矿工，算力随时间变化，观察难度如何自动跟随；奖励如何减半
# ---------------------------------------------------------------------------
def demo(verbose=False):
    print("=" * 78)
    print("阶段 3 演示：难度调整 + 区块奖励减半")
    print("=" * 78)
    params = Params(target_block_time=10, retarget_interval=20, halving_interval=60,
                    initial_difficulty=2 ** 9)
    print(f"参数：期望出块 {params.target_block_time:g}s，每 {params.retarget_interval} 块调整难度，"
          f"每 {params.halving_interval} 块奖励减半，初始奖励 {fmt(params.initial_reward)} 币，"
          f"初始难度 {difficulty_of(params.initial_target):.0f}")
    print("全网算力剧本：#1~79 为 200 H/s；#80~159 新矿工加入，变 800 H/s；#160~239 大量矿工离开，变 100 H/s")
    print("（加 -v 参数可以看到每一个块的明细）\n")

    def hashrate_at(h):
        return 200 if h < 80 else 800 if h < 160 else 100

    chain = Blockchain(params, make_genesis(params))
    miner, alice = Wallet("矿工"), Wallet("Alice")
    mempool = []
    window_start = chain.tip_block

    print(f"{'区块范围':<12}{'算力H/s':>8}{'难度':>8}{'平均出块':>9}{'每块奖励':>9}   说明")
    for h in range(1, 240):
        parent = chain.tip_block
        if h == 6:  # 让一笔带手续费的交易进入内存池，观察 coinbase = 奖励 + 手续费
            mempool.append(miner.create_tx(chain.utxo, alice.address, 10 * COIN, fee=COIN // 2))

        block = chain.build_block_template(miner.address, mempool, parent.timestamp, miner="矿工")
        attempts = block.mine_with_clock(parent.timestamp, hashrate_at(h))
        result = chain.add_block(block)
        assert result["status"] == "extend", result
        mempool = [t for t in mempool if t not in block.txs]

        if verbose:
            print(f"    #{h:<4} 尝试 {attempts:>6} 次，间隔 {block.timestamp - parent.timestamp:6.1f}s，"
                  f"coinbase {fmt(block.txs[0].total_out())}")
        if len(block.txs) > 1:
            print(f"    （#{h} 打包了一笔手续费 0.5 币的交易，coinbase = {fmt(block.txs[0].total_out())} 币"
                  f" = 奖励 {fmt(chain.block_reward(h))} + 手续费 0.5）")

        # 每到调整点（下一个块要换难度）时，打印这一窗口的统计
        if (h + 1) % params.retarget_interval == 0:
            n = h - window_start.height
            avg = (block.timestamp - window_start.timestamp) / n
            new_target = chain.next_target(block)
            notes = []
            if hashrate_at(h) != hashrate_at(window_start.height + 1):
                notes.append("算力中途变化")
            notes.append(f"下一窗口难度 ×{block.target / new_target:.2f}")
            print(f"#{window_start.height + 1:>3} ~ #{h:<4}{hashrate_at(h):>8}{difficulty_of(block.target):>10.0f}"
                  f"{avg:>9.1f}s{fmt(chain.block_reward(h)):>10}   {'，'.join(notes)}")
            window_start = block
            if (h + 1) % params.halving_interval == 0:
                print(f"  ==== 奖励减半：{fmt(chain.block_reward(h))} → {fmt(chain.block_reward(h + 1))} 币 ====")

    print("\n观察：算力一变，出块间隔就偏离 10s；下一次调整后难度跟着算力走（难度 ≈ 算力 × 10s），间隔又回到 10s 附近。")
    print("      单个窗口只有 20 个块，随机波动不小；比特币用 2016 个块，所以稳得多。")

    supply = sum(o.amount for o in chain.utxo.utxos.values())
    cap = sum(chain.block_reward(h) for h in range(0, params.halving_interval * 64))
    print(f"\n当前流通量（含创世块）：{fmt(supply)} 币；按当前参数，总量上限 = {fmt(cap)} 币")
    print(f"  （≈ {fmt(params.initial_reward)} × {params.halving_interval} × 2 = "
          f"{fmt(params.initial_reward * params.halving_interval * 2)}；奖励以“聪”为单位右移取整，"
          f"所以最终略少一点 —— 比特币也因此略少于 2100 万）")


if __name__ == "__main__":
    import sys
    demo(verbose="-v" in sys.argv)
