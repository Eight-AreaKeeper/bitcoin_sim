"""
阶段 4：单机模拟多个节点互相广播，观察分叉与最长链规则

运行：python stage4_network.py [随机种子]

模拟方式（离散事件模拟）：
- 有一个全局“模拟时钟”和一个按时间排序的事件队列。消息发送 = 往队列里放一个“若干秒后送达”的事件。
  所以几百秒的网络活动一眨眼就能跑完，而且同一个随机种子每次结果完全一样，便于复现。
- 每个节点有自己独立的一份区块链、内存池、钱包，只能通过网络消息了解别人。
- 挖矿：PoW 是“无记忆”的随机过程，下一次挖到块的等待时间服从指数分布，
  均值 = 难度 / 算力。我们按这个分布抽样“什么时候挖到”，到点后再真的去算 nonce
  （难度很低，瞬间完成），这样别的节点收到后可以真实地验证 PoW。
- 链尾一变就重新开始挖（因为无记忆，丢掉之前的进度不吃亏）。

观察重点：
- 两个节点几乎同时挖到块 → 网络里一部分节点先看到 A，另一部分先看到 B → 分叉。
- 每个节点都只认“累计工作量最大”的链；同样大时坚持先收到的。
- 下一个块接在哪边，哪边就更长，另一边的节点发生“链重组”，被淘汰的块叫陈旧块（stale/orphan）。
- 网络分区时两边各自出块；分区恢复后短的一边整条放弃，其中的交易回到内存池，
  和主链冲突的（双花）直接作废 —— 这就是为什么收款要等多个确认。
"""
import heapq
import random
import sys
from collections import defaultdict

from stage2_utxo import COIN, TxError, Wallet, fmt, validate_transaction
from stage3_difficulty import Blockchain, Params, make_genesis


class Network:
    def __init__(self, seed=1, verbose=True):
        self.rng = random.Random(seed)
        self.now = 0.0
        self.queue = []          # 事件堆：(时间, 序号, 类型, 函数, 参数)
        self.seq = 0
        self.nodes = []
        self.latency = {}        # (a, b) -> 基础延迟秒数
        self.blocked = set()     # 网络分区时被切断的连接
        self.mining_enabled = True
        self.verbose = verbose

    def log(self, msg):
        if self.verbose:
            print(f"  [t={self.now:7.1f}s] {msg}")

    def schedule(self, delay, kind, fn, *args):
        self.seq += 1
        heapq.heappush(self.queue, (self.now + delay, self.seq, kind, fn, args))

    def connect(self, a, b, latency):
        self.latency[(a.id, b.id)] = self.latency[(b.id, a.id)] = latency
        a.peers.append(b)
        b.peers.append(a)

    def send(self, src, dst, kind, payload):
        if (src.id, dst.id) in self.blocked:
            return  # 连接被切断，消息丢失
        delay = self.latency[(src.id, dst.id)] * self.rng.uniform(0.8, 1.2)
        self.schedule(delay, "msg", dst.receive, kind, payload, src)

    def run(self, until):
        while self.queue and self.queue[0][0] <= until:
            t, _, _, fn, args = heapq.heappop(self.queue)
            self.now = t
            fn(*args)
        self.now = until

    def drain(self):
        """停止挖矿，把所有在途消息送达。"""
        self.mining_enabled = False
        self.queue = [e for e in self.queue if e[2] != "mine"]
        heapq.heapify(self.queue)
        while self.queue:
            t, _, _, fn, args = heapq.heappop(self.queue)
            self.now = t
            fn(*args)

    def resume_mining(self):
        self.mining_enabled = True
        for n in self.nodes:
            n.start_mining()

    def converge(self):
        """
        让全网达成一致：停挖 → 把消息送完 → 看大家链尾是否相同。
        不同（比如两条等长的链僵持），就再挖一会儿：下一个块会打破平局。
        """
        while True:
            self.drain()
            if len({n.chain.tip for n in self.nodes}) == 1:
                return
            self.log("各节点链尾仍不一致（等长分叉僵持），继续挖矿等下一个块打破平局…")
            self.resume_mining()
            self.run(self.now + 10)

    def partition(self, group_a, group_b):
        for a in group_a:
            for b in group_b:
                self.blocked.add((a.id, b.id))
                self.blocked.add((b.id, a.id))

    def heal(self):
        pairs = list(self.blocked)
        self.blocked.clear()
        # 重新连上后，双方互相告知自己的链尾（真实比特币里是握手后交换区块清单）
        for a_id, b_id in pairs:
            a, b = self.nodes[a_id], self.nodes[b_id]
            if b in a.peers:
                self.send(a, b, "block", a.chain.tip_block)


class Node:
    def __init__(self, net: Network, nid: int, hashrate: float, params: Params):
        self.net = net
        self.id = nid
        self.name = f"N{nid}"
        self.hashrate = hashrate
        self.chain = Blockchain(params, make_genesis(params))
        self.wallet = Wallet(self.name)
        self.mempool = {}        # txid -> Transaction，等待打包的交易
        self.orphans = {}        # 父块还没收到的区块：prev_hash -> {hash: block}
        self.peers = []
        self.mining_epoch = 0
        self.mined = []          # 自己挖出的区块哈希
        self.reorgs = 0

    # ---------------- 挖矿 ----------------
    def start_mining(self):
        """（重新）开始在当前链尾上挖矿。旧的挖矿事件因 epoch 不匹配而作废。"""
        self.mining_epoch += 1
        if not self.net.mining_enabled:
            return
        target = self.chain.next_target(self.chain.tip_block)
        mean_time = (2 ** 256 / target) / self.hashrate
        self.net.schedule(self.net.rng.expovariate(1 / mean_time), "mine", self.on_mined, self.mining_epoch)

    def on_mined(self, epoch):
        if epoch != self.mining_epoch or not self.net.mining_enabled:
            return
        parent = self.chain.tip_block
        ts = max(round(self.net.now, 3), parent.timestamp + 0.001)
        block = self.chain.build_block_template(self.wallet.address, list(self.mempool.values()), ts,
                                                miner=self.name)
        block.mine()  # 真的算出 nonce
        self.mined.append(block.hash)
        extra = f"，含 {len(block.txs) - 1} 笔交易" if len(block.txs) > 1 else ""
        self.net.log(f"{self.name} 挖出 #{block.height} {block.hash[:6]}（父 {parent.hash[:6]}）{extra}")
        self.accept_block(block, sender=None)

    # ---------------- 收消息 ----------------
    def receive(self, kind, payload, sender):
        if kind == "block":
            self.accept_block(payload, sender)
        elif kind == "tx":
            self.accept_tx(payload, sender)
        elif kind == "getblock":
            blk = self.chain.blocks.get(payload)
            if blk:
                self.net.send(self, sender, "block", blk)

    def broadcast(self, kind, payload, exclude=None):
        """泛洪广播：发给除来源外的所有邻居，邻居再转发，最终传遍全网。"""
        for p in self.peers:
            if p is not exclude:
                self.net.send(self, p, kind, payload)

    def accept_block(self, block, sender):
        if block.hash in self.chain.blocks:
            return  # 已经有了，不再转发（防止消息无限循环）
        if block.prev_hash not in self.chain.blocks:
            # 父块还没收到（比如刚从分区中恢复）：先暂存，并向发送方索要父块
            self.orphans.setdefault(block.prev_hash, {})[block.hash] = block
            if sender is not None:
                self.net.send(self, sender, "getblock", block.prev_hash)
            return

        old_tip = self.chain.tip_block
        res = self.chain.add_block(block)
        status = res["status"]
        if status == "invalid":
            self.net.log(f"{self.name} 拒绝无效区块 {block.hash[:6]}：{res['reason']}")
            return

        self.broadcast("block", block, exclude=sender)

        if status == "side" and sender is not None:
            same = block.height == old_tip.height
            self.net.log(f"{self.name} 收到 {block.miner} 的 #{block.height} {block.hash[:6]}，"
                         + ("和自己的链一样长，坚持先收到的 " + old_tip.hash[:6] if same
                            else "它所在的分支目前比自己的链短，先存为侧链")
                         + "  ← 分叉")
        elif status == "reorg":
            self.reorgs += 1
            dropped = ", ".join(f"#{b.height} {b.hash[:6]}" for b in res["disconnected"])
            adopted = ", ".join(f"#{b.height} {b.hash[:6]}" for b in res["connected"])
            self.net.log(f"{self.name} *** 链重组 *** 放弃 [{dropped}]，改用更长的 [{adopted}]")

        if status in ("extend", "reorg"):
            self.on_tip_changed(res)

        # 这个块到了以后，原来等它的孤儿块就能接上了
        for child in self.orphans.pop(block.hash, {}).values():
            self.accept_block(child, None)

    def on_tip_changed(self, res):
        # 被放弃的区块里的交易退回内存池（放在前面，保持原先顺序）
        returned = [tx for b in res["disconnected"] for tx in b.txs[1:]]
        confirmed = {tx.txid for b in res["connected"] for tx in b.txs}
        candidates = returned + list(self.mempool.values())
        # 用新链尾的 UTXO 依次重新校验，丢掉已上链的、和主链冲突的
        utxo = self.chain.utxo.copy()
        self.mempool = {}
        for tx in candidates:
            if tx.txid in confirmed or tx.txid in self.mempool:
                continue
            try:
                validate_transaction(tx, utxo)
            except TxError as e:
                self.net.log(f"{self.name} 从内存池丢弃交易 {tx.txid[:6]}：{e}")
                continue
            utxo.apply(tx)
            self.mempool[tx.txid] = tx
        self.start_mining()

    def accept_tx(self, tx, sender):
        if tx.txid in self.mempool:
            return
        utxo = self.chain.utxo.copy()
        for t in self.mempool.values():
            utxo.apply(t)
        try:
            validate_transaction(tx, utxo)
        except TxError as e:
            self.net.log(f"{self.name} 拒绝交易 {tx.txid[:6]}：{e}")
            return
        self.mempool[tx.txid] = tx
        self.broadcast("tx", tx, exclude=sender)


# ---------------------------------------------------------------------------
# 工具：建网络、画区块树、找交易
# ---------------------------------------------------------------------------
def build_network(seed, hashrates, edges, latency_range=(0.5, 2.0), block_time=10.0):
    net = Network(seed)
    total = sum(hashrates)
    # 初始难度直接设成“全网算力 × 出块时间”，省掉开头的难度爬坡
    params = Params(target_block_time=block_time, retarget_interval=20, halving_interval=10_000,
                    initial_difficulty=int(total * block_time))
    net.nodes = [Node(net, i, hr, params) for i, hr in enumerate(hashrates)]
    for a, b in edges:
        net.connect(net.nodes[a], net.nodes[b], round(net.rng.uniform(*latency_range), 2))
    for n in net.nodes:
        n.start_mining()
    return net


def render_tree(node, from_height=1, only_forks=False):
    """按高度列出 node 见过的所有区块：主链一列，被淘汰的分叉块另列。"""
    chain = node.chain
    main = {b.hash for b in chain.main_chain()}
    by_height = defaultdict(list)
    for b in chain.blocks.values():
        by_height[b.height].append(b)
    print(f"    {'高度':<6}{'主链区块':<16}被淘汰的分叉块")
    for h in range(from_height, chain.tip_block.height + 1):
        mains = [b for b in by_height[h] if b.hash in main]
        sides = [b for b in by_height[h] if b.hash not in main]
        if only_forks and not sides:
            continue
        m = f"{mains[0].hash[:6]}({mains[0].miner})" if mains else "-"
        s = "  ".join(f"✗ {b.hash[:6]}({b.miner})" for b in sides)
        print(f"    #{h:<5}{m:<16}{s}")


def find_tx(node, txid):
    """返回交易在 node 主链上的区块高度，不在主链上返回 None。"""
    for b in node.chain.main_chain():
        if any(t.txid == txid for t in b.txs):
            return b.height
    return None


def print_nodes(net):
    main = {b.hash for b in net.nodes[0].chain.main_chain()}
    for n in net.nodes:
        on_main = sum(1 for h in n.mined if h in main)
        tip = n.chain.tip_block
        print(f"    {n.name}: 算力 {n.hashrate:>3} H/s | 链尾 #{tip.height} {tip.hash[:6]} | "
              f"挖出 {len(n.mined):>2} 块，其中 {on_main:>2} 块在最终主链 | 重组 {n.reorgs} 次 | "
              f"余额 {fmt(n.chain.utxo.balance(n.wallet.address))}")


# ---------------------------------------------------------------------------
# 场景 1：自然分叉
# ---------------------------------------------------------------------------
def scenario_natural_forks(seed):
    print("=" * 78)
    print("场景 1：5 个节点，网络有延迟 → 偶尔同时出块产生分叉，最长链规则自动收敛")
    print("=" * 78)
    #   拓扑： N0 — N1 — N2
    #           \         |
    #            N4 ——— N3
    edges = [(0, 1), (1, 2), (2, 3), (3, 4), (4, 0)]
    # 为了让分叉多一点、方便观察：延迟 1~4 秒，相对 10 秒出块已经很大了（真实比特币是 1~2 秒 / 600 秒）
    net = build_network(seed, hashrates=[100, 80, 80, 70, 70], edges=edges, latency_range=(1.0, 4.0))
    print("  连接与延迟：" + "，".join(f"N{a}-N{b} {net.latency[(a, b)]}s" for a, b in edges))
    print()

    net.run(until=400)
    net.log("—— 停止挖矿，等全网消息传完 ——")
    net.converge()

    n0 = net.nodes[0]
    total_blocks = len(n0.chain.blocks) - 1
    main_len = n0.chain.tip_block.height
    print(f"\n  结果：所有节点链尾一致 = {len({n.chain.tip for n in net.nodes}) == 1}，"
          f"主链高度 {main_len}，一共挖出 {total_blocks} 个块，其中 {total_blocks - main_len} 个成了陈旧块"
          f"（分叉率 {(total_blocks - main_len) / total_blocks:.0%}）")
    print_nodes(net)
    print("\n  区块树（只列出发生过分叉的高度）：")
    render_tree(n0, only_forks=True)
    print("""
  解读：被淘汰块里的 coinbase 奖励也一起作废了，所以每个节点“挖出的块数”≠“拿到奖励的块数”。
        延迟越大（相对出块时间），分叉越多，浪费的算力越多 —— 这是比特币选择 10 分钟出块的原因之一。""")


# ---------------------------------------------------------------------------
# 场景 2：网络分区 + 双花
# ---------------------------------------------------------------------------
def scenario_partition(seed):
    print("\n" + "=" * 78)
    print("场景 2：网络分区 + 双花。分区恢复后，算力小的一边整条链被放弃")
    print("=" * 78)
    edges = [(0, 1), (1, 2), (2, 0), (2, 3), (3, 4), (4, 0)]
    net = build_network(seed, hashrates=[150, 100, 100, 60, 40], edges=edges, latency_range=(0.3, 1.0))
    net.verbose = False
    n0, n1, n2, n3, n4 = net.nodes

    # 先正常运行，直到 N0 有钱可花
    net.run(until=100)
    net.converge()
    while net.nodes[0].chain.utxo.balance(n0.wallet.address) == 0:
        net.resume_mining()
        net.run(net.now + 50)
        net.converge()
    fork_height = n0.chain.tip_block.height
    print(f"  [t={net.now:.0f}s] 正常运行到高度 #{fork_height}，全网一致。N0 余额 "
          f"{fmt(n0.chain.utxo.balance(n0.wallet.address))} 币")

    # 切断网络：A 组 {N0,N1,N2} 算力 350，B 组 {N3,N4} 算力 100
    net.partition([n0, n1, n2], [n3, n4])
    print(f"  [t={net.now:.0f}s] 网络分区！A 组 N0/N1/N2（算力 350） | B 组 N3/N4（算力 100）")

    # 双花：N0 用同一笔 UTXO，在 A 组付给 N1，在 B 组付给 N3
    pay_n1 = n0.wallet.create_tx(n0.chain.utxo, n1.wallet.address, 10 * COIN, fee=COIN // 10)
    pay_n3 = n0.wallet.create_tx(n0.chain.utxo, n3.wallet.address, 10 * COIN, fee=COIN // 10)
    shared = {i.outpoint for i in pay_n1.inputs} & {i.outpoint for i in pay_n3.inputs}
    print(f"  N0 构造两笔花同一个 UTXO 的交易（共用 {len(shared)} 个输入）：")
    print(f"     交易 {pay_n1.txid[:6]}：付 10 币给 N1，发到 A 组")
    print(f"     交易 {pay_n3.txid[:6]}：付 10 币给 N3，偷偷发到 B 组")
    n0.accept_tx(pay_n1, None)
    n3.accept_tx(pay_n3, None)

    net.resume_mining()
    net.run(net.now + 200)
    net.drain()  # 分区内消息传完，便于观察

    def describe(node, tx, who):
        h = find_tx(node, tx.txid)
        conf = node.chain.tip_block.height - h + 1 if h else 0
        return f"{who} 的收款交易{'已上链，' + str(conf) + ' 个确认' if h else '不在链上'}"

    print(f"\n  [t={net.now:.0f}s] 分区 200 秒后：")
    print(f"     A 组链尾 #{n0.chain.tip_block.height}，{describe(n0, pay_n1, 'N1')}")
    print(f"     B 组链尾 #{n3.chain.tip_block.height}，{describe(n3, pay_n3, 'N3')}"
          f"，N3 余额 {fmt(n3.chain.utxo.balance(n3.wallet.address))}")
    print("     → 两边各自认为自己的那笔付款有效！N3 如果此时就发货，就上当了。")

    print(f"\n  [t={net.now:.0f}s] 网络恢复，双方交换链尾：")
    net.verbose = True
    net.heal()
    net.converge()
    net.verbose = False

    print(f"\n  最终（全网一致 = {len({n.chain.tip for n in net.nodes}) == 1}）：")
    print(f"     {describe(n3, pay_n1, 'N1')}")
    print(f"     {describe(n3, pay_n3, 'N3')}，N3 余额 {fmt(n3.chain.utxo.balance(n3.wallet.address))}")
    print_nodes(net)
    print(f"\n  分区以来的区块树（从 #{fork_height} 开始）：")
    render_tree(n0, from_height=fork_height)
    print("""
  解读：
  - 分区期间 B 组也在正常出块，N3 看到了“好几个确认”，但这些块最后全部作废，
    B 组矿工的奖励也一起消失。累计工作量大的 A 组链胜出。
  - 冲突的那笔交易被退回内存池后，发现输入已被主链花掉，直接丢弃 —— 双花只有一笔能成功。
  - 如果 B 组算力超过一半，赢的就是 B 组：这就是 “51% 攻击” 能改写历史的原因。
  - 所以收款方要等足够多的确认（比特币惯例 6 个），确认越多，被推翻需要的算力越不现实。""")


if __name__ == "__main__":
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 7
    print(f"随机种子 = {seed}（换一个种子会看到不同的分叉情况：python stage4_network.py 42）\n")
    scenario_natural_forks(seed)
    scenario_partition(seed)
