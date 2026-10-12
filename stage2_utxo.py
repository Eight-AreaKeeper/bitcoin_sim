"""
阶段 2：UTXO 交易模型 + 私钥签名验证

运行：python stage2_utxo.py

要点：
- 比特币没有“账户余额”。所有的钱都是一个个“未花费的交易输出”（UTXO）。
  你的余额 = 所有锁定到你地址的 UTXO 金额之和。
- 一笔交易 = 消耗若干旧 UTXO（输入） + 创造若干新 UTXO（输出）。
  输入总额 - 输出总额 = 手续费，归打包这笔交易的矿工。
- 想花一个 UTXO，必须提供：① 公钥，其哈希等于 UTXO 上的地址；② 用对应私钥做的签名。
- 每个区块的第一笔交易是 coinbase：没有输入，凭空产生区块奖励 —— 这是新币的唯一来源。
"""
import json
import time

from crypto import PrivateKey, double_sha256_hex, pubkey_to_address, sha256, verify

COIN = 100_000_000  # 1 个币 = 1 亿“聪”，金额全部用整数（聪）表示，避免浮点误差


def fmt(amount: int) -> str:
    """把聪显示成币。"""
    return f"{amount / COIN:.8f}".rstrip("0").rstrip(".")


# ---------------------------------------------------------------------------
# 交易
# ---------------------------------------------------------------------------
class TxOut:
    """交易输出：把 amount 聪“锁”到某个地址上。"""

    def __init__(self, amount: int, address: str):
        self.amount = amount
        self.address = address

    def to_dict(self):
        return {"amount": self.amount, "address": self.address}


class TxIn:
    """交易输入：指向之前某笔交易的某个输出（outpoint），并附上解锁它的公钥和签名。"""

    def __init__(self, prev_txid: str, prev_index: int, pubkey: str = "", signature: str = ""):
        self.prev_txid = prev_txid
        self.prev_index = prev_index
        self.pubkey = pubkey
        self.signature = signature

    @property
    def outpoint(self):
        return (self.prev_txid, self.prev_index)

    def to_dict(self, with_sig=True):
        d = {"prev_txid": self.prev_txid, "prev_index": self.prev_index}
        if with_sig:
            d.update(pubkey=self.pubkey, signature=self.signature)
        return d


class Transaction:
    def __init__(self, inputs, outputs, coinbase_data=None):
        self.inputs = inputs
        self.outputs = outputs
        # coinbase 交易没有输入。写入区块高度等信息，保证每个 coinbase 的 txid 都不同
        self.coinbase_data = coinbase_data

    @property
    def is_coinbase(self):
        return self.coinbase_data is not None

    def serialize(self, with_sig=True) -> bytes:
        return json.dumps({
            "inputs": [i.to_dict(with_sig) for i in self.inputs],
            "outputs": [o.to_dict() for o in self.outputs],
            "coinbase": self.coinbase_data,
        }, sort_keys=True).encode()

    @property
    def txid(self) -> str:
        return double_sha256_hex(self.serialize())

    def sighash(self) -> bytes:
        """
        签名的对象：交易中除签名以外的全部内容（引用了哪些 UTXO、钱给谁、给多少）。
        所以签完名后改动任何金额或收款地址，签名都会失效。
        """
        return sha256(self.serialize(with_sig=False))

    def total_out(self):
        return sum(o.amount for o in self.outputs)

    def __repr__(self):
        kind = "coinbase" if self.is_coinbase else f"{len(self.inputs)}入"
        outs = ", ".join(f"{fmt(o.amount)}→{o.address[:6]}" for o in self.outputs)
        return f"Tx {self.txid[:8]} [{kind}] {outs}"


def make_coinbase(miner_address: str, amount: int, height: int) -> Transaction:
    return Transaction([], [TxOut(amount, miner_address)], coinbase_data=f"height={height}")


# ---------------------------------------------------------------------------
# UTXO 集合：全网所有“还没花掉的钱”
# ---------------------------------------------------------------------------
class UTXOSet:
    def __init__(self, utxos=None):
        self.utxos = dict(utxos or {})  # {(txid, index): TxOut}

    def copy(self):
        return UTXOSet(self.utxos)

    def get(self, outpoint):
        return self.utxos.get(outpoint)

    def apply(self, tx: Transaction):
        """交易生效：删掉被花掉的 UTXO，加入新产生的 UTXO。"""
        for i in tx.inputs:
            del self.utxos[i.outpoint]
        for idx, out in enumerate(tx.outputs):
            self.utxos[(tx.txid, idx)] = out

    def balance(self, address):
        return sum(o.amount for o in self.utxos.values() if o.address == address)

    def owned_by(self, address):
        return sorted((op, o) for op, o in self.utxos.items() if o.address == address)


class TxError(Exception):
    pass


def validate_transaction(tx: Transaction, utxo: UTXOSet) -> int:
    """
    校验一笔普通（非 coinbase）交易，通过则返回手续费，否则抛出 TxError。
    这就是每个全节点对每笔交易做的事。
    """
    if tx.is_coinbase:
        raise TxError("coinbase 只能出现在区块第一笔")
    if not tx.inputs or not tx.outputs:
        raise TxError("交易必须有输入和输出")
    if any(o.amount <= 0 for o in tx.outputs):
        raise TxError("输出金额必须为正")
    if len({i.outpoint for i in tx.inputs}) != len(tx.inputs):
        raise TxError("同一笔交易里重复花同一个 UTXO")

    msg = tx.sighash()
    total_in = 0
    for i in tx.inputs:
        prev_out = utxo.get(i.outpoint)
        if prev_out is None:
            raise TxError(f"引用的 UTXO {i.prev_txid[:8]}:{i.prev_index} 不存在或已被花掉（双花？）")
        if pubkey_to_address(i.pubkey) != prev_out.address:
            raise TxError("公钥对应的地址不是这个 UTXO 的主人")
        if not verify(i.pubkey, msg, i.signature):
            raise TxError("签名验证失败（私钥不对，或交易签名后被篡改）")
        total_in += prev_out.amount

    if total_in < tx.total_out():
        raise TxError(f"输出 {fmt(tx.total_out())} 大于输入 {fmt(total_in)}，凭空造币")
    return total_in - tx.total_out()


# ---------------------------------------------------------------------------
# 钱包：保管私钥，帮你挑 UTXO、找零、签名
# ---------------------------------------------------------------------------
class Wallet:
    def __init__(self, name):
        self.name = name
        self.key = PrivateKey()
        self.address = self.key.address()

    def create_tx(self, utxo: UTXOSet, to_address: str, amount: int, fee: int = 0) -> Transaction:
        need = amount + fee
        chosen, total = [], 0
        for outpoint, out in utxo.owned_by(self.address):  # 简单策略：按顺序凑够为止
            chosen.append(outpoint)
            total += out.amount
            if total >= need:
                break
        if total < need:
            raise TxError(f"{self.name} 余额不足：有 {fmt(total)}，需要 {fmt(need)}")

        inputs = [TxIn(txid, idx) for txid, idx in chosen]
        outputs = [TxOut(amount, to_address)]
        if total > need:
            outputs.append(TxOut(total - need, self.address))  # 找零给自己
        tx = Transaction(inputs, outputs)
        self.sign(tx)
        return tx

    def sign(self, tx: Transaction):
        msg = tx.sighash()
        for i in tx.inputs:
            i.pubkey = self.key.public_key_hex()
            i.signature = self.key.sign(msg)


# ---------------------------------------------------------------------------
# 区块（这次装的是交易）和链
# ---------------------------------------------------------------------------
def merkle_root(txids):
    """
    默克尔根：交易 ID 两两哈希，层层向上，最后得到一个哈希。
    区块头只需存这一个值，就能锁定区块里的全部交易。
    """
    if not txids:
        return "0" * 64
    level = list(txids)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # 奇数个时复制最后一个（比特币的做法）
        level = [double_sha256_hex((level[i] + level[i + 1]).encode()) for i in range(0, len(level), 2)]
    return level[0]


class Block:
    def __init__(self, height, prev_hash, txs, difficulty_bits):
        self.height = height
        self.prev_hash = prev_hash
        self.txs = txs
        self.merkle_root = merkle_root([t.txid for t in txs])
        self.difficulty_bits = difficulty_bits
        self.timestamp = time.time()
        self.nonce = 0
        self.hash = self.compute_hash()

    def compute_hash(self):
        header = f"{self.height}|{self.prev_hash}|{self.merkle_root}|{self.difficulty_bits}|{self.timestamp}|{self.nonce}"
        return double_sha256_hex(header.encode())

    def mine(self):
        target = 2 ** (256 - self.difficulty_bits)
        while int(self.hash, 16) >= target:
            self.nonce += 1
            self.hash = self.compute_hash()


class Blockchain:
    BLOCK_REWARD = 50 * COIN

    def __init__(self, difficulty_bits=12):
        self.difficulty_bits = difficulty_bits
        self.chain = []
        self.utxo = UTXOSet()

    def mine_block(self, miner_address, txs):
        """矿工打包：coinbase（奖励 + 手续费）+ 交易，然后做 PoW。"""
        fees = 0
        tmp = self.utxo.copy()
        for tx in txs:  # 矿工自己先算一遍手续费（无效交易会在这里直接报错）
            fees += validate_transaction(tx, tmp)
            tmp.apply(tx)
        height = len(self.chain)
        coinbase = make_coinbase(miner_address, self.BLOCK_REWARD + fees, height)
        prev = self.chain[-1].hash if self.chain else "0" * 64
        block = Block(height, prev, [coinbase] + txs, self.difficulty_bits)
        block.mine()
        self.add_block(block)
        return block

    def add_block(self, block):
        """全节点收到区块后的完整校验。任何一步失败整个区块都作废，UTXO 不变。"""
        prev = self.chain[-1].hash if self.chain else "0" * 64
        if block.prev_hash != prev or block.height != len(self.chain):
            raise TxError("区块没有接在链尾")
        if block.hash != block.compute_hash() or int(block.hash, 16) >= 2 ** (256 - block.difficulty_bits):
            raise TxError("PoW 无效")
        if block.merkle_root != merkle_root([t.txid for t in block.txs]):
            raise TxError("默克尔根与交易不符（交易被篡改）")
        if not block.txs or not block.txs[0].is_coinbase:
            raise TxError("第一笔必须是 coinbase")

        tmp = self.utxo.copy()  # 在副本上依次应用，全部成功才替换
        fees = 0
        for tx in block.txs[1:]:
            fees += validate_transaction(tx, tmp)
            tmp.apply(tx)
        if block.txs[0].total_out() > self.BLOCK_REWARD + fees:
            raise TxError("coinbase 领取的奖励超过 区块奖励+手续费")
        tmp.apply(block.txs[0])
        self.utxo = tmp
        self.chain.append(block)


# ---------------------------------------------------------------------------
# 演示
# ---------------------------------------------------------------------------
def show_utxo(utxo, wallets):
    names = {w.address: w.name for w in wallets}
    print("    当前 UTXO 集合：")
    for (txid, idx), out in sorted(utxo.utxos.items(), key=lambda kv: names.get(kv[1].address, "")):
        print(f"      {txid[:8]}:{idx}  {fmt(out.amount):>6} 币  → {names.get(out.address, out.address[:8])}")
    print("    余额：" + "，".join(f"{w.name}={fmt(utxo.balance(w.address))}" for w in wallets))


def try_block(bc, miner, txs, desc):
    try:
        bc.mine_block(miner.address, txs)
        print(f"  ✓ {desc}：被接受（意外！）")
    except TxError as e:
        print(f"  ✗ {desc}：被拒绝 —— {e}")


def demo():
    print("=" * 70)
    print("阶段 2 演示：UTXO 交易模型 + 签名验证")
    print("=" * 70)

    alice, bob, carol, mallory = (Wallet(n) for n in ("Alice", "Bob", "Carol", "Mallory"))
    wallets = [alice, bob, carol, mallory]
    for w in wallets:
        print(f"  {w.name:<8} 地址 {w.address}")
    bc = Blockchain(difficulty_bits=12)

    print("\n[1] Alice 挖出第一个区块，coinbase 交易凭空给她 50 币：")
    bc.mine_block(alice.address, [])
    show_utxo(bc.utxo, wallets)

    print("\n[2] Alice 付给 Bob 20 币，手续费 1 币。她唯一的 UTXO 是 50 币，")
    print("    所以交易 = 输入 50 → 输出 20 给 Bob + 29 找零给自己（差额 1 是手续费）。Carol 挖矿打包：")
    tx1 = alice.create_tx(bc.utxo, bob.address, 20 * COIN, fee=1 * COIN)
    print("   ", tx1)
    bc.mine_block(carol.address, [tx1])
    show_utxo(bc.utxo, wallets)
    print("    注意 Carol 拿到了 51 币 = 区块奖励 50 + 手续费 1")

    print("\n[3] Bob 付给 Carol 5 币（无手续费），同一区块里 Carol 再把收到的钱转 3 币给 Alice：")
    tx2 = bob.create_tx(bc.utxo, carol.address, 5 * COIN)
    # tx3 专门花 tx2 刚产生、还没上链的那个输出（同一区块内的交易可以前后衔接）
    tx3 =carol.create_tx(UTXOSet({(tx2.txid, 0): tx2.outputs[0]}), alice.address, 3 * COIN)
    bc.mine_block(bob.address, [tx2, tx3])
    show_utxo(bc.utxo, wallets)

    print("\n[4] 各种作弊尝试（矿工打包时、全节点收块时都用同一个 validate_transaction 校验）：")
    alice_op, alice_out = bc.utxo.owned_by(alice.address)[0]

    # 4.1 Mallory 想花 Alice 的钱，用自己的私钥签名
    fake = Transaction([TxIn(*alice_op)], [TxOut(alice_out.amount, mallory.address)])
    mallory.sign(fake)
    try_block(bc, mallory, [fake], "Mallory 用自己的密钥花 Alice 的 UTXO")

    # 4.2 Mallory 冒充 Alice 的公钥，但他没有 Alice 的私钥，只能用自己的私钥签
    fake2 = Transaction([TxIn(*alice_op)], [TxOut(alice_out.amount, mallory.address)])
    fake2.inputs[0].pubkey = alice.key.public_key_hex()
    fake2.inputs[0].signature = mallory.key.sign(fake2.sighash())
    try_block(bc, mallory, [fake2], "Mallory 填上 Alice 的公钥、用自己的私钥签名")

    # 4.3 Alice 签好的交易在广播途中被篡改收款地址
    honest = alice.create_tx(bc.utxo, bob.address, 1 * COIN)
    honest.outputs[0].address = mallory.address
    try_block(bc, mallory, [honest], "签名后把收款人从 Bob 改成 Mallory")

    # 4.4 输出大于输入
    greedy = Transaction([TxIn(*alice_op)], [TxOut(alice_out.amount + 100 * COIN, alice.address)])
    alice.sign(greedy)
    try_block(bc, alice, [greedy], "输出比输入多 100 币")

    # 4.5 双花：同一个 UTXO 先付给 Bob，再付给 Carol
    pay_bob = alice.create_tx(bc.utxo, bob.address, 10 * COIN)
    pay_carol = alice.create_tx(bc.utxo, carol.address, 10 * COIN)
    try_block(bc, alice, [pay_bob, pay_carol], "同一区块里双花（先付 Bob 再付 Carol）")
    bc.mine_block(alice.address, [pay_bob])
    print("  ✓ 付给 Bob 的那笔单独打包：被接受")
    try_block(bc, alice, [pay_carol], "下一个区块再把同一个 UTXO 付给 Carol")

    print()
    show_utxo(bc.utxo, wallets)
    total = sum(o.amount for o in bc.utxo.utxos.values())
    print(f"\n  全网 UTXO 总额 {fmt(total)} 币 = {len(bc.chain)} 个区块 × 50 奖励。手续费只是转移，不会凭空产生或消失。")


if __name__ == "__main__":
    demo()
