import argparse
import configparser
from io import BytesIO
import os
import psutil

from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.test_framework import BitcoinTestFramework

# Read configuration from config.ini
config = configparser.ConfigParser()
configfile = os.path.abspath(os.path.dirname(__file__)) + "/config.ini"
config.read_file(open(configfile, encoding="utf8"))

SOURCE_DIRECTORY = config["path"]["SOURCE_DIRECTORY"]

assert not SOURCE_DIRECTORY == '', 'SOURCE_DIRECTORY not configured! Edit config.ini to configure SOURCE_DIRECTORY.'

print("Source directory configured as {}".format(SOURCE_DIRECTORY))

class TestWrapper:
    """Singleton TestWrapper class.

    This wraps the actual TestWrapper class to ensure that users only ever
    instantiate a single TestWrapper."""

    class __TestWrapper(BitcoinTestFramework):
        """Wrapper Class for BitcoinTestFramework.

        Provides the BitcoinTestFramework rpc & daemon process management
        functionality to external python projects."""

        def set_test_params(self):
            # This can be overriden in setup() parameter.
            self.num_nodes = 1

        def run_test(self):
            pass

        def setup(self,
                  bitcoind=os.path.abspath(SOURCE_DIRECTORY + "/src/bitcoind"),
                  bitcoincli=None,
                  setup_clean_chain=True,
                  num_nodes=1,
                  network_thread=None,
                  rpc_timeout=60,
                  supports_cli=False,
                  bind_to_localhost_only=True,
                  nocleanup=False,
                  noshutdown=False,
                  cachedir=os.path.abspath(SOURCE_DIRECTORY + "/test/cache"),
                  tmpdir=None,
                  loglevel='INFO',
                  trace_rpc=False,
                  port_seed=os.getpid(),
                  coveragedir=None,
                  configfile=os.path.abspath(SOURCE_DIRECTORY + "/test/config.ini"),
                  pdbonfailure=False,
                  usecli=False,
                  perf=False,
                  randomseed=None):

            if self.running:
                print("TestWrapper is already running!")
                return

            # Check whether there are any bitcoind processes running on the system
            for p in [proc for proc in psutil.process_iter() if 'bitcoin' in proc.name()]:
                if p.exe().split('/')[-1] == 'bitcoind':
                    print("bitcoind processes are already running on this system. Please shutdown all bitcoind processes!")
                    return

            self.setup_clean_chain = setup_clean_chain
            self.num_nodes = num_nodes
            self.network_thread = network_thread
            self.rpc_timeout = rpc_timeout
            self.supports_cli = supports_cli
            self.bind_to_localhost_only = bind_to_localhost_only

            self.options = argparse.Namespace
            self.options.nocleanup = nocleanup
            self.options.noshutdown = noshutdown
            self.options.cachedir = cachedir
            self.options.tmpdir = tmpdir
            self.options.loglevel = loglevel
            self.options.trace_rpc = trace_rpc
            self.options.port_seed = port_seed
            self.options.coveragedir = coveragedir
            self.options.configfile = configfile
            self.options.pdbonfailure = pdbonfailure
            self.options.usecli = usecli
            self.options.perf = perf
            self.options.randomseed = randomseed

            self.options.bitcoind = bitcoind
            self.options.bitcoincli = bitcoincli

            super().setup()

            # Add notebook-specific methods
            for node in self.nodes:
                node.generate_and_send_coins = generate_and_send_coins.__get__(node)
                node.test_transaction = test_transaction.__get__(node)
            self.running = True

        def create_spending_transaction(self, txid, version=1, nSequence=0):
            """Construct a CTransaction object that spends the first ouput from txid."""
            # Construct transaction
            spending_tx = CTransaction()

            # Populate the transaction version
            spending_tx.nVersion = version

            # Populate the locktime
            spending_tx.nLockTime = 0

            # Populate the transaction inputs
            outpoint = COutPoint(int(txid, 16), 0)
            spending_tx_in = CTxIn(outpoint=outpoint, nSequence=nSequence)
            spending_tx.vin = [spending_tx_in]

            # Generate new Bitcoin Core wallet address
            dest_addr = self.nodes[0].getnewaddress(address_type="bech32")
            scriptpubkey = bytes.fromhex(self.nodes[0].getaddressinfo(dest_addr)['scriptPubKey'])

            # Complete output which returns 0.5 BTC to Bitcoin Core wallet
            amount_sat = int(0.5 * 100_000_000)
            dest_output = CTxOut(nValue=amount_sat, scriptPubKey=scriptpubkey)
            spending_tx.vout = [dest_output]

            return spending_tx

        def shutdown(self):
            if not self.running:
                print("TestWrapper is not running!")
            else:
                super().shutdown()
                self.running = False

    instance = None

    def __new__(cls):
        if not TestWrapper.instance:
            TestWrapper.instance = TestWrapper.__TestWrapper()
            TestWrapper.instance.running = False
        return TestWrapper.instance

    def __getattr__(self, name):
        return getattr(self.instance, name)

    def __setattr__(self, name):
        return setattr(self.instance, name)

def generate_and_send_coins(node, address):
    """Generate blocks on node and then send 1 BTC to address.

    No change output is added to the transaction.
    Return a CTransaction object."""
    version = node.getnetworkinfo()['subversion']
    print("\nClient version is {}\n".format(version))

    # Generate 101 blocks and send reward to bech32 address
    reward_address = node.getnewaddress(address_type="bech32")
    node.generatetoaddress(101, reward_address)
    balance = node.getbalance()
    print("Balance: {}\n".format(balance))

    assert balance > 1

    unspent_txid = node.listunspent(1)[-1]["txid"]
    inputs = [{"txid": unspent_txid, "vout": 0}]

    # Create a raw transaction sending 1 BTC to the address, then sign and send it.
    # We won't create a change output, so maxfeerate must be set to 0
    # to allow any fee rate.
    tx_hex = node.createrawtransaction(inputs=inputs, outputs=[{address: 1}])

    res = node.signrawtransactionwithwallet(hexstring=tx_hex)

    tx_hex = res["hex"]
    assert res["complete"]
    assert 'errors' not in res

    txid = node.sendrawtransaction(hexstring=tx_hex, maxfeerate=0)

    tx_hex = node.getrawtransaction(txid)

    # Reconstruct wallet transaction locally
    tx = CTransaction()
    tx.deserialize(BytesIO(bytes.fromhex(tx_hex)))
    tx.rehash()

    return tx

def test_transaction(node, tx):
    tx_str = tx.serialize().hex()
    ret = node.testmempoolaccept(rawtxs=[tx_str], maxfeerate=0)[0]
    print(ret)
    return ret['allowed']
