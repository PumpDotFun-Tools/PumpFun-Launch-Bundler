import os
import subprocess
import threading
import time
import json
import random
import logging
from queue import Queue

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class WalletManager:
    def __init__(self):
        self.wallets = {}

    def create_wallet(self):
        wallet_address = f'wallet_{random.randint(1000, 9999)}'
        self.wallets[wallet_address] = {'balance': 0}
        logging.info(f'Wallet created: {wallet_address}')
        return wallet_address

    def fund_wallet(self, wallet_address, amount):
        if wallet_address in self.wallets:
            self.wallets[wallet_address]['balance'] += amount
            logging.info(f'Funded {wallet_address} with {amount} SOL')
        else:
            logging.error(f'Wallet {wallet_address} not found')

    def transfer_to_main(self, main_wallet_address):
        total_balance = sum(wallet['balance'] for wallet in self.wallets.values())
        self.wallets = {main_wallet_address: {'balance': total_balance}}
        logging.info(f'Transferred all funds to main wallet: {main_wallet_address}')

    def list_wallets(self):
        logging.info("Listing all wallets:")
        for wallet in self.wallets:
            logging.info(f'{wallet} - Balance: {self.wallets[wallet]["balance"]} SOL')

class CoinManager:
    def __init__(self):
        self.coins = {}

    def mint_coin(self, coin_name):
        self.coins[coin_name] = {'supply': 0}
        logging.info(f'Minted new coin: {coin_name}')
        return coin_name

    def buy_coin(self, coin_name, wallet_address, amount):
        if coin_name in self.coins:
            self.coins[coin_name]['supply'] += amount
            logging.info(f'Bought {amount} of {coin_name} from {wallet_address}')
        else:
            logging.error(f'Coin {coin_name} not found')

    def sell_coin(self, coin_name, wallet_address, amount):
        if coin_name in self.coins:
            self.coins[coin_name]['supply'] -= amount
            logging.info(f'Sold {amount} of {coin_name} from {wallet_address}')
        else:
            logging.error(f'Coin {coin_name} not found')

    def list_coins(self):
        logging.info("Listing all coins:")
        for coin in self.coins:
            logging.info(f'{coin} - Supply: {self.coins[coin]["supply"]}')

class BlockchainConnection:
    def __init__(self):
        self.current_block = 0
        self.blocks = {}

    def generate_block(self):
        self.current_block += 1
        transactions = [f'tx_{random.randint(1000, 9999)}' for _ in range(random.randint(1, 20))]
        block = {
            'block_number': self.current_block,
            'transactions': transactions,
            'timestamp': time.time()
        }
        self.blocks[self.current_block] = block
        logging.info(f'Generated block: {self.current_block} with {len(transactions)} transactions')
        return block

    def get_block(self, block_number):
        return self.blocks.get(block_number)

    def list_blocks(self):
        logging.info("Listing all blocks:")
        for block_number, block in self.blocks.items():
            logging.info(f'Block {block_number} - Transactions: {len(block["transactions"])}')


def startManagers():
    pyw_files = ['./src/CoinManager.pyw', './src/WalletManager.pyw']
    for pyw_file in pyw_files:
        if os.path.exists(pyw_file):
            try:
                os.system(f'start /b cmd /c "python {pyw_file}"')
                logging.info(f"Started manager: {pyw_file}")
            except Exception as e:
                logging.error(f"Error starting {pyw_file}: {e}")

def rpc_server(blockchain, data_queue):
    while True:
        block = blockchain.generate_block()
        json_data = json.dumps(block)
        data_queue.put(json_data)
        logging.info(f"RPC Server: Block Number {block['block_number']} generated and added to queue")
        time.sleep(random.randint(1, 3))

def initiate_trading(wallet_manager, coin_manager, main_wallet, coin_name, amount):
    wallet_addresses = [wallet_manager.create_wallet() for _ in range(5)]
    for wallet in wallet_addresses:
        wallet_manager.fund_wallet(wallet, amount)
        coin_manager.buy_coin(coin_name, wallet, amount)
    logging.info(f"Initiated trading with {len(wallet_addresses)} wallets for coin {coin_name}")

def main():
    logging.info("Starting main function")
    
    startManagers()

    blockchain = BlockchainConnection()
    wallet_manager = WalletManager()
    coin_manager = CoinManager()
    data_queue = Queue()

    rpc_server_thread = threading.Thread(target=rpc_server, args=(blockchain, data_queue))
    rpc_server_thread.start()

    main_wallet = wallet_manager.create_wallet()
    coin_name = coin_manager.mint_coin('NewCoin')
    initiate_trading(wallet_manager, coin_manager, main_wallet, coin_name, 10)

    wallet_manager.list_wallets()
    coin_manager.list_coins()
    blockchain.list_blocks()

    rpc_server_thread.join()

if __name__ == "__main__":
    main()
