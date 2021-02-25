from flask import Flask, render_template, jsonify, request
from time import time
from flask_cors import CORS
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
import binascii
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from uuid import uuid4
import json
import requests
import hashlib

MINING_SENDER = 'The Blockchain'
MINING_REWARD = 1
MINING_DIFFICULTY = 2


class Blockchain:

    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()
        self.node_id = str(uuid4()).replace('-', '')
        # Create genesis block on init
        self.create_block(0, '000')

    def create_block(self, nonce, previous_hash):
        """
        Add a block of transactions to the blockchain
        :param nonce: Generated nonce
        :param previous_hash: Previous block hash
        :return:
        """
        block_number = len(self.chain) + 1

        block = {
            'block_number': block_number,
            'timestamp': time(),
            'transactions': self.transactions,
            'nonce': nonce,
            'previous_hash': previous_hash
        }

        self.transactions = []
        self.chain.append(block)

        return block

    def verify_transaction_signature(self, sender_public_key, signature, transaction):
        public_key = RSA.importKey(binascii.unhexlify(sender_public_key))
        verifier = PKCS1_v1_5.new(public_key)
        hash = SHA.new(str(transaction).encode('utf-8'))

        try:
            verifier.verify(hash, binascii.unhexlify(signature))
            return True
        except ValueError:
            return False

    def submit_transaction(self, sender_public_key, recipient_public_key, signature, amount):
        transaction = OrderedDict({
            'sender_public_key': sender_public_key,
            'recipient_public_key': recipient_public_key,
            'amount': amount
        })

        if sender_public_key == MINING_SENDER:
            # Reward for mining a block
            self.transactions.append(transaction)
            return self.get_next_block_number()
        else:
            # Transaction from wallet to another wallet
            signature_verification = self.verify_transaction_signature(sender_public_key, signature, transaction)

            if signature_verification:
                self.transactions.append(transaction)
                return self.get_next_block_number()
            else:
                return False

    def get_next_block_number(self):
        return len(self.chain) + 1

    @staticmethod
    def hash_block(block):
        # We must to ensure that the Dictionary is ordered, otherwise we'll get inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode('utf8')
        hash = hashlib.new('sha256')
        hash.update(block_string)

        return hash.hexdigest()

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None
        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get('http://' + node + '/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.validate_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True



    def validate_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]

            if block['previous_hash'] != self.hash_block(last_block):
                return False

            transactions = block['transactions'][:-1]
            transaction_elements = ['sender_public_key', 'recipient_public_key', 'amount']
            transactions = [OrderedDict((k, transactions[k]) for k in transaction_elements) for transaction in
                            transactions]

            if not self.valid_proof(block['transactions'], block['last_hash'], block['nonce']):
                return False

            last_block = block
            current_index += 1

        return True

    @staticmethod
    def valid_proof(transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        guess = (str(transactions) + str(last_hash) + str(nonce)).encode('utf8')
        hash = hashlib.new('sha256')
        hash.update(guess)
        guess_hash = hash.hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def proof_of_work(self):
        last_block = self.chain[-1]
        last_hash = self.hash_block(last_block)
        nonce = 0

        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1

        return nonce

    @staticmethod
    def get_last_block():
        return blockchain.chain[-1]


blockchain = Blockchain()

app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    transactions = blockchain.transactions
    response = {'transactions': transactions}

    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }

    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    nonce = blockchain.proof_of_work()

    blockchain.submit_transaction(
        sender_public_key=MINING_SENDER,
        recipient_public_key=blockchain.node_id,
        signature='',
        amount=MINING_REWARD
    )

    previous_hash = blockchain.hash_block(blockchain.get_last_block())

    new_block = blockchain.create_block(nonce, previous_hash)

    response = {
        'message': 'New block created',
        'block_number': new_block['block_number'],
        'transactions': new_block['transactions'],
        'nonce': new_block['nonce'],
        'previous_hash': new_block['previous_hash'],
    }

    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form
    required = ['confirmation_sender_public_key', 'confirmation_recipient_public_key', 'transaction_signature',
                'confirmation_amount']

    if not all(key in values for key in required):
        return 'Missing values', 400

    transaction_results = blockchain.submit_transaction(
        values['confirmation_sender_public_key'],
        values['confirmation_recipient_public_key'],
        values['transaction_signature'],
        values['confirmation_amount']
    )

    if not transaction_results:
        return jsonify({'message': 'Invalid transaction'}), 406
    else:
        return jsonify({'message': 'Transaction will be added to the Block ' + str(transaction_results)})


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help='Port to listen to')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
