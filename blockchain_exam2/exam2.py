# -*- coding: utf-8 -*-

from argparse import _MutuallyExclusiveGroup
import hashlib
import math
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

from flask import Flask, render_template, request, redirect, jsonify, session, url_for, flash
import pymysql
import bcrypt
import config
from pip._vendor import requests
from bs4 import BeautifulSoup
import json

from pyfingerprint.pyfingerprint import PyFingerprint

# from Crypto.PublicKey import RSA
# from Crypto.Random import get_random_bytes
# from Crypto.Cipher import AES, PKCS1_OAEP

def private_key(fp_data):
    fp_data=bytes(fp_data,'utf-8')
    #지문데이터에대해서 해시함수 적용
    h=hashlib.sha256(fp_data).digest()
    #바이트 배열에 저장된 데이터를 16진수 문자열로 변환
    key = ''.join('{:02x}'.format(y)for y in h)
    return key

def addOperation(a, b, p, q, m):
    if q == (math.inf, math.inf):
        return p
    
    x1 = p[0]
    y1 = p[1]
    x2 = q[0]
    y2 = q[1]
    
    if p == q:
        # Doubling
        # slope (s) = (3 * x1 ^ 2 + a) / (2 * y1) mod m
        # 분모의 역원부터 계산한다 (by Fermat's Little Theorem)
        # pow() 함수가 내부적으로 Square-and-Multiply 알고리즘을 수행한다.
        r = 2 * y1
        rInv = pow(r, m-2, m)   # Fermat's Little Theorem
        s = (rInv * (3 * (x1 ** 2) + a)) % m
    else:
        r = x2 - x1
        rInv = pow(r, m-2, m)   # Fermat's Little Theorem
        s = (rInv * (y2 - y1)) % m
    x3 = (s ** 2 - x1 - x2) % m
    y3 = (s * (x1 - x3) - y1) % m
    return x3, y3

def public_key(pk):
    d=int(pk,16)
    bits = bin(d)
    bits = bits[2:len(bits)]

    K=G

    bits = bits[1:len(bits)]
    for bit in bits:
        #Double
        K=addOperation(a,b,K,K,m) 

        #Mulitply
        if bit=='1':
            K=addOperation(a,b,K,G,m)
    return K

a = 0
b = 7
m = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


db = pymysql.connect(host=config.host,port=3306,user=config.user,passwd=config.password,db=config.db,charset='utf8') # db 접속 본인 환경맞춰 설정
cursor = db.cursor() # 객체에 담기
global characterics

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        self.new_block(previous_hash='1', proof=100)

    def register_node(self, address):
        """
        Add a new node to the list of nodes
        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1
        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1
        return True

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None        
        max_length = len(self.chain)
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')
            
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True
        return False

    def new_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        self.current_transactions = [] 
        self.chain.append(block)
        return block
    
    def new_transaction(self, sender, recipient, amount):
        self.current_transactions.append({
                    'sender': sender,
                    'recipient': recipient,
                    'amount': amount,
                })
        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]
    
    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        # 위에서 설정한 last_block의 proof 값은 last_proof으로 설정
        last_proof = last_block['proof']
        # 마지막 블록을 해시한 것이 마지막 해시값
        last_hash = self.hash(last_block)
        # valid proof가 옳게될 때까지 proof 값을 더한다. 
        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1
        return proof

    # 위에서 말한 valid proof
    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        # 첫 4개가 0이 되어야만 통과
        return guess_hash[:4] == "0000"

app = Flask(__name__)
app.config.from_object(__name__)
app.config.update(
    SESSION_COOKIE_NAME = 'session_exam2',
    # SESSION_COOKIE_PATH = '/exam2/'
)
node_identifier = str(uuid4()).replace('-', '')
blockchain = Blockchain()

# 처음 index 시작 ----------------------------------------
@app.route('/')
def index():
    return render_template('bseoul.html',host=config.host)

# 상단 메뉴바 href ----------------------------------------
@app.route('/logo_index')
def logo_index():
    return render_template('bseoul.html',host=config.host)

@app.route('/teamplay')
def teamplay():
    return render_template('teamplay.html')

@app.route('/outsourcing')
def outsourcing():
    return render_template('outsourcing.html')

@app.route('/mypage')
def mypage():
    return render_template('/mypage.html')

@app.route('/loginpage')
def loginpage():
    return render_template('login.html')

@app.route('/login' , methods=['POST'])
def login():
    global characterics
    global pubKey
    db = pymysql.connect(host=config.host,port=3306,user=config.user,passwd=config.password,db=config.db,charset='utf8') # db 접속 본인 환경맞춰 설정
    cursor = db.cursor() # 객체에 담기
    if request.method == 'POST':
        login_info = request.form
        finger = login_info['finger']
        # password = login_info['password']
        sql = "SELECT * FROM exam WHERE finger = %s"
        rows_count = cursor.execute(sql , finger)
        if rows_count > 0:
            user_info = cursor.fetchone() # 일치하는 정보 객체에 담기
            name = user_info[2] 
            resident=user_info[3].split('-')[0]
            # mile = user_info[6] 
            korean=user_info[5]
            math=user_info[6]
            select1=user_info[7]
            select2=user_info[8]
            session['name'] = name
            session['finger'] = finger
            session['resident']=resident
            session['korean']=korean
            session['math']=math
            session['select1']=select1
            session['select2']=select2
            # session['mile'] = mile                
         
        try:       
            url=f'http://{config.host}:5000/chain'
            
            res=requests.get(url)
            res.raise_for_status()
            
            soup=BeautifulSoup(res.text,'html.parser')
            chain=json.loads(soup.text)
            for block in chain['chain'][::-1]:
                # print(block['transactions'][0]['sender'])
                if block['transactions'][0]['sender']==name:
                    print(block['transactions'][0]['sender'])
                    pubKey=int(block['transactions'][0]['public_key'])
                    encrypted_msg=block['transactions'][0]['data']
                    break
            pk=private_key(finger)
            
        except:
            # 검증이 안됐다면
            db.close()
            flash('Not Verified!')
            return redirect('/loginpage')
        # is_pw_correct = bcrypt.checkpw(password.encode('UTF-8') , user_info[2].encode('UTF-8')) # 패스워드 맞는지 확인
        if public_key(pk)[1]==pubKey: # 일치하게되면
            db.close() 
            flash('verify!')
            return redirect('/verify')
        else:
            db.close()
            flash('Not Verified!')
            return redirect('/loginpage')

@app.route('/logout')
def logout():
    session.clear()
    return render_template('bseoul.html')

@app.route('/registerpage')
def regit():
    return render_template('/register.html')

@app.route('/register' , methods=['POST']) # 회원가입부분
def register():
    if(request.method == 'POST'):
        register_info = request.form
        email = register_info['email']
        hased_password = bcrypt.hashpw(register_info['password'].encode('utf-8') , bcrypt.gensalt())
        name = register_info['name']
        department = register_info['department']
        sno = register_info['sno']
        sex = register_info['sex']
        sql = """
            INSERT INTO userinfo (email, hashed_password, name, sex, department, student_number) VALUES (%s , %s , %s , %s, %s, %s);
        """
        # 아이디 겹치면 try 구문 사용해서 오류 반환해주기 ... 구현해야함
        # cursor.execute(sql , (username , hased_password, email , department)) # sql 실행
        cursor.execute(sql , (email , hased_password , name , sex, department, sno))
        db.commit() #데이터 삽입 , 삭제 등의 구문에선 commit 해주어야함
        db.close() # 연결 해제        return redirect(request.url)
    return render_template('/login.html')

@app.route('/myinfo_fix')
def fix():
    return render_template('/myinfo_fix.html')

@app.route('/find')
def find():
    return render_template('/find.html')

#---------------------------------------------------------
@app.route('/goboard1')
def goboard1():
    return render_template('/board.html')

@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)
    
    blockchain.new_transaction(
        sender=f"{session['name']}",
        recipient=node_identifier,
        amount=1
    )

    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)
    
    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
        'context':"https://www.w3.org/ns/did/v1",
        'id':"did:btcr:123456789abcdefghi",
        'authentication':[{
        "id": "did:btcr:123456789abcdefghi#keys-1",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:btcr:123456789abcdefghi",
        "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
        }]
    }
    return jsonify(response), 200

@app.route('/transactions/new')
def new_transaction():
    db.ping()
    values = {
        'sender' : '안재현' , 
        'recipient' : '강홍구' , 
        'amount' : 20
    }
    cursor.execute("update userinfo set milegea = 180 where id = 3")
    cursor.execute("update userinfo set milegea = 620 where id = 5")
    required = ['sender', 'recipient', 'amount']

    if not all(k in values for k in required):
        return 'Missing values', 400

    #index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])
    #response = {'message': f'Transaction will be added to Block {index}'}
    #return jsonify(response), 201
    return redirect('/mine')
    
@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }   
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

@app.route('/verify')
def verify():
    url=f'http://{config.host}:5000/chain'
            
    res=requests.get(url)
    res.raise_for_status()
    
    soup=BeautifulSoup(res.text,'html.parser')
    chain=json.loads(soup.text)
    for block in chain['chain'][::-1]:
        # print(block['transactions'][0]['sender'])
        
        if block['transactions'][0]['sender']==session['name']:
            name=block['transactions'][0]['personal']['name']
            resident=str(block['transactions'][0]['personal']['resident']).split('-')[0]
            korean=block['transactions'][0]['personal']['korean']
            math=block['transactions'][0]['personal']['math']
            select1=block['transactions'][0]['personal']['select1']
            select2=block['transactions'][0]['personal']['select2']
            break
            
    return render_template('verify.html',name=name,host=config.host,resident=resident,korean=korean,math=math,select1=select1,select2=select2)

@app.route('/check',methods=['POST'])
def check():
    global characterics
    conn=pymysql.connect(host=config.host,port=3306,user=config.user,password=config.password,db=config.db)
    try:
        f=PyFingerprint('/dev/ttyAMA2',57600,0xFFFFFFFF,0x00000000)
        if(f.verifyPassword()==False):
            raise ValueError('The given fingerprint sensor password is wrong!')
        
    except Exception as e:
        print('The fingerprint sensor could not be initialized!')
        print('Exception message:'+str(e))
        exit(1)
        
    try:
        print('Wainting for finger')
        #waiting until reading fingerprint
        while(f.readImage()==False):
            pass
        #Converts read image to characteristics and stores it in charbuffer 1
        f.convertImage(0x01)
        characterics=str(f.downloadCharacteristics(0x01))
        cur=conn.cursor()
        sql="select*from exam"
        cur.execute(sql)
        for row in cur.fetchall():
            # print(str.encode(row[1]))
            print(f.uploadCharacteristics(0x02,eval(row[1])))
            score=f.compareCharacteristics()
            # print(type(score))
            if score>60:
                characterics=row[1]
    except Exception as e:
        print('Operation failed!')
        print('Exception message:' +str(e))
        exit(1)
    finally:
        conn.close()
    try:
        return render_template('login.html',check=characterics)
    except:
        flash('잘못입력하셨습니다.')
        return render_template('login.html')

if __name__ == '__main__':
    from argparse import ArgumentParser

    app.secret_key = b'1234qwerasdfzxcv'
    
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host=config.host, port=port,debug=True)
#---------------------------------------------------------