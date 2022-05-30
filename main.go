package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"log"
	"math"
	"math/big"
	"time"

	"github.com/boltdb/bolt"
)

//브록들을 체인형태로 연결
//블록헤더에는 해시,난이도,논스,이전블록해시,타임스탬프,머클트리루트
type Block struct {
	PrevBlockHash []byte
	Hash          []byte
	Timestamp     int64
	Data          []byte
	Nonce         int64
}
type blockchainIterator struct {
	db   *bolt.DB
	hash []byte
}

//새로운블록
func NewBlock(data string, prevBloclHash []byte) *Block {
	block := &Block{prevBloclHash, []byte{}, time.Now().Unix(), []byte(data), 0}
	pow := NewProofOfWork(block)
	block.Nonce, block.Hash = pow.Run()
	return block
}

//블록의 해시를설정
//sha256해시설정
func (b *Block) SetHash() {
	header := bytes.Join([][]byte{
		b.PrevBlockHash,
		b.Data,
		IntToHex(b.Timestamp),
	}, []byte{})
	hash := sha256.Sum256(header)
	b.Hash = hash[:]

}

//int64값을 받아 바이트로 변환
func IntToHex(i int64) []byte {
	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.BigEndian, i)
	if err != nil {
		log.Panic(err)
	}

	return buf.Bytes()
}

//다수의 블록
type Blockchain struct {
	db *bolt.DB
	l  []byte
}

const (
	BlocksBucks = "blocks"
	dbFile      = "chain.db"
)

//제네시스 블록을 미리 포함
//첫번쨰 블록
func NewBlockchain() *Blockchain {
	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	var l []byte
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BlocksBucks))

		if b == nil {
			//새로운블록체인을 만들어야 하는 경우
			b, err := tx.CreateBucket([]byte(BlocksBucks))
			if err != nil {
				log.Panic(err)
			}
			genesis := NewBlock("Genesis Block", []byte{})

			err = b.Put(genesis.Hash, genesis.Serialize())
			if err != nil {
				log.Panic(err)
			}

			//l키는 마지막 블록해시를 저장
			err = b.Put([]byte("l"), genesis.Hash)
			if err != nil {
				log.Panic(err)
			}
			l = genesis.Hash

		} else {
			//이미 블록체인이 있는 경우
			l = b.Get([]byte("l"))
		}
		if err != nil {
			log.Panic(err)
		}
		return nil
	})
}

//블록체인에 새로운 블록 포함
//blocks에 저장하던 것을 스토어에 저장할수 있도록 변경
func (bc *Blockchain) AddBlock(data string) {
	block := NewBlock(data, bc.l)
	err := bc.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BlocksBucks))

		err := b.Put(block.Hash, block.Serialize())
		if err != nil {
			log.Panic(err)
		}
		err = b.Put([]byte("l"), block.Hash)
		if err != nil {
			log.Panic(err)
		}
		bc.l = block.Hash

		return nil
	})
	if err != nil {
		log.Panic(err)
	}
}

//해시값을 찾을 블록,
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

//작업증명생성,
const targetBits = 24

func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, 256-targetBits)

	return &ProofOfWork{b, target}
}

//nonce target보다 더 작은 값을 찾기위해 데이터를 준비시키위한 준비
func (pow *ProofOfWork) prepareData(nonce int64) []byte {
	data := bytes.Join([][]byte{
		pow.block.PrevBlockHash,
		pow.block.Data,
		IntToHex(pow.block.Timestamp),
		IntToHex(nonce),
		IntToHex(targetBits),
	}, []byte{})
	return data
}
func (pow *ProofOfWork) Run() (int64, []byte) {

	var nonce int64
	var hashInt big.Int
	var hash [32]byte

	for nonce < math.MaxInt64 {
		data := pow.prepareData(nonce)
		hash = sha256.Sum256(data)

		hashInt.SetBytes(hash[:])
		if hashInt.Cmp(pow.target) == -1 {
			break
		}
		nonce++
	}
	return nonce, hash[:]
}

func (pow *ProofOfWork) Validata(b *Block) bool {
	var hashInt big.Int
	data := pow.prepareData(b.Nonce)
	hash := sha256.Sum256(data)

	hashInt.SetBytes(hash[:])

	return hashInt.Cmp(pow.target) == -1
}

//영속성
func (b *Block) Serialize() []byte {
	var buf bytes.Buffer

	encoder := gob.NewEncoder(&buf)

	err := encoder.Encode(b)

	if err != nil {
		log.Panic(err)
	}
	return buf.Bytes()
}

func DeserializeBlock(encodedBlock []byte) *Block {
	var buf bytes.Buffer
	var block Block

	buf.Write(encodedBlock)
	decoder := gob.NewDecoder(&buf)

	err := decoder.Decode(&block)
	if err != nil {
		log.Panic(err)
	}
	return &block
}
func NewBlockchainIterator(bc *Blockchain) *blockchainIterator {
	return &blockchainIterator{bc.db, bc.l}
}
func (i *blockchainIterator) Next() *Block {
	var block *Block
	err := i.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BlocksBucks))
		encodedBlock := b.Get(i.hash)
		block = DeserializeBlock(encodedBlock)

		i.hash = block.PrevBlockHash

		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return block
}

//다음블록이 있는지 검사 //제네시스 블록의 이전블록은 없기때문에 제네시스 블록의 값을 활용
func (i *blockchainIterator) HashNext() bool {
	return bytes.Compare(i.hash, []byte{}) != 0
}

//트랜잭션,합의 알고리즘,주소 ,네트워크 등
func main() {
	bc := NewBlockchain()

	bc.AddBlock("send 1 BTC to Ivan")
	bc.AddBlock("send 2 more BTC to Ivan")

	for _, b := range bc.blocks {
		fmt.Printf("PrevBlockHash: %x\n", b.PrevBlockHash)
		fmt.Printf("Hash: %x\n", b.Hash)
		fmt.Printf("PrevBlockHash: %x\n", b.Hash)
		pow := NewProofOfWork(b)
		fmt.Println("pow:", pow.Validata(b))

		fmt.Println()
	}

}
