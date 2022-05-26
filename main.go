package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"time"
)

//브록들을 체인형태로 연결
//블록헤더에는 해시,난이도,논스,이전블록해시,타임스탬프,머클트리루트
type Block struct {
	PrevBlockHash []byte
	Hash          []byte
	Timestamp     int64
	Data          []byte
}

//새로운블록
func NewBlock(data string, prevBloclHash []byte) *Block {
	block := Block{prevBloclHash, []byte{}, time.Now().Unix(), []byte(data)}
	block.SetHash()

	return &block
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
	blocks []*Block
}

//제네시스 블록을 미리 포함
//첫번쨰 블록
func NewBlockchain() *Blockchain {
	return &Blockchain{[]*Block{NewBlock("Genesis Block", []byte{})}}
}

//블록체인에 새로운 블록 포함
func (bc *Blockchain) AddBlock(data string) {
	block := NewBlock(data, bc.blocks[len(bc.blocks)-1].Hash)
	bc.blocks = append(bc.blocks, block)
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

//트랜잭션,합의 알고리즘,주소 ,네트워크 등
func main() {
	bc := NewBlockchain()

	bc.AddBlock("send 1 BTC to Ivan")
	bc.AddBlock("send 2 more BTC to Ivan")

	for _, b := range bc.blocks {
		fmt.Printf("PrevBlockHash: %x\n", b.PrevBlockHash)
		fmt.Printf("Hash: %x\n", b.Hash)
		fmt.Printf("PrevBlockHash: %x\n", b.Hash)

		fmt.Println()
	}

}
