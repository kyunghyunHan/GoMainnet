package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"time"
)

type Block struct {
	PrevBlockHash []byte
	Hash          []byte
	Timestamp     int64
	Data          []byte
}

func NewBlock(data string, prevBloclHash []byte) *Block {
	block := Block{prevBloclHash, []byte{}, time.Now().Unix(), []byte(data)}
	block.SetHash()

	return &block
}
func (b *Block) SetHash() {
	header := bytes.Join([][]byte{
		b.PrevBlockHash,
		b.Data,
		IntToHex(b.Timestamp),
	}, []byte{})
	hash := sha256.Sum256(header)
	b.Hash = hash[:]

}
func IntToHex(i int64) []byte {
	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.BigEndian, i)
	if err != nil {
		log.Panic(err)
	}

	return buf.Bytes()
}

type Blockchain struct {
	blocks []*Block
}

func NewBlockchain() *Blockchain {
	return &Blockchain{[]*Block{NewBlock("Genesis Block", []byte{})}}
}

func (bc *Blockchain) AddBlock(data string) {
	block := NewBlock(data, bc.blocks[len(bc.blocks)-1].Hash)
	bc.blocks = append(bc.blocks, block)
}

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
