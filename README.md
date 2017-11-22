# HoneyBadger

An abstract, Rust-language, futures-based implementation of HoneyBadgerBFT.

Currently in-progress.

The paper: https://eprint.iacr.org/2016/199.pdf

The python implementation: https://github.com/amiller/HoneyBadgerBFT

## Architecture

While the HoneyBadgerBFT paper goes into detail about exact instantiations of the primitives it needs to function, the architecture of this crate is trait-based, allowing the interfaces to be fulfilled by various instantiations of communication protocols, ACS, and threshold signature schemes.

## Deployment in an actual blockchain

HoneyBadgerBFT effectively reaches agreement for the produced block in an epoch r with up to t malicious participants (3t + 1 <= N).

However, the block produced at an epoch doesn't have any justification for its production. The protocol would have to be extended with an additional signature-collection phase at the end, with the generated threshold signature being
included in the block. 

This will provide justification for each block in the chain, allowing a peer with only the genesis (or latest checkpoint) to synchronize the head of the chain securely.