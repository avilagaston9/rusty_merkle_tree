# rusty_merkle_tree

Implementation of a simple Merkle Tree in Rust.

## Introduction

Merkle trees are used in distributed systems for efficient data verification. They are efficient because they use hashes instead of full files. Hashes are ways of encoding files that are much smaller than the actual file itself. Currently, their main uses are in peer-to-peer networks such as Tor, Bitcoin, and Git. 

## Purpose

The purpose of this repository is to implement a basic Merkle Tree in Rust as a means of practicing the Rust programming language.

## Features

- The **build_from** method constructs a Merkle Tree from a given list of leaves.
- The **get_root** method retrieves the root hash of the Merkle Tree.
- The **count_leaves** method counts the number of leaves in the Merkle Tree.
- The **add_leaves** method allows for the addition of new leaves to the Merkle Tree.
- The **contains_leaf** method checks if a leaf exists in the Merkle Tree and generates a proof of existence if found.
- The **verify** method verifies the authenticity of a leaf in the Merkle Tree using the provided proof and root hash.
  
## Usage

You can import and use the MerkleTree struct in your Rust code as needed.
```rust
use merkle_tree::MerkleTree;

fn main() {
    // Example usage
    let leaves = vec!["leaf1".to_string(), "leaf2".to_string(), "leaf3".to_string()];
    let merkle_tree = MerkleTree::build_from(leaves).unwrap();
    let root = merkle_tree.get_root();
    println!("Root Hash: {}", root);
}
```
## Validating Proof of Leaf Existence

Once you have generated a proof for the existence of a leaf in the Merkle Tree, you can validate the proof to ensure the integrity and authenticity of the leaf. Here's how you can do it:

1. **Get the Root Hash**: Retrieve the root hash of the Merkle Tree using the `get_root` method.

2. **Verify the Proof**: Use the `verify` method to verify the proof by providing the proof, root hash, leaf hash, and leaf index as arguments. The `verify` method will return `true` if the proof is valid, indicating that the leaf exists in the Merkle Tree.

Example:

```rust
use merkle_tree::MerkleTree;

// Construct the Merkle Tree (previous code)

// Generates the proof
if let (proof, index) = merkle_tree.contains_leaf(leaf1_hash) {
        
  // Verify the proof
  let root = merkle_tree.get_root();
  let is_valid = MerkleTree::verify(proof, root, leaf_hash, leaf_index);
  if is_valid {
      println!("Proof verified successfully. Leaf exists in the Merkle Tree.");
  } else {
      println!("Proof verification failed. Leaf does not exist in the Merkle Tree.");
  }
}
```

## Running Tests

To run tests for this Merkle Tree implementation, you can use the provided Makefile. Simply execute the following command:

```sh
make test
```
## Hash Function

This Merkle Tree implementation utilizes the Keccak256 hash function from the `crypto` crate for hashing leaf nodes and computing the Merkle Tree's internal nodes. Keccak256 is a cryptographic hash function that produces a 256-bit (32-byte) hash value.

