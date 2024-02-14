extern crate crypto;

use crypto::digest::Digest;
use crypto::sha3::Sha3;

fn main() {
    // Create a Sha3 hasher
    let mut hasher = Sha3::keccak256();

    // Input data
    let data = b"Hello, world!";

    // Feed input data to the hasher
    hasher.input(data);

    // Compute the hash
    let result = hasher.result_str();

    // Print the hash
    println!("Keccak hash: {}", result);
}
