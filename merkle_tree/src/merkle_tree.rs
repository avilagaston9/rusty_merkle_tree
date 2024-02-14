extern crate crypto;

mod node;

use crypto::digest::Digest;
use crypto::sha3::Sha3;

#[derive(Debug, PartialEq)]
pub enum CreationError {
    // Empty input array
    Empty,
    // Incorrect number of fields
    NotPowerOfTwo,
}

pub struct MerkleTree {
    leaves: Vec<String>,
}
impl MerkleTree {
    pub fn build_from(array: Vec<String>) -> Result<MerkleTree, CreationError> {
        if array.is_empty() {
            return Err(CreationError::Empty);
        }
        let len = array.len();
        if (len & (len - 1)) != 0 {
            return Err(CreationError::NotPowerOfTwo);
        }

        let leaves = Self::get_leaves(&array);

        Ok(MerkleTree { leaves })
    }

    pub fn calculate_root(&self) -> String { Self::calculate_root_from_array(&self.leaves)}

    fn get_leaves(array: &[String]) -> Vec<String> {
        let mut hasher = Sha3::keccak256();

        let hashes: Vec<String> = array
            .iter()
            .map(|elem| {
                hasher.input(elem.as_bytes());
                hasher.result_str().to_string()
            })
            .collect();

        hashes
    }

    fn calculate_root_from_array(array: &Vec<String>) -> String {
        if array.len() == 1 {
            return array.first().unwrap().clone();
        }

        let mut hasher = Sha3::keccak256();
        let mut parents_array = vec![];
        
        for chunk in array.chunks(2) {
            hasher.input((chunk[0].to_string() + &chunk[1].as_str()).as_bytes());
            parents_array.push(hasher.result_str().to_string());
        }

        return Self::calculate_root_from_array(&parents_array);
    }
}
