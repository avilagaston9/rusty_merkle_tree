extern crate crypto;

use crypto::digest::Digest;
use crypto::sha3::Sha3;

#[derive(Debug, PartialEq)]
pub enum CreationError {
    // Empty input array
    Empty,
    // Incorrect number of fields
    NotPowerOfTwo,
}

#[derive(Debug, PartialEq)]
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

    pub fn get_root(&self) -> String { Self::calculate_root(&self.leaves)}

    fn get_leaves(array: &[String]) -> Vec<String> {
        
        let hashes: Vec<String> = array
        .iter()
        .map(|elem| {
                let mut hasher = Sha3::keccak256();
                hasher.input(elem.as_bytes());
                hasher.result_str().to_string()
            })
            .collect();

        hashes
    }

    fn calculate_root(array: &[String]) -> String {
        if array.len() == 1 {
            return array.first().unwrap().clone();
        }

        let mut parents_array = vec![];
        
        for chunk in array.chunks(2) {
            let mut hasher = Sha3::keccak256();
            hasher.input((chunk[0].to_string() + chunk[1].as_str()).as_bytes());
            parents_array.push(hasher.result_str().to_string());
        }

        Self::calculate_root(&parents_array)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn build_from_empty_array() {
        let tree = MerkleTree::build_from(vec![]);
        assert!(tree.is_err());
        assert_eq![tree, Err(CreationError::Empty)];
    }
    #[test]
    fn build_from_two_elements_is_ok() {
        let tree = MerkleTree::build_from(vec!["foo".into(), "bar".into()]);
        assert!(tree.is_ok());
    }
    #[test]
    fn build_from_two_elements_root_is_ok() {
        let tree = MerkleTree::build_from(vec!["foo".into(), "bar".into()]);
        let mut hasher = Sha3::keccak256();
        hasher.input("foo".to_string().as_bytes());
        let hash1 = hasher.result_str();
        let mut hasher = Sha3::keccak256();
        hasher.input("bar".to_string().as_bytes());
        let hash2 = hasher.result_str();
        let mut hasher = Sha3::keccak256();
        hasher.input((hash1 + hash2.as_str()).as_bytes());
        let root = hasher.result_str();

        assert_eq![tree.unwrap().get_root(), root];
    }

    #[test]
    fn build_from_four_elements_root_is_ok() {
        let tree = MerkleTree::build_from(vec!["foo".into(), "bar".into(), "hello".into(), "world!".into()]);

        //manually get the hashes of all inputs
        let mut hasher = Sha3::keccak256();
        hasher.input("foo".to_string().as_bytes());
        let hash1 = hasher.result_str();

        let mut hasher = Sha3::keccak256();
        hasher.input("bar".to_string().as_bytes());
        let hash2 = hasher.result_str();

        let mut hasher = Sha3::keccak256();
        hasher.input("hello".to_string().as_bytes());
        let hash3 = hasher.result_str();

        let mut hasher = Sha3::keccak256();
        hasher.input("world!".to_string().as_bytes());
        let hash4 = hasher.result_str();

        //manually get the hashes of the parents
        let mut hasher = Sha3::keccak256();
        hasher.input((hash1 + hash2.as_str()).as_bytes());
        let root1 = hasher.result_str();

        let mut hasher = Sha3::keccak256();
        hasher.input((hash3 + hash4.as_str()).as_bytes());
        let root2 = hasher.result_str();

        //manually get the root
        let mut hasher = Sha3::keccak256();
        hasher.input((root1 + root2.as_str()).as_bytes());
        let root = hasher.result_str();

        println!("{root}");
        assert!(tree.is_ok());

        assert_eq![tree.unwrap().get_root(), root];
        
    }
}