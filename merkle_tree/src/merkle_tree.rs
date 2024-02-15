extern crate crypto;

use crypto::digest::Digest;
use crypto::sha3::Sha3;

#[derive(Debug, PartialEq)]
pub enum CreationError {
    // Empty input array
    Empty,
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
        let leaves = Self::get_leaves(&array);
        Ok(MerkleTree { leaves })
    }

    pub fn get_root(&self) -> String { Self::calculate_root(&Self::resize_leaves(&self.leaves))}
    pub fn count_leaves(&self) -> usize { self.leaves.len()}

    pub fn add_leaves(&mut self, mut new_leaves: Vec<String>) {
        let new_leaves = Self::get_leaves(&mut new_leaves);
        self.leaves.extend(new_leaves);
    }

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

    fn resize_leaves(leaves: &Vec<String>) -> Vec<String>{
        let mut resized_leaves = leaves.clone();
        let mut len = resized_leaves.len();
        while (len & (len - 1)) != 0 {
            resized_leaves.push(resized_leaves.last().unwrap().clone());
            len = resized_leaves.len();
        }
        resized_leaves
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
    fn build_from_one_element_is_ok() {
        let tree = MerkleTree::build_from(vec!["foo".into()]);
        assert!(tree.is_ok());
        let tree = tree.unwrap();
        assert_eq![tree.count_leaves(), 1];
    }
    #[test]
    fn build_from_one_element_root_is_ok() {
        let tree = MerkleTree::build_from(vec!["foo".into()]);
        let mut hasher = Sha3::keccak256();
        hasher.input("foo".to_string().as_bytes());
        let root = hasher.result_str();
        let tree = tree.unwrap();
        assert_eq![tree.count_leaves(), 1];
        assert_eq![tree.get_root(), root];
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

        assert!(tree.is_ok());
        let tree = tree.unwrap();
        assert_eq![tree.count_leaves(), 4];
        assert_eq![tree.get_root(), root];
        
    }
    #[test]
    fn build_from_three_elements_root_is_ok() {
        let tree = MerkleTree::build_from(vec!["foo".into(), "bar".into(), "hello".into()]);
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

        //manually get the hashes of the parents
        let mut hasher = Sha3::keccak256();
        hasher.input((hash1 + hash2.as_str()).as_bytes());
        let root1 = hasher.result_str();

        let mut hasher = Sha3::keccak256();
        hasher.input((hash3.clone() + hash3.as_str()).as_bytes());
        let root2 = hasher.result_str();

        //manually get the root
        let mut hasher = Sha3::keccak256();
        hasher.input((root1 + root2.as_str()).as_bytes());
        let root = hasher.result_str();

        assert!(tree.is_ok());
        let tree = tree.unwrap();
        assert_eq![tree.count_leaves(), 3];
        assert_eq![tree.get_root(), root];
    }
}