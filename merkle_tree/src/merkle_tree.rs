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

    pub fn get_root(&self) -> String {
        Self::calculate_root(&Self::resize_leaves(&self.leaves))
    }
    pub fn count_leaves(&self) -> usize {
        self.leaves.len()
    }

    pub fn add_leaves(&mut self, new_leaves: Vec<String>) {
        let new_leaves = Self::get_leaves(&new_leaves);
        self.leaves.extend(new_leaves);
    }

    pub fn contains_leaf(&mut self, leaf_hash: String) -> Option<(Vec<String>, usize)> {
        if let Some(index) = self.leaves.iter().position(|x| *x == leaf_hash) {
            Some((Self::generate_proof(index, &self.leaves, vec![]), index))
        } else {
            None
        }
    }

    pub fn verify(
        proof: Vec<String>,
        root: String,
        mut value: String,
        mut value_index: usize,
    ) -> bool {
        for hash in proof {
            if value_index % 2 == 0 {
                value = Self::calculate_hash((value + hash.as_str()).as_str());
            } else {
                value = Self::calculate_hash((hash + value.as_str()).as_str());
            }
            value_index /= 2;
        }
        value == root
    }

    fn generate_proof(leaf_index: usize, leaves: &[String], mut proof: Vec<String>) -> Vec<String> {
        if leaves.len() == 1 {
            return proof;
        }

        let mut parents_array = vec![];

        for chunk in leaves.chunks(2) {
            parents_array.push(Self::calculate_hash(
                (chunk[0].to_string() + chunk[1].as_str()).as_str(),
            ));
        }
        let sibling_index = if leaf_index % 2 == 0 {
            leaf_index + 1
        } else {
            leaf_index - 1
        };
        proof.push(leaves[sibling_index].clone());

        let new_index = leaf_index / 2;
        Self::generate_proof(new_index, &parents_array, proof)
    }

    fn get_leaves(array: &[String]) -> Vec<String> {
        let hashes: Vec<String> = array
            .iter()
            .map(|elem| Self::calculate_hash(elem))
            .collect();

        hashes
    }

    fn resize_leaves(leaves: &[String]) -> Vec<String> {
        let mut resized_leaves = leaves.to_owned();
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
            parents_array.push(Self::calculate_hash(
                (chunk[0].to_string() + chunk[1].as_str()).as_str(),
            ));
        }

        Self::calculate_root(&parents_array)
    }

    fn calculate_hash(input: &str) -> String {
        let mut hasher = Sha3::keccak256();
        hasher.input(input.to_string().as_bytes());
        hasher.result_str()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn calculate_hash(input: &str) -> String {
        let mut hasher = Sha3::keccak256();
        hasher.input(input.to_string().as_bytes());
        hasher.result_str()
    }

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
        let root = calculate_hash("foo");

        let tree = MerkleTree::build_from(vec!["foo".into()]);
        let tree = tree.unwrap();

        assert_eq![tree.count_leaves(), 1];
        assert_eq![tree.get_root(), root];
    }

    #[test]
    fn build_from_four_elements_root_is_ok() {
        //manually get the hashes of all inputs
        let foo_hash = calculate_hash("foo");
        let bar_hash = calculate_hash("bar");
        let hello_hash = calculate_hash("hello");
        let world_hash = calculate_hash("world!");

        //manually get the hashes of the parents
        let root1 = calculate_hash((foo_hash + bar_hash.as_str()).as_str());
        let root2 = calculate_hash((hello_hash + world_hash.as_str()).as_str());

        //manually get the root
        let root = calculate_hash((root1 + root2.as_str()).as_str());

        //build the tree
        let tree = MerkleTree::build_from(vec![
            "foo".into(),
            "bar".into(),
            "hello".into(),
            "world!".into(),
        ]);

        assert!(tree.is_ok());
        let tree = tree.unwrap();
        assert_eq![tree.count_leaves(), 4];
        assert_eq![tree.get_root(), root];
    }
    #[test]
    fn build_from_three_elements_root_is_ok() {
        //manually get the hashes of all inputs
        let foo_hash = calculate_hash("foo");
        let bar_hash = calculate_hash("bar");
        let hello_hash = calculate_hash("hello");

        //manually get the hashes of the parents
        let root1 = calculate_hash((foo_hash + bar_hash.as_str()).as_str());
        let root2 = calculate_hash((hello_hash.clone() + hello_hash.as_str()).as_str());

        //manually get the root
        let root = calculate_hash((root1 + root2.as_str()).as_str());

        //build the tree
        let tree = MerkleTree::build_from(vec!["foo".into(), "bar".into(), "hello".into()]);

        assert!(tree.is_ok());
        let tree = tree.unwrap();
        assert_eq![tree.count_leaves(), 3];
        assert_eq![tree.get_root(), root];
    }
    #[test]
    fn build_from_one_element_adds_two() {
        //manually get the hashes of all inputs
        let foo_hash = calculate_hash("foo");
        let bar_hash = calculate_hash("bar");
        let hello_hash = calculate_hash("hello");

        //manually get the hashes of the parents
        let root1 = calculate_hash((foo_hash.clone() + bar_hash.as_str()).as_str());
        let root2 = calculate_hash((hello_hash.clone() + hello_hash.as_str()).as_str());

        //manually get the final root
        let root = calculate_hash((root1 + root2.as_str()).as_str());

        //build the tree with one element
        let tree = MerkleTree::build_from(vec!["foo".into()]);
        let mut tree = tree.unwrap();

        assert_eq![tree.count_leaves(), 1];
        assert_eq![tree.get_root(), foo_hash];

        //add two
        tree.add_leaves(vec!["bar".into(), "hello".into()]);

        assert_eq![tree.count_leaves(), 3];
        assert_eq![tree.get_root(), root];
    }
    #[test]
    fn build_from_one_element_two_inserts() {
        //manually get the hashes of all inputs
        let foo_hash = calculate_hash("foo");
        let bar_hash = calculate_hash("bar");
        let hello_hash = calculate_hash("hello");

        //manually get the hashes of the parents
        let root1 = calculate_hash((foo_hash.clone() + bar_hash.as_str()).as_str());
        let root2 = calculate_hash((hello_hash.clone() + hello_hash.as_str()).as_str());

        //manually get the final root
        let root = calculate_hash((root1.clone() + root2.as_str()).as_str());

        //build the tree with one element
        let tree = MerkleTree::build_from(vec!["foo".into()]);
        let mut tree = tree.unwrap();
        assert_eq![tree.count_leaves(), 1];
        assert_eq![tree.get_root(), foo_hash];

        //first insert
        tree.add_leaves(vec!["bar".into()]);

        assert_eq![tree.count_leaves(), 2];
        assert_eq![tree.get_root(), root1];

        //second insert
        tree.add_leaves(vec!["hello".into()]);

        assert_eq![tree.count_leaves(), 3];
        assert_eq![tree.get_root(), root];
    }
    #[test]
    fn generate_proof_even_index() {
        //manually get the hashes of all inputs
        let foo_hash = calculate_hash("foo");
        let bar_hash = calculate_hash("bar");
        let hello_hash = calculate_hash("hello");
        let world_hash = calculate_hash("world!");

        //manually get the hashes of the parents
        let root1 = calculate_hash((foo_hash.clone() + bar_hash.as_str()).as_str());
        let root2 = calculate_hash((hello_hash.clone() + world_hash.as_str()).as_str());

        //manually get the root
        let root = calculate_hash((root1 + root2.as_str()).as_str());

        //build the tree
        let tree = MerkleTree::build_from(vec![
            "foo".into(),
            "bar".into(),
            "hello".into(),
            "world!".into(),
        ]);
        let mut tree = tree.unwrap();
        assert_eq![tree.count_leaves(), 4];
        assert_eq![tree.get_root(), root];

        let (proof, index) = tree.contains_leaf(hello_hash.clone()).unwrap();
        assert_eq!(index, 2);
        assert!(MerkleTree::verify(
            proof.clone(),
            root.clone(),
            hello_hash.clone(),
            index
        ));
        assert!(!MerkleTree::verify(
            proof.clone(),
            root.clone(),
            hello_hash,
            3
        ));
        assert!(!MerkleTree::verify(
            proof.clone(),
            root.clone(),
            bar_hash,
            index
        ));
        assert!(!MerkleTree::verify(
            proof.clone(),
            root.clone(),
            world_hash,
            index
        ));
        assert!(!MerkleTree::verify(proof, root, foo_hash, index));
    }
    #[test]
    fn generate_proof_odd_index() {
        //manually get the hashes of all inputs
        let foo_hash = calculate_hash("foo");
        let bar_hash = calculate_hash("bar");
        let hello_hash = calculate_hash("hello");
        let world_hash = calculate_hash("world!");

        //manually get the hashes of the parents
        let root1 = calculate_hash((foo_hash.clone() + bar_hash.as_str()).as_str());
        let root2 = calculate_hash((hello_hash.clone() + world_hash.as_str()).as_str());

        //manually get the root
        let root = calculate_hash((root1 + root2.as_str()).as_str());

        //build the tree
        let tree = MerkleTree::build_from(vec![
            "foo".into(),
            "bar".into(),
            "hello".into(),
            "world!".into(),
        ]);
        let mut tree = tree.unwrap();
        assert_eq![tree.count_leaves(), 4];
        assert_eq![tree.get_root(), root];

        let (proof, index) = tree.contains_leaf(foo_hash.clone()).unwrap();
        assert_eq!(index, 0);
        assert!(MerkleTree::verify(
            proof.clone(),
            root.clone(),
            foo_hash.clone(),
            index
        ));
        assert!(!MerkleTree::verify(
            proof.clone(),
            root.clone(),
            foo_hash,
            3
        ));
        assert!(!MerkleTree::verify(
            proof.clone(),
            root.clone(),
            bar_hash,
            index
        ));
        assert!(!MerkleTree::verify(
            proof.clone(),
            root.clone(),
            world_hash,
            index
        ));
        assert!(!MerkleTree::verify(proof, root, hello_hash, index));
    }
}
