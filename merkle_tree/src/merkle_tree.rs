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
    leaves: Vec<[u8; 32]>,
}
impl MerkleTree {
    pub fn build_from(array: Vec<String>) -> Result<MerkleTree, CreationError> {
        if array.is_empty() {
            return Err(CreationError::Empty);
        }
        let leaves = Self::get_leaves(&array);
        Ok(MerkleTree { leaves })
    }

    pub fn get_root(&self) -> [u8;32] {
        Self::calculate_root(&Self::resize_leaves(&self.leaves))
    }
    pub fn count_leaves(&self) -> usize {
        self.leaves.len()
    }

    pub fn add_leaves(&mut self, new_leaves: Vec<String>) {
        let new_leaves = Self::get_leaves(&new_leaves);
        self.leaves.extend(new_leaves);
    }

    /// Checks if a leaf with the given hash exists in the Merkle tree and returns its proof and index.
    pub fn contains_leaf(&mut self, leaf_hash: [u8;32]) -> Option<(Vec<[u8;32]>, usize)> {
        if let Some(index) = self.leaves.iter().position(|x| *x == leaf_hash) {
            Some((
                Self::generate_proof(index, &Self::resize_leaves(&self.leaves), vec![]),
                index,
            ))
        } else {
            None
        }
    }

    pub fn verify(
        proof: Vec<[u8;32]>,
        root: [u8;32],
        mut leaf_hash: [u8;32],
        mut leaf_index: usize,
    ) -> bool {
        for hash in proof {
            if leaf_index % 2 == 0 {
                leaf_hash = Self::calculate_hash(&[leaf_hash, hash].concat());
            } else {
                leaf_hash = Self::calculate_hash(&[hash, leaf_hash].concat());
            }
            leaf_index /= 2;
        }
        leaf_hash == root
    }

    fn generate_proof(leaf_index: usize, leaves: &[[u8;32]], mut proof: Vec<[u8;32]>) -> Vec<[u8;32]> {
        if leaves.len() == 1 {
            return proof;
        }
        //get the sibling index of the current leaf
        let sibling_index = if leaf_index % 2 == 0 {
            leaf_index + 1
        } else {
            leaf_index - 1
        };
        //add the sibling to the proof
        proof.push(leaves[sibling_index]);
        //build the parents array
        let mut parents_array = vec![];
        for chunk in leaves.chunks(2) {
            parents_array.push(Self::calculate_hash(
                &[chunk[0], chunk[1]].concat(),
            ));
        }
        //get the next iteration index
        let new_index = leaf_index / 2;
        //start next iteration
        Self::generate_proof(new_index, &parents_array, proof)
    }

    fn get_leaves(array: &[String]) -> Vec<[u8;32]> {
        let hashes: Vec<[u8;32]> = array
            .iter()
            .map(|elem| Self::calculate_hash(elem.as_bytes()))
            .collect();

        hashes
    }

    fn resize_leaves(leaves: &Vec<[u8;32]>) -> Vec<[u8;32]> {
        let mut resized_leaves = leaves.to_owned();
        let mut len = resized_leaves.len();
        while (len & (len - 1)) != 0 {
            resized_leaves.push(*resized_leaves.last().unwrap());
            len = resized_leaves.len();
        }
        resized_leaves
    }   

    fn calculate_root(array: &[[u8;32]]) -> [u8;32] {
        if array.len() == 1 {
            return *array.first().unwrap();
        }
        //build the parents array
        let mut parents_array = vec![];
        for chunk in array.chunks(2) {
            parents_array.push(Self::calculate_hash(
                &[chunk[0], chunk[1]].concat(),
            ));
        }

        Self::calculate_root(&parents_array)
    }

    fn calculate_hash(input: &[u8]) -> [u8;32] {
        let mut hasher = Sha3::keccak256();
        hasher.input(input);
        let mut output = [0; 32];
        hasher.result(&mut output);
        output
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn calculate_hash(input: &[u8]) -> [u8;32] {
        let mut hasher = Sha3::keccak256();
        hasher.input(input);
        let mut output = [0; 32];
        hasher.result(&mut output);
        output
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
        let root = calculate_hash("foo".as_bytes());

        let tree = MerkleTree::build_from(vec!["foo".into()]);
        let tree = tree.unwrap();

        assert_eq![tree.count_leaves(), 1];
        assert_eq![tree.get_root(), root];
    }

    #[test]
    fn build_from_four_elements_root_is_ok() {
        //manually get the hashes of all inputs
        let foo_hash = calculate_hash("foo".as_bytes());
        let bar_hash = calculate_hash("bar".as_bytes());
        let hello_hash = calculate_hash("hello".as_bytes());
        let world_hash = calculate_hash("world!".as_bytes());

        //manually get the hashes of the parents
        let root1 = calculate_hash(&[foo_hash, bar_hash].concat());
        let root2 = calculate_hash(&[hello_hash, world_hash].concat());

        //manually get the root
        let root = calculate_hash(&[root1, root2].concat());

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
        let foo_hash = calculate_hash("foo".as_bytes());
        let bar_hash = calculate_hash("bar".as_bytes());
        let hello_hash = calculate_hash("hello".as_bytes());

        //manually get the hashes of the parents
        let root1 = calculate_hash(&[foo_hash, bar_hash].concat());
        let root2 = calculate_hash(&[hello_hash, hello_hash].concat());

        //manually get the root
        let root = calculate_hash(&[root1, root2].concat());

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
        let foo_hash = calculate_hash("foo".as_bytes());
        let bar_hash = calculate_hash("bar".as_bytes());
        let hello_hash = calculate_hash("hello".as_bytes());

        //manually get the hashes of the parents
        let root1 = calculate_hash(&[foo_hash, bar_hash].concat());
        let root2 = calculate_hash(&[hello_hash, hello_hash].concat());

        //manually get the final root
        let root = calculate_hash(&[root1, root2].concat());

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
        let foo_hash = calculate_hash("foo".as_bytes());
        let bar_hash = calculate_hash("bar".as_bytes());
        let hello_hash = calculate_hash("hello".as_bytes());

        //manually get the hashes of the parents
        let root1 = calculate_hash(&[foo_hash, bar_hash].concat());
        let root2 = calculate_hash(&[hello_hash, hello_hash].concat());

        //manually get the final root
        let root = calculate_hash(&[root1, root2].concat());

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
        let foo_hash = calculate_hash("foo".as_bytes());
        let bar_hash = calculate_hash("bar".as_bytes());
        let hello_hash = calculate_hash("hello".as_bytes());
        let world_hash = calculate_hash("world!".as_bytes());

        //manually get the hashes of the parents
        let root1 = calculate_hash(&[foo_hash, bar_hash].concat());
        let root2 = calculate_hash(&[hello_hash, world_hash].concat());

        //manually get the root
        let root = calculate_hash(&[root1, root2].concat());

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
        let foo_hash = calculate_hash("foo".as_bytes());
        let bar_hash = calculate_hash("bar".as_bytes());
        let hello_hash = calculate_hash("hello".as_bytes());
        let world_hash = calculate_hash("world!".as_bytes());

        //manually get the hashes of the parents
        let root1 = calculate_hash(&[foo_hash, bar_hash].concat());
        let root2 = calculate_hash(&[hello_hash, world_hash].concat());

        //manually get the root
        let root = calculate_hash(&[root1, root2].concat());

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
    #[test]
    fn generate_proof_three_leaves() {
        //manually get the hashes of all inputs
        let foo_hash = calculate_hash("foo".as_bytes());
        let bar_hash = calculate_hash("bar".as_bytes());
        let hello_hash = calculate_hash("hello".as_bytes());

        //manually get the hashes of the parents
        let root1 = calculate_hash(&[foo_hash, bar_hash].concat());
        let root2 = calculate_hash(&[hello_hash, hello_hash].concat());

        //manually get the root
        let root = calculate_hash(&[root1, root2].concat());

        //build the tree
        let tree = MerkleTree::build_from(vec!["foo".into(), "bar".into(), "hello".into()]);
        let mut tree = tree.unwrap();
        assert_eq![tree.count_leaves(), 3];
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
        assert!(!MerkleTree::verify(proof, root, hello_hash, index));
    }
    #[test]
    fn generate_proof_three_leaves_at_index_two() {
        //manually get the hashes of all inputs
        let foo_hash = calculate_hash("foo".as_bytes());
        let bar_hash = calculate_hash("bar".as_bytes());
        let hello_hash = calculate_hash("hello".as_bytes());

        //manually get the hashes of the parents
        let root1 = calculate_hash(&[foo_hash, bar_hash].concat());
        let root2 = calculate_hash(&[hello_hash, hello_hash].concat());

        //manually get the root
        let root = calculate_hash(&[root1, root2].concat());

        //build the tree
        let tree = MerkleTree::build_from(vec!["foo".into(), "bar".into(), "hello".into()]);
        let mut tree = tree.unwrap();
        assert_eq![tree.count_leaves(), 3];
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
            foo_hash,
            2
        ));
        assert!(!MerkleTree::verify(
            proof.clone(),
            root.clone(),
            bar_hash,
            index
        ));
    }
}
