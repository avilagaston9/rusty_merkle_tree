extern crate crypto;

mod node;

use crypto::digest::Digest;
use crypto::sha3::Sha3;
use node::Node;
use std::rc::Rc;

#[derive(Debug, PartialEq)]
pub enum CreationError {
    // Empty input array
    Empty,
    // Incorrect number of fields
    NotPowerOfTwo,
}

pub struct MerkleTree {
    root: Rc<Node>,
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

        let array_of_leaves = Self::get_leaves_nodes(&array);

        let root = Self::build_tree(array_of_leaves);

        Ok(MerkleTree { root })
    }

    pub fn get_root_hash(&self) -> String {
        self.root.get_hash()
    }

    fn get_leaves_nodes(array: &[String]) -> Vec<Rc<Node>> {
        let mut hasher = Sha3::keccak256();

        // Use map to transform each element and collect the results into a new vector
        let hashes: Vec<Rc<Node>> = array
            .iter()
            .map(|elem| {
                hasher.input(elem.as_bytes());
                Rc::new(Node::new_with_hash(hasher.result_str().to_string()))
            })
            .collect();

        hashes
    }

    fn build_tree(mut array: Vec<Rc<Node>>) -> Rc<Node> {
        if array.len() == 1 {
            return array.pop().unwrap();
        }

        let mut parents_array = vec![];

        for chunk in array.chunks(2) {
            parents_array.push(Rc::new(Node::new_parent(
                Rc::clone(&chunk[0]),
                Rc::clone(&chunk[1]),
            )));
        }

        return Self::build_tree(parents_array);
    }
}
