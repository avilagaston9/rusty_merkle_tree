use crypto::digest::Digest;
use crypto::sha3::Sha3;
use std::rc::Rc;

pub struct Node {
    left_child: Option<Rc<Node>>,
    right_child: Option<Rc<Node>>,
    hash: String,
}

impl Node {
    pub fn new_with_hash(hash: String) -> Self {
        Self {
            left_child: None,
            right_child: None,
            hash,
        }
    }
    pub fn new_parent(left_child: Rc<Node>, right_child: Rc<Node>) -> Self {
        let mut hasher = Sha3::keccak256();
        hasher.input((left_child.get_hash() + right_child.get_hash().as_str()).as_bytes());
        Self {
            left_child: Some(left_child),
            right_child: Some(right_child),
            hash: hasher.result_str().to_string(),
        }
    }
    pub fn get_left_child(&self) -> Option<Rc<Node>> {
        if let Some(child) = &self.left_child {
            return Some(Rc::clone(child));
        }
        None
    }
    pub fn get_right_child(&self) -> Option<Rc<Node>> {
        if let Some(child) = &self.right_child {
            return Some(Rc::clone(child));
        }
        None
    }
    pub fn get_hash(&self) -> String {
        self.hash.clone()
    }
}
