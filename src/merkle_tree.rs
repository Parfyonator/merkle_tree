extern crate crypto;
extern crate std;

use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;
use std::io::prelude::*;
use std::error::Error;
use std::path::Path;
use std::fs;

pub struct Leaf {
    info: String,
}

impl Leaf {
    pub fn new(filename: &str) -> Leaf {
        let path = Path::new(filename);
        let display = path.display();

        let mut file = match fs::File::open(path) {
            Err(why) => panic!("Can't create Leaf. Couldn't open {}: {}", display, why.description()),
            Ok(file) => file,
        };

        let mut s = std::string::String::new();
        match file.read_to_string(&mut s) {
            Err(why) => panic!("Can't create Leaf. Couldn't read {}: {}", display,why.description()),
            Ok(_) => {},
        }

        Leaf {info: s}
    }

    fn get_info(&self) -> &String {
        &self.info
    }

    fn set_info(&mut self, new_info: String) {
        self.info = new_info;
    }
}

struct Node {
    val: String,
    leaf: Option<Box<Leaf>>,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

impl Node {
    fn new(new_val: String) -> Node {
        Node {
            val: new_val,
            left: None,
            right: None,
            leaf: None,
        }
    }

    fn add_child(&mut self, new_val: String) -> bool {
        match self {
            &mut Node{left: None, ..} => {
                self.left = Some(Box::new(Node::new(new_val)));
                true
            }
            &mut Node{right: None, ..} => {
                self.right = Some(Box::new(Node::new(new_val)));
                true
            }
            _ => false
        }
    }

    fn has_children(&self) -> bool {
        match self {
            &Node{left: None, right: None, ..} => false,
            _ => true,
        }
    }

    fn left(self) -> Option<Box<Node>> {
        self.left
    }

    fn right(self) -> Option<Box<Node>> {
        self.right
    }

    fn hash(self) -> String {
        self.val
    }

    fn compute_hash(&self) -> String {
        let mut sha = Sha256::new();

        match self {
            &Node{left: Some(ref l), right: Some(ref r), ..} => {
                let mut input = String::new();
                input.push_str(&l.val[..]);
                input.push_str(&r.val[..]);
                sha.input_str(&input[..]);
            },
            &Node{left: Some(ref l), ..} => {
                let mut input = String::new();
                input.push_str(&l.val[..]);
                input.push_str(&l.val[..]);
                sha.input_str(&input[..]);
            },
            &Node{right: Some(ref r), ..} => {
                let mut input = String::new();
                input.push_str(&r.val[..]);
                input.push_str(&r.val[..]);
                sha.input_str(&input[..]);
            },
            _ => {},
        };

        sha.result_str()
    }

    fn validate(&self) -> bool {
        match self {
            &Node{left: Some(ref l), right: None, ..} => {
                if !l.validate() {
                    false
                } else {
                    if &self.compute_hash()[..] != &self.val[..] { false } else { true }
                }
            },
            &Node{right: Some(ref r), left: None, ..} => {
                if !r.validate() {
                    false
                } else {
                    if &self.compute_hash()[..] != &self.val[..] { false } else { true }
                }
            },
            &Node{right: Some(ref r), left: Some(ref l), ..} =>{
                if l.validate() && r.validate() {
                    if &self.compute_hash()[..] != &self.val[..] { false } else { true }
                } else {
                    false
                }
            },
            &Node{leaf: Some(ref lf), ..} => {
                let mut sha = Sha256::new();
                sha.input_str(lf.get_info());
                if &sha.result_str()[..] != &self.val[..] { false } else { true }
            },
            _ => true,
        }
    }

    fn corrupt_leaf(&mut self) {
        match self {
            &mut Node{left: Some(ref mut l), ..} => l.corrupt_leaf(),
            &mut Node{right: Some(ref mut r), ..} => r.corrupt_leaf(),
            &mut Node{leaf: Some(ref mut lf), ..} => lf.set_info("You were hacked.".to_string()),
            _ => {},
        }
    }
}

pub struct MerkleTree {
    head: Option<Box<Node>>,
}

impl MerkleTree {
    pub fn new(leaf_v: Vec<Box<Leaf>>) -> MerkleTree {
        let mut v_1: Vec<Box<Node>> = Vec::new();
        let mut v_2: Vec<Box<Node>> = Vec::new();
        let paths = fs::read_dir("./db/").unwrap();

        for lf in leaf_v {
            let mut sha = Sha256::new();
            sha.input_str(lf.get_info());
            let mut n = Box::new(Node::new(sha.result_str()));
            n.leaf = Some(lf);
            v_1.push(n);
        }

        while v_1.len() > 1 {
            loop {
                if v_1.len() == 1 {
                    let n = v_1.pop();
                    let mut new_n = Box::new(Node::new(String::from("")));
                    new_n.left = n;
                    new_n.val = new_n.compute_hash();
                    v_2.push(new_n);
                    break;
                } else if v_1.len() == 0 { break; }

                let n_1 = v_1.pop();
                let n_2 = v_1.pop();
                let mut new_n = Box::new(Node::new(String::from("")));
                new_n.left = n_1;
                new_n.right = n_2;
                new_n.val = new_n.compute_hash();
                v_2.push(new_n);
            }
            v_1.append(&mut v_2);
        }

        MerkleTree{ head: v_1.pop() }
    }

    pub fn validate(&self) -> bool {
        match self.head {
            Some(ref n) => n.validate(),
            _ => true,
        }
    }

    pub fn corrupt_tree(&mut self) {
        match self.head {
            Some(ref mut n) => n.corrupt_leaf(),
            _ => {},
        }
    }
}
