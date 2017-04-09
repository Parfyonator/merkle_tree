mod merkle_tree;

use std::fs;
use merkle_tree::{MerkleTree, Leaf};

fn main() {
    // get paths of files with data
    let paths = fs::read_dir("./db/").unwrap();
    // create vector of Leafs (contain data from files)
    let mut leaf_v: Vec<Box<Leaf>> = Vec::new();

    // fill vector of Leafs with data from files
    for path in paths {
        leaf_v.push(Box::new(Leaf::new(path.unwrap().path().to_str().unwrap())));
    }

    // create tree
    let mut mt = MerkleTree::new(leaf_v);

    // check if the tree is valid
    if mt.validate() {
        println!("Tree is valid. No damaged leaves present.");
    } else {
        println!("Tree is invalid. One or more leaves are damaged.");
    }

    // corrupt the tree
    mt.corrupt_tree();

    // check if the tree is valid
    if mt.validate() {
        println!("Tree is valid. No damaged leaves present.");
    } else {
        println!("Tree is invalid. One or more leaves are damaged.");
    }
}
