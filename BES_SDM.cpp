#include "BES_SDM.hpp"

// Constructor for the BES_SDM_scheme class
BES_SDM_scheme::BES_SDM_scheme(size_t Tree_Depth, size_t node_key_length) 
    : Keytree(Tree_Depth, node_key_length) {}

// Method to deny access to a user by their user ID
int BES_SDM_scheme::denegate_user(unsigned int userID) {
    if (userID >= allowed_users.size()) {
        throw invalid_argument("Invalid User Index"); // Throws an exception if the user ID is invalid
        return -1;
    } else {
        // Calculate the node key index for the user ID
        int key_index = userID + allowed_users.size() - 1;
        allowed_users[userID] = false; // Deny access to the user
        return 1;
    }
}

//finds the path between a leaf and a node
int BES_SDM_scheme::find_path(unsigned int leaf_node_index, unsigned int root_node_index , vector<unsigned int>& path){
	if(leaf_node_index == root_node_index){
		return -1; // both are same node, nothing to be done 
	}
	path.push_back(leaf_node_index); // the leaf node is the first node on the path
	while(leaf_node_index != root_node_index){
		leaf_node_index = get_father_index(leaf_node_index);
		path.push_back(leaf_node_index); // add the node to the path as it is father of the current index
		if(leaf_node_index == 0){ // if we already found the root, stop the while loop
			break;
		}
	}
	return 1; // path found correctly
}

int BES_SDM_scheme::calculate_subset_key(unsigned int i,unsigned int j , uint8_t *key){
	// implementalo con AES DRNG para calcular el label de Sij
}

// Method to get the keys for a specific user
int BES_SDM_scheme::get_user_keys(unsigned int userID, vector<Key_subset>& user_keys_id, vector<uint8_t*>& user_keys) {
	Key_subset aux_subset;
    if (userID >= allowed_users.size()) {
        throw invalid_argument("Invalid User Index"); // Throws an exception if the user ID is invalid
        return -1;
    }
	unsigned int user_node_index = pow(2,depth) + userID - 1;               // calculate the leaf position in the tree corresponding to the user
	unsigned int current_node_iterator = user_node_index;                   // iterator for move between the leaf and the subtree root node
	unsigned int current_subtree_root = get_father_index(user_node_index) ; // root node of the current subtree
	vector<unsigned int> path;                                              // path from the subtree root, to the leaf node

	for(int i = depth ; i > 0 ; i--){ // for ech subtree such that the current node leaf is part of
		find_path(current_node_iterator,current_subtree_root,path);
		for(int j = path.size() -1 ; j > 0 ; j--){
			if(path[j-1] == get_leftchild_index(path[j])){
				// añadir la clave del subgrupo con i = current_subtree_root y j = get_right_child(path[j])
			}
			else{
				// añadir la clave del subgrupo con i = current_subtree_root y j = get_left_child(path[j])
			}
		}
		current_subtree_root = get_father_index(current_subtree_root); // iterate to the next subtree, which is the one rooted as the father of current one
	}
}




