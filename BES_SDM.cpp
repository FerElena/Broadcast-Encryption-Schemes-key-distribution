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


void BES_SDM_scheme::drbg_triplesize(uint8_t *key_in,size_t key_size, uint8_t *triple_out){	
	aes_stream_state drbg_context;							// context for the deterministic random byte generator used for key derivation
	aes_stream_init(&drbg_context,key_in);					// initializates the DRBG with the input key
	aes_stream(&drbg_context,triple_out,(key_size) * 3);    // triples de output with the DRBG
}

// Method to get the keys for a specific user
int BES_SDM_scheme::get_user_keys(unsigned int userID, vector<Key_subset>& user_keys_id, vector<uint8_t*>& user_keys) {
    if (userID >= allowed_users.size()) {
        throw invalid_argument("Invalid User Index"); // Throws an exception if the user ID is invalid
        return -1;
    }
	Key_subset aux_subset;													// auxiliar struct for adding the key indexs
	unsigned int user_node_index = pow(2,depth) + userID - 1;               // calculate the leaf position in the tree corresponding to the user
	unsigned int current_node_iterator = user_node_index;                   // iterator for move between the leaf and the subtree root node
	unsigned int current_subtree_root = get_father_index(user_node_index) ; // root node of the current subtree
	vector<unsigned int> path;                                              // path from the subtree root, to the leaf node
	uint8_t drbg_output[32 * 3];											// data buffer to triple the output of the DRBG 
	uint8_t iterator_key[32];												// data buffer to iterate the key tree
	uint8_t *ptr_key = nullptr;
	size_t Key_length_bytes = Key_length / 8;

	for(int i = depth ; i > 0 ; i--){ // for each subtree such that the current node leaf is part of
		find_path(current_node_iterator,current_subtree_root,path);
		memcpy(iterator_key,FCB_tree[current_subtree_root],Key_length_bytes);
		for(int j = path.size() -1 ; j > 0 ; j--){                         // add the key with subset: i=current_subtree_root and j = get_right_child(path[j])
			drbg_triplesize(iterator_key,Key_length_bytes, drbg_output);     // derivate the subnodes labels, and the current node key

			if(path[j-1] == get_leftchild_index(path[j])){
				memcpy(iterator_key,drbg_output,Key_length_bytes);
				ptr_key = new uint8_t[Key_length_bytes];
				memcpy(ptr_key,drbg_output + (Key_length_bytes * 2), Key_length / 8);
				aux_subset.low_node = get_rightchild_index(path[j]);  		   
			}
			else{														  //  add the key with subset: i=current_subtree_root and j = get_left_child(path[j])
				memcpy(iterator_key,drbg_output + (Key_length_bytes * 2),Key_length/8);
				ptr_key = new uint8_t[Key_length_bytes];
				memcpy(ptr_key,drbg_output, Key_length_bytes);
				aux_subset.low_node = get_leftchild_index(path[j]);  		   
			}
			aux_subset.high_node = current_subtree_root;
			user_keys_id.push_back(aux_subset);              		  	  // add both high and low index, corresponding to a subset in the SDM scheme
			user_keys.push_back(ptr_key);                             	  // add the corresponding user key to the key vector
		}
		current_subtree_root = get_father_index(current_subtree_root);    // iterate to the next subtree, which is the one rooted as the father of current one
		path.clear();													  // reset the path to calculate the new path
	}
	return 1;
}




