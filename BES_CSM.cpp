#include "BES_CSM.hpp"

// Constructor for the BES_CSM_scheme class
BES_CSM_scheme::BES_CSM_scheme(size_t Tree_Depth, size_t node_key_length) : Keytree(Tree_Depth, node_key_length){
	for(int i = 0 ; i < FCB_tree.size() ; i++){	
        allowed_keys.push_back(true); // Mark key as allowed to be used at creation
	}
}

// Method to deny access to a user by their user ID
int BES_CSM_scheme::denegate_user(unsigned int userID) {
    if (userID >= allowed_users.size()) {
        throw invalid_argument("Invalid User Index"); // Throws an exception if the user ID is invalid
        return -1;
    } else {
        // Calculate the node key index for the user ID
        int key_index = userID + allowed_users.size() - 1;
        allowed_users[userID] = false; // Deny access to the user

        // Deny the keys which the user has access to
        for (int i = depth; i >= 0; i--) {
            allowed_keys[key_index] = false;
            key_index = get_father_index(key_index);
        }
        return 1;
    }
}

// Method to get the keys for a specific user
int BES_CSM_scheme::get_user_keys(unsigned int userID, vector<unsigned int>& user_keys_id, vector<uint8_t*>& user_keys) {
    if (userID >= allowed_users.size()) {
        throw invalid_argument("Invalid User Index"); // Throws an exception if the user ID is invalid
        return -1;
    }
    // Calculate the node key index for the user ID
    int key_index = userID + allowed_users.size() - 1;
    // Resize vectors for the corresponding tree
    user_keys_id.resize(depth + 1);
    user_keys.resize(depth + 1);

    // Initialize memory for the user keys according to the key size
    for (int i = 0; i <= depth; i++) {
        user_keys[i] = new uint8_t[Key_length / 8];
    }
    // Load the corresponding user keys
    for (int i = depth; i >= 0; i--) {
        user_keys_id[i] = key_index;
        memcpy(user_keys[i], FCB_tree[key_index], Key_length / 8);
        key_index = get_father_index(key_index);
    }
    return 1;
}

// Recursive method to find the allowed keys from a given index
void BES_CSM_scheme::find_allowed_keys(vector<unsigned int>& node_key_ID, vector<uint8_t*>& user_keys, unsigned int index) {
    if (index >= FCB_tree.size()) {
        return; // Stop recursion if the index exceeds the size of the tree
    }
    if (allowed_keys[index] == true) {
        uint8_t *newKey = new uint8_t[Key_length / 8];
        memcpy(newKey, FCB_tree[index], Key_length / 8);
        node_key_ID.push_back(index);
        user_keys.push_back(newKey);
    } else {
        // Recursively call on the left and right children
        find_allowed_keys(node_key_ID, user_keys, get_leftchild_index(index));
        find_allowed_keys(node_key_ID, user_keys, get_rightchild_index(index));
    }
}

// Method to get all the allowed keys for the allowed users
void BES_CSM_scheme::get_allowed_keys(vector<unsigned int>& node_key_ID, vector<uint8_t*>& user_keys) {
    find_allowed_keys(node_key_ID, user_keys, 0); // Call the recursive function from the root
}

