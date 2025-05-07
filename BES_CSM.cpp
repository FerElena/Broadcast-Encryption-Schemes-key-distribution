#include "BES_CSM.hpp"

////////////////////////////////////// PRIVATE METHODS ////////////////////////////////////////////////

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


////////////////////////////////////// PUBLIC METHODS ////////////////////////////////////////////////

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

// Method to get all the allowed keys for the allowed users
void BES_CSM_scheme::get_allowed_keys(vector<unsigned int>& node_key_ID, vector<uint8_t*>& user_keys) {
    find_allowed_keys(node_key_ID, user_keys, 0); // Call the recursive function from the root
}

ostream& operator << (ostream& os, const BES_CSM_scheme& obj) {
    unsigned char scheme_name[scheme_name_size] = "CSM_BES_scheme";

    os.write(reinterpret_cast<const char*>(scheme_name), scheme_name_size); // write the scheme name

    os.write(reinterpret_cast<const char*>(&obj.depth), sizeof(obj.depth)); // write the depth of the tree

    os.write(reinterpret_cast<const char*>(&obj.Key_length), sizeof(obj.Key_length)); // write the Key_length of the tree

    size_t allowed_users_size = obj.allowed_users.size();
    os.write(reinterpret_cast<const char*>(&allowed_users_size), sizeof(size_t)); // write the allowed users vector size

    // logic to translate the bool vector array to normal bytes
    uint8_t byte = 0;
    size_t bit_index = 0;

    for (size_t i = 0; i < allowed_users_size; ++i) {
        if (obj.allowed_users[i]) { // if user is allowed put the bit to 1
            byte |= (1 << (7 - bit_index));
        }
        ++bit_index;
        if (bit_index == 8) {
            os.write(reinterpret_cast<const char*>(&byte), sizeof(byte));
            byte = 0;
            bit_index = 0;
        }
    }
    // Write any remaining bits (if the size is not a multiple of 8)
    if (bit_index != 0) {
        os.write(reinterpret_cast<const char*>(&byte), sizeof(byte));
    }

    size_t allowed_keys_size = obj.allowed_keys.size();
    os.write(reinterpret_cast<const char*>(&allowed_keys_size), sizeof(size_t)); // write the length of total allowed keys

    byte = 0;
    bit_index = 0;
    for (size_t i = 0; i < allowed_keys_size; ++i) {
        if (obj.allowed_keys[i]) { // if key is allowed put the bit to 1
            byte |= (1 << (7 - bit_index));
        }
        ++bit_index;
        if (bit_index == 8) {
            os.write(reinterpret_cast<const char*>(&byte), sizeof(byte));
            byte = 0;
            bit_index = 0;
        }
    }
    // Write any remaining bits (if the size is not a multiple of 8)
    if (bit_index != 0) {
        os.write(reinterpret_cast<const char*>(&byte), sizeof(byte));
    }

    // write all the keys
    for (int i = 0; i < obj.FCB_tree.size(); i++) {
        os.write(reinterpret_cast<const char*>(obj.FCB_tree[i]), obj.Key_length / 8);
    }
    return os;
}

istream& operator >> (istream& is, BES_CSM_scheme& obj) {
    unsigned char scheme_name[scheme_name_size];

    is.read(reinterpret_cast<char*>(scheme_name), scheme_name_size); // read the scheme name

    // verify scheme name
    if (strncmp(reinterpret_cast<const char*>(scheme_name), "CSM_BES_scheme", scheme_name_size) != 0) {
        std::cerr << "Error: Nombre del esquema incorrecto." << std::endl;
        return is;
    }

    is.read(reinterpret_cast<char*>(&obj.depth), sizeof(obj.depth)); // read the depth of the tree

    is.read(reinterpret_cast<char*>(&obj.Key_length), sizeof(obj.Key_length)); // read the Key_length of the tree

    size_t allowed_users_size;
    is.read(reinterpret_cast<char*>(&allowed_users_size), sizeof(size_t)); // read the allowed users vector size
    obj.allowed_users.resize(allowed_users_size);

    // read allowed users vector
    uint8_t byte = 0;
    size_t bit_index = 0;

    for (size_t i = 0; i < allowed_users_size; ++i) {
        if (bit_index == 0) {
            // read next byte
            is.read(reinterpret_cast<char*>(&byte), sizeof(byte));
        }

        obj.allowed_users[i] = (byte & (1 << (7 - bit_index))) != 0; // if bit is 1 write true, else write false
        ++bit_index;

        if (bit_index == 8) {
            bit_index = 0;
        }
    }

    size_t allowed_keys_size;
    is.read(reinterpret_cast<char*>(&allowed_keys_size), sizeof(size_t)); // read allowed_keys size
    obj.allowed_keys.resize(allowed_keys_size);

    byte = 0;
    bit_index = 0;
    for (size_t i = 0; i < allowed_keys_size; ++i) {
        if (bit_index == 0) {
            // read next byte
            is.read(reinterpret_cast<char*>(&byte), sizeof(byte));
        }

        obj.allowed_keys[i] = (byte & (1 << (7 - bit_index))) != 0; // if bit is 1 write true, else write false
        ++bit_index;

        if (bit_index == 8) {
            bit_index = 0;
        }
    }

    // free any old keys in the tree
    for (int i = 0; i < obj.FCB_tree.size(); i++) {
        delete obj.FCB_tree[i];
    }
    // read all keys of the CSM_tree
    obj.FCB_tree.resize(pow(2, obj.depth + 1) - 1);
    for (int i = 0; i < obj.FCB_tree.size(); i++) {
        obj.FCB_tree[i] = new uint8_t[obj.Key_length / 8];
        is.read(reinterpret_cast<char*>(obj.FCB_tree[i]), obj.Key_length / 8);
    }

    return is;
}
