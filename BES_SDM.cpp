#include "BES_SDM.hpp"

////////////////////////////////////// PRIVATE METHODS ////////////////////////////////////////////////

// finds the path between a leaf and a node
int BES_SDM_scheme::find_path(unsigned int leaf_node_index, unsigned int root_node_index, vector<unsigned int> &path)
{
    if (leaf_node_index == root_node_index)
    {
        return -1; // both are same node, nothing to be done
    }
    path.push_back(leaf_node_index); // the leaf node is the first node on the path
    while (leaf_node_index != root_node_index)
    {
        leaf_node_index = get_father_index(leaf_node_index);
        path.push_back(leaf_node_index); // add the node to the path as it is father of the current index
        if (leaf_node_index == 0)
        { // if we already found the root, stop the while loop
            break;
        }
    }
    return 1; // path found correctly
}

void BES_SDM_scheme::drbg_triplesize(uint8_t *key_in, size_t key_size, uint8_t *triple_out)
{
    aes_stream_state drbg_context;                         // context for the deterministic random byte generator used for key derivation
    aes_stream_init(&drbg_context, key_in);                // initializates the DRBG with the input key
    aes_stream(&drbg_context, triple_out, (key_size) * 3); // triples de output with the DRBG
}

Key_subset BES_SDM_scheme::find_subset_and_key(int subtree_root_node, std::vector<char> node_tree, uint8_t *key)
{
    uint8_t drbg_output[32 * 3]; // data buffer to triple the output of the DRBG
    uint8_t iterator_key[32];    // data buffer to iterate the key tree
    int current_index = subtree_root_node;
    unsigned int key_length_bytes = Key_length / 8;
    Key_subset KS_to_return;

    memcpy(iterator_key, FCB_tree[current_index], key_length_bytes); // copy the subtree root node key
    while (node_tree[current_index] != D_node)
    {
        if (node_tree[get_leftchild_index(current_index)] == S_node)
        { // if the S node is on the left, iterate in the tree to the left
            drbg_triplesize(iterator_key, key_length_bytes, drbg_output);
            memcpy(iterator_key, drbg_output, key_length_bytes);
            current_index = get_leftchild_index(current_index);
        }
        else if (node_tree[get_rightchild_index(current_index)] == S_node)
        { // if the S node is on the right, iterate in the tree to the right
            drbg_triplesize(iterator_key, key_length_bytes, drbg_output);
            memcpy(iterator_key, drbg_output + (key_length_bytes * 2), key_length_bytes);
            current_index = get_rightchild_index(current_index);
        }
        else
        {
            if (node_tree[get_leftchild_index(current_index)] == D_node)
            {
                drbg_triplesize(iterator_key, key_length_bytes, drbg_output);
                memcpy(iterator_key, drbg_output, key_length_bytes);
                current_index = get_leftchild_index(current_index);
            }
            else if (node_tree[get_rightchild_index(current_index)] == D_node)
            {
                drbg_triplesize(iterator_key, key_length_bytes, drbg_output);
                memcpy(iterator_key, drbg_output + (key_length_bytes * 2), key_length_bytes);
                current_index = get_rightchild_index(current_index);
            }
        }
    }
    KS_to_return.high_node = subtree_root_node;
    KS_to_return.low_node = current_index;
    drbg_triplesize(iterator_key, key_length_bytes, drbg_output);
    memcpy(key, drbg_output + key_length_bytes, key_length_bytes); // key supposed to be allocated from the outside
    return KS_to_return;                                           // everything ok, key also calculated
}

////////////////////////////////////// PUBLIC METHODS ////////////////////////////////////////////////

// Constructor for the BES_SDM_scheme class
BES_SDM_scheme::BES_SDM_scheme(size_t Tree_Depth, size_t node_key_length): Keytree(Tree_Depth, node_key_length) {
    Fill_With_Random(all_users_allowed_key,node_key_length/8);
}

// Method to deny access to a user by their user ID
int BES_SDM_scheme::denegate_user(unsigned int userID)
{
    if (userID >= allowed_users.size())
    {
        throw invalid_argument("Invalid User Index"); // Throws an exception if the user ID is invalid
        return -1;
    }
    else
    {
        // Calculate the node key index for the user ID
        int key_index = userID + allowed_users.size() - 1;
        allowed_users[userID] = false; // Deny access to the user
        return 1;
    }
}

// Method to get the keys for a specific user
int BES_SDM_scheme::get_user_keys(unsigned int userID, vector<Key_subset> &user_keys_id, vector<uint8_t *> &user_keys)
{
    if (userID >= allowed_users.size())
    {
        throw invalid_argument("Invalid User Index"); // Throws an exception if the user ID is invalid
        return -1;
    }
    Key_subset aux_subset;                                                 // auxiliar struct for adding the key indexs
    unsigned int user_node_index = pow(2, depth) + userID - 1;             // calculate the leaf position in the tree corresponding to the user
    unsigned int current_node_iterator = user_node_index;                  // iterator for move between the leaf and the subtree root node
    unsigned int current_subtree_root = get_father_index(user_node_index); // root node of the current subtree
    vector<unsigned int> path;                                             // path from the subtree root, to the leaf node
    uint8_t drbg_output[32 * 3];                                           // data buffer to triple the output of the DRBG
    uint8_t iterator_key[32];                                              // data buffer to iterate the key tree
    uint8_t *ptr_key = nullptr;
    size_t Key_length_bytes = Key_length / 8;

    for (int i = depth; i > 0; i--)
    { // for each subtree such that the current node leaf is part of
        find_path(current_node_iterator, current_subtree_root, path);
        memcpy(iterator_key, FCB_tree[current_subtree_root], Key_length_bytes);
        for (int j = path.size() - 1; j > 0; j--)
        {                                                                 // add the key with subset: i=current_subtree_root and j = get_rightchild_index(path[j])
            drbg_triplesize(iterator_key, Key_length_bytes, drbg_output); // derivate the subnodes labels, and the current node key

            if (path[j - 1] == get_leftchild_index(path[j]))
            {
                memcpy(iterator_key, drbg_output, Key_length_bytes);
                ptr_key = new uint8_t[Key_length_bytes];
                memcpy(ptr_key, drbg_output + (Key_length_bytes * 2), Key_length / 8);
                aux_subset.low_node = get_rightchild_index(path[j]);
            }
            else
            { // add the key with subset: i=current_subtree_root and j = get_leftchild_index(path[j])
                memcpy(iterator_key, drbg_output + (Key_length_bytes * 2), Key_length / 8);
                ptr_key = new uint8_t[Key_length_bytes];
                memcpy(ptr_key, drbg_output, Key_length_bytes);
                aux_subset.low_node = get_leftchild_index(path[j]);
            }
            aux_subset.high_node = current_subtree_root;
            user_keys_id.push_back(aux_subset); // add both high and low index, corresponding to a subset in the SDM scheme
            user_keys.push_back(ptr_key);       // add the corresponding user key to the key vector
        }
        current_subtree_root = get_father_index(current_subtree_root); // iterate to the next subtree, which is the one rooted as the father of current one
        path.clear();                                                  // reset the path to calculate the new path
    }
    return 1;
}

void BES_SDM_scheme::get_allowed_keys(std::vector<Key_subset> &user_keys_id, std::vector<uint8_t *> &user_keys)
{
    unsigned int number_of_nodes = FCB_tree.size();  // number of node in the complete binary tree
    std::vector<char> node_tree(number_of_nodes);    // vector used as the Steiner Tree of FCB_tree for the cover finding algorithm
    Key_subset aux_subset;                           // auxiliar key subset for output user_keys_id vector
    uint8_t *aux_key;                                // ptr to allocate memory for keys
    unsigned int key_length_bytes = Key_length / 8;  // length of the current tree keys in bytes

    //Check if no user is denied, if no user is denied, return all_users_allowed_key, else continue with normal execution of the functionn
    bool all_users_allowed = all_of(this->allowed_users.begin(),this->allowed_users.end(), [](bool v) {return v;});
    if(all_users_allowed){
        Key_subset all_users_key= {0,0};
        user_keys_id.push_back(all_users_key);
        user_keys.push_back(all_users_allowed_key);
        return;
    }
    
    //else, normal functioning:
    for (int i = number_of_nodes / 2, j = 0; i < number_of_nodes; i++, j++)
    { // setup the initial vector representing the binary tree, and initialize leaf nodes
        if (allowed_users[j]) // if user is allowed to acces the system, setup his node as operative node
            node_tree[i] = O_node;
        else                  // else setup node as denegated node
            node_tree[i] = D_node;
    }
    for (int iteration = number_of_nodes / 4; iteration >= 0; iteration /= 2) // for each tree level, excluding the one with the leafs
    {

        for (int index = iteration; index <= iteration * 2; index++)
        {
            if (node_tree[get_leftchild_index(index)] == O_node && node_tree[get_rightchild_index(index)] == O_node) // if both children are allowed nodes
                node_tree[index] = O_node;
            else if (node_tree[get_leftchild_index(index)] == D_node && node_tree[get_rightchild_index(index)] == D_node) // if both children are denied nodes
                node_tree[index] = D_node;
            else if ((node_tree[get_leftchild_index(index)] == D_node && node_tree[get_rightchild_index(index)] == O_node) || (node_tree[get_leftchild_index(index)] == O_node && node_tree[get_rightchild_index(index)] == D_node)) // if either of both child nodes is denied, and the other is operative
                node_tree[index] = S_node;
            else
            {
                if ((node_tree[get_leftchild_index(index)] == S_node && node_tree[get_rightchild_index(index)] == O_node) || (node_tree[get_leftchild_index(index)] == O_node && node_tree[get_rightchild_index(index)] == S_node))
                {
                    node_tree[index] = S_node;
                }
                else if (node_tree[get_leftchild_index(index)] == S_node && node_tree[get_rightchild_index(index)] == D_node)
                {
                    aux_key = new uint8_t[key_length_bytes];
                    aux_subset = find_subset_and_key(get_leftchild_index(index), node_tree, aux_key);
                    user_keys_id.push_back(aux_subset);
                    user_keys.push_back(aux_key);
                    node_tree[index] = D_node;
                }
                else if (node_tree[get_leftchild_index(index)] == D_node && node_tree[get_rightchild_index(index)] == S_node)
                {
                    aux_key = new uint8_t[key_length_bytes];
                    aux_subset = find_subset_and_key(get_rightchild_index(index), node_tree, aux_key);
                    user_keys_id.push_back(aux_subset);
                    user_keys.push_back(aux_key);
                    node_tree[index] = D_node;
                }
                else if (node_tree[get_leftchild_index(index)] == S_node && node_tree[get_rightchild_index(index)] == S_node)
                {
                    // find subset for left path
                    aux_key = new uint8_t[key_length_bytes];
                    aux_subset = find_subset_and_key(get_leftchild_index(index), node_tree, aux_key);
                    user_keys_id.push_back(aux_subset);
                    user_keys.push_back(aux_key);
                    // find subset for right path
                    aux_key = new uint8_t[key_length_bytes];
                    aux_subset = find_subset_and_key(get_rightchild_index(index), node_tree, aux_key);
                    user_keys_id.push_back(aux_subset);
                    user_keys.push_back(aux_key);
                    // update subtree root node
                    node_tree[index] = D_node;
                }
            }
        }
        if (iteration == 0)
        { // base case
            if (node_tree[0] == S_node)
            {
                unsigned char root_left_node = node_tree[get_leftchild_index(iteration)];
                unsigned char root_right_node = node_tree[get_rightchild_index(iteration)];
                if ((root_left_node == S_node && root_right_node == O_node) || (root_left_node == O_node && root_right_node == S_node) || (root_left_node == D_node && root_right_node == O_node) || (root_left_node == O_node && root_right_node == D_node))
                {
                    // find last subset
                    aux_key = new uint8_t[key_length_bytes];
                    aux_subset = find_subset_and_key(iteration, node_tree, aux_key);
                    user_keys_id.push_back(aux_subset);
                    user_keys.push_back(aux_key);
                }
            }
            break;
        }
    }
}

ostream& operator << (ostream& os, const BES_SDM_scheme& obj) {
    unsigned char scheme_name[scheme_name_size] = "SDM_BES_scheme";

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

    // write all the keys
    for (int i = 0; i < obj.FCB_tree.size(); i++) {
        os.write(reinterpret_cast<const char*>(obj.FCB_tree[i]), obj.Key_length / 8);
    }
    return os;
}

istream& operator >> (istream& is, BES_SDM_scheme& obj) {
    unsigned char scheme_name[scheme_name_size];

    is.read(reinterpret_cast<char*>(scheme_name), scheme_name_size); // read the scheme name

    // verify scheme name
    if (strncmp(reinterpret_cast<const char*>(scheme_name), "SDM_BES_scheme", scheme_name_size) != 0) {
        cerr << "Error: Nombre del esquema incorrecto." << std::endl;
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

    // free any old keys in the tree
    for (int i = 0; i < obj.FCB_tree.size(); i++) {
        delete obj.FCB_tree[i];
    }
    // read all keys of the SDM_tree
    obj.FCB_tree.resize(pow(2, obj.depth + 1) - 1);
    for (int i = 0; i < obj.FCB_tree.size(); i++) {
        obj.FCB_tree[i] = new uint8_t[obj.Key_length / 8];
        is.read(reinterpret_cast<char*>(obj.FCB_tree[i]), obj.Key_length / 8);
    }

    return is;
}

