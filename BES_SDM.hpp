/**
 * @file file implementating the Subset Diference Method for symetric BES as defined in https://eprint.iacr.org/2001/059.pdf
 * 
 */
#ifndef BES_SDM_H
#define BES_SDM_H

#include "Key_Tree.hpp"
#include "DRBG_AES.hpp"

/**
 *@brief struct representing a subset group in the SDM scheme
 *
 */
typedef struct key_subset
{
    unsigned int high_node;
    unsigned int low_node;
} Key_subset;

/**
 *@brief params used by get_allowed_keys to diferentiate between nodes
 *
 */
const char O_node = 0; // Operative user
const char D_node = 1; // Denied user
const char S_node = 2; // Semi operative node

/**
 * @class BES_SDM_scheme
 * @brief Class representing a Subset Difference Broadcast Encryption Scheme (BES) which inherits from Keytree.
 */
class BES_SDM_scheme : public Keytree
{
private:
    /** 
     * @brief key for the special case where all users are allowed
     *
     */
    uint8_t all_users_allowed_key[32];

    /*!
     * @brief Finds the path between a leaf and a node.
     *
     * @param leaf_node_index The index of the leaf node.
     * @param root_node_index The index of the root node.
     * @param path Vector to store the path.
     * @return 1 if the path is found, -1 if the leaf and root nodes are the same.
     */
    int find_path(unsigned int leaf_node_index, unsigned int root_node_index, vector<unsigned int> &path);

    /*!
     * @brief Generates a triple-sized key using a Deterministic Random Byte Generator (DRBG).
     *
     * @param key_in The input key.
     * @param key_size The size of the input key.
     * @param triple_out Buffer to store the triple-sized key output.
     */
    void drbg_triplesize(uint8_t *key_in, size_t key_size, uint8_t *triple_out);

    /*!
     * @brief Finds the subset and key for a given subtree in the node tree.
     *
     * @param subtree_root_node The index of the subtree root node.
     * @param node_tree Vector representing the structure of the node tree.
     * @param key Buffer to store the derived key.
     * @return An instance of Key_subset containing the high and low nodes of the subset.
     */
    Key_subset find_subset_and_key(int subtree_root_node, vector<char> node_tree, uint8_t *key);

public:
    /**
     * @brief Constructor for a Subset Difference BES scheme.
     *
     * @param Tree_Depth The depth of the tree.
     * @param node_key_length The length of the node keys in bits.
     */
    BES_SDM_scheme(size_t Tree_Depth, size_t node_key_length);

    /**
     * @brief Destructor for a Subset Difference BES scheme.
     */
    ~BES_SDM_scheme() = default;

    /**
     * @brief overwrite output stream operator, so we can write the CSM_tree to a file
     */
    friend ostream& operator << ( ostream& os, const BES_SDM_scheme& obj);

    /**
     * @brief overwrite input stream operator, so we can read the CSM_tree to a file
     */
    friend istream& operator >> ( istream& is, BES_SDM_scheme& obj);

    /*!
     * @brief Denies access to a user by their user ID.
     *
     * @param userID The ID of the user.
     * @return 1 if the user access is successfully denied, -1 if the user ID is invalid.
     * @throws invalid_argument if the user ID is invalid.
     */
    int denegate_user(unsigned int userID);

    /*!
     * @brief Gets the key_labels for a specific user according to the SDM scheme (remark on it gets the key_labels, not the direct keys).
     *
     * @param userID The ID of the user.
     * @param user_labels_id Vector to store the user's labels subset IDs.
     * @param user_labels Vector to store the user's labels.
     * @return 1 if the user labels are successfully retrieved, -1 if the user ID is invalid.
     * @throws invalid_argument if the user ID is invalid.
     */
    int get_user_labels(unsigned int userID, vector<Key_subset> &user_labels_id, vector<uint8_t *> &user_labels);

    /*!
     * @brief Gets the allowed keys for operative users in the system.
     *
     * @param user_keys_id Vector to store the key subset IDs.
     * @param user_keys Vector to store the keys.
     */
    void get_allowed_keys(vector<Key_subset> &user_keys_id, vector<uint8_t *> &user_keys);
};

#endif
