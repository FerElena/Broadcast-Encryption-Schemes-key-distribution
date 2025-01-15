#ifndef BES_SDM_H
#define BES_SDM_H

#include "Key_Tree.hpp"
#include "DRBG_AES.hpp"

/**
 * @class BES_sdM_scheme
 * @brief Class representing a Subset Difference Broadcast Encryption Scheme (BES) which inherits from Keytree.
 */
class BES_SDM_scheme : public Keytree {
private:
    /**
     * @brief Auxiliary method to find the current allowed keys in the tree starting from a given index.
     * 
     */
    void find_allowed_keys(vector<unsigned int>& node_key_ID, vector<uint8_t*>& user_keys, unsigned int index);

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
     * @brief Deny access for keys to a user.
     * 
     * @param userID The ID of the user to be denied access.
     * @return 1 if the user is successfully denied, -1 if the user ID is invalid.
     */
    int denegate_user(unsigned int userID);

    /**
     * @brief Get the corresponding keys for a determined user.
     * 
     */
    int get_user_keys();

    /**
     * @brief Get the allowed keys that can be used at the moment with the currently allowed users.
     * 
     */
    void get_allowed_keys();
};

#endif



