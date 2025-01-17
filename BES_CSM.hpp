#ifndef BES_CSM_H
#define BES_CSM_H

#include "Key_Tree.hpp"

/**
 * @class BES_CSM_scheme
 * @brief Class representing a Complete Subtree Broadcast Encryption Scheme (BES)(stateless) which inherits from Keytree.
 */
class BES_CSM_scheme : public Keytree {
private:	
	/**
	 * @brief Vector representing the current keys that can be used or are not denied.
	 *
	*/
    vector<bool> allowed_keys;

    /**
     * @brief Auxiliary method to find the current allowed keys in the tree starting from a given index.
     * 
     * @param node_key_ID Vector to store the node key IDs.
     * @param user_keys Vector to store the user keys.
     * @param index The starting index for the search.
     */
    void find_allowed_keys(vector<unsigned int>& node_key_ID, vector<uint8_t*>& user_keys, unsigned int index);

public:
    /**
     * @brief Constructor for a Complete Subtree Difference BES scheme.
     * 
     * @param Tree_Depth The depth of the tree.
     * @param node_key_length The length of the node keys in bits.
     */
    BES_CSM_scheme(size_t Tree_Depth, size_t node_key_length);

    /**
     * @brief Destructor for a Complete Subtree Difference BES scheme.
     */
    ~BES_CSM_scheme() = default;

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
     * @param userID The ID of the user.
     * @param user_keys_id Vector to store the user key IDs.
     * @param user_keys Vector to store the user keys.
     * @return 1 if the keys are successfully retrieved, -1 if the user ID is invalid.
     */
    int get_user_keys(unsigned int userID, vector<unsigned int>& user_keys_id, vector<uint8_t*>& user_keys);

    /**
     * @brief Get the allowed keys that can be used at the moment with the currently allowed users.
     * 
     * @param node_key_ID Vector to store the node key IDs.
     * @param user_keys Vector to store the user keys.
     */
    void get_allowed_keys(vector<unsigned int>& node_key_ID, vector<uint8_t*>& user_keys);
};

#endif
