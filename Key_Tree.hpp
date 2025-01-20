#ifndef KEY_TREE_H
#define KEY_TREE_H

/**
 * @file Key_Tree.h
 * @brief File containing the implementation of a complete binary tree used for stateless BES encryption schemes based on trees.
 * The type of Broadcast Encryption Scheme represented by the tree is denoted by the enum BES_Scheme.
 */

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <cmath>
#include <random>
#include <iomanip> // For std::hex and std::setw

using namespace std;


/**
 * @brief Function to fill memory with cryptographically secure random data.
 * 
 * @param buffer Pointer to the memory location to be filled.
 * @param size Size of the memory to be filled in bytes.
 */
void Fill_With_Random(uint8_t* buffer, std::size_t size);

/**
 * @brief Testing function to print a buffer in hexadecimal format.
 * 
 * @param array Pointer to the array of bytes to be printed.
 * @param size Size of the array.
 */
void printHex(const uint8_t* array, std::size_t size);

const size_t scheme_name_size = 20;

/**
 *@brief gets the father of a tree node
 *
*/
inline unsigned int get_father_index(unsigned int index){
	return (index % 2 == 0) ? (index - 1) / 2 : index / 2;
}

/**
 *@brief gets the left child of a tree node
 *
*/
inline unsigned int get_leftchild_index(unsigned int index){
	return index * 2 + 1;	
}

/**
 *@brief gets the right child of a tree node
 *
*/
inline unsigned int get_rightchild_index(unsigned int index){
	return index * 2 + 2;
}
/**
 * @brief Class representing a BES key tree, where each node is assigned a symmetric key, and the users are represented by the leaf nodes.
 */
class Keytree {
protected:
    size_t depth; ///< The total depth of the complete binary tree.
    vector<bool> allowed_users; ///< Vector representing the users allowed or denied access to the communications.
    vector<uint8_t*> FCB_tree; ///< The complete binary tree represented as a vector where each element is the key of the node.
    size_t Key_length; ///< Length of the keys in the nodes of the complete binary tree.

public:
    /**
     * @brief Constructor for the Keytree class.
     * 
     * @param Tree_Depth The depth of the new tree.
     * @param node_key_length The length of the node keys in bits.
     */
    Keytree(size_t Tree_Depth, size_t node_key_length);

    /**
     * @brief Destructor for the Keytree class.
     */
    ~Keytree();

    /**
     * @brief Testing method to print information about the KeyTree.
     */
    void print_KeyTree_info();

    /**
     * @brief Get the number of users in this scheme.
     * 
     * @return The number of users.
     */
    unsigned int get_numberof_users();

    /**
     * @brief Get the depth of the complete binary tree.
     * 
     * @return The depth of the tree.
     */
    size_t get_depth();
};

#endif // KEY_TREE_H

