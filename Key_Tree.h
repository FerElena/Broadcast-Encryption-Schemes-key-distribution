#ifndef KEY_TREE_H
#define KEY_TREE_H

/**
 * @file Key_Tree.h
 * 
 * @brief File containing the implementation of a complete binary tree used for stateless BES encryption schemes based on trees, the type of
 * Broadcast Encryption Scheme represented by the tree is represented by the enum BES_scheme
 */

#include <iostream>
#include <string>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <cmath>
#include <random>
#include <iomanip> // Para std::hex y std::setw

using namespace std;

//TODO EL ESQUEMA BES HEREDA DE EL KEY TREE
/**
 * @brief enum representing the BES scheme that the FCB_tree is representing
 * CSD-> Complete Subtree Method (stateless)
 * SDM-> Subset Difference Method (stateless)
 * 
typedef enum bes_scheme{
    LKH,
    CSM,
    SDM
}BES_Scheme;

 */


/**
 * @brief Function to fill memory with cryptographically secure random data.
 *  
 * 
 * @param pointer Pointer to the memory location to be filled. * 
 * @param size Size of the memory to be filled in bytes. 
 * 
 */
void Fill_With_Random(uint8_t* buffer, std::size_t size);

class Keytree { // TODO añadir un array de usuarios con información de si el usuario está denegado o no
    private:
        size_t depth;               // the total depth of the complete binary tree
        vector <bool> allowed_users;// vector representing the number of users which are allowed / denegated
        vector <uint8_t*> FCB_tree; // full complete binary tree represented as a vector where each element is the key of the node
        size_t Key_length;          // length of the keys in the nodes of the complete binary tree

    public:

    /**
     * @brief constructor 
     */
    Keytree(size_t Tree_Depth,size_t node_key_length);

    /**
     * @brief destrcutor
     */
    ~Keytree();

    /**
     * @brief testing method, not operational
     */
    void print_KeyTree_info();

    /**
     * @brief testing method, not operational
     */
    int denegate_user(unsigned int User_index);

};

#endif