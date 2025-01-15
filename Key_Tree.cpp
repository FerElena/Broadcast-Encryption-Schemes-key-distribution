#include "Key_Tree.hpp"

////////////////////////////////////// AUXILIARY FUNCTIONS ////////////////////////////////////////////////

// If compiling on Windows, include necessary headers and libraries for random number generation
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

// Function to fill a buffer with random bytes using Windows' cryptographic random number generator
void Fill_With_Random(uint8_t* buffer, size_t size) {
    if (BCryptGenRandom(NULL, buffer, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw runtime_error("Error generating random bytes on Windows");
    }
}

#else
// If compiling on a Unix-like system, include necessary headers for random number generation
#include <fcntl.h>
#include <unistd.h>

// Function to fill a buffer with random bytes using /dev/urandom
void Fill_With_Random(uint8_t* buffer, size_t size) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        throw runtime_error("Error opening /dev/urandom");
    }

    ssize_t result = read(fd, buffer, size);
    if (result < 0 || static_cast<size_t>(result) != size) {
        close(fd);
        throw runtime_error("Error reading from /dev/urandom");
    }

    close(fd);
}
#endif

// Function to print a buffer in hexadecimal format
void printHex(const uint8_t* array, std::size_t size) {
    for (size_t i = 0; i < size; ++i) {
        // Print each byte as a two-digit hexadecimal number
        cout << hex << setw(2) << setfill('0') << static_cast<int>(array[i]) << " ";
    }
    cout << dec << endl; // Switch back to decimal format and end the line
}

////////////////////////////////////// PUBLIC METHODS ////////////////////////////////////////////////

// Constructor for Keytree class
Keytree::Keytree(size_t Tree_Depth, size_t node_key_length) {
    this->depth = Tree_Depth; // Set the depth of the tree
    this->allowed_users.assign(pow(2, depth), true); // Initialize allowed_users with true values
    this->Key_length = node_key_length; // Set the key length

    // Resize the tree vector to represent the complete binary tree and assign random keys to each node
    this->FCB_tree.resize(pow(2, depth + 1) - 1);
    if (node_key_length % 8 != 0 || (node_key_length != 256 && node_key_length != 192 && node_key_length != 128))
        throw invalid_argument("Invalid key_size for the BES tree");

    for (int i = 0; i < this->FCB_tree.size(); i++) {
        FCB_tree[i] = new uint8_t[node_key_length / 8];
        Fill_With_Random(FCB_tree[i], node_key_length / 8); // Assign a random value to the key using a cryptographic PRNG
        allowed_keys.push_back(true); // Mark key as allowed to be used at creation
    }
}

// Destructor for Keytree class
Keytree::~Keytree() {
    // Free all the memory assigned to node keys
    for (int i = 0; i < this->FCB_tree.size(); i++) {
        delete[] FCB_tree[i];
    }
}

// Method to print information about the KeyTree
void Keytree::print_KeyTree_info() {
    cout << "KeyTree defined as: " << endl;
    cout << "The depth of the tree is: " << this->depth << ", and the number of users is: " << this->allowed_users.size() << endl;
    for (int i = 0; i < this->FCB_tree.size(); i++) {
        cout << "Node " << i << " with key: ";
        printHex(FCB_tree[i], this->Key_length / 8); // Print the key of each node in hex format
    }
    cout << endl << "The users denied are:" << endl;
    for (int i = 0; i < allowed_users.size(); i++) {
        if (!allowed_users[i]) {
            cout << "The user: " << i << " at the leaf node: " << i + allowed_users.size() - 1 << " is denied" << endl;
        }
    }
}

// Method to get the number of users
unsigned int Keytree::get_numberof_users() {
    return allowed_users.size(); // Return number of users
}

// Method to get the depth of the tree
size_t Keytree::get_depth() {
    return depth; // Return depth of the tree
}

