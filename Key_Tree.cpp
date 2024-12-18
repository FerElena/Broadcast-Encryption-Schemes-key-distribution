#include "Key_Tree.h"

//////////////////////////////////////AUXILIAR FUNCTIONS////////////////////////////////////////////////////////////////

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

void Fill_With_Random(uint8_t* buffer,size_t size) {
    if (BCryptGenRandom(NULL, buffer, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw runtime_error("Error generating random bytes on Windows");
    }
}

#else
#include <fcntl.h>
#include <unistd.h>

void Fill_With_Random(uint8_t* buffer,size_t size) {
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

void printHex(const uint8_t* array, std::size_t size) {
    for (size_t i = 0; i < size; ++i) {
        // Print hex bytes
        cout << hex << setw(2) << setfill('0') << static_cast<int>(array[i]) << " ";
    }
    cout << dec << endl; // back to hex format and end line
}


//////////////////////////////////////PUBLIC METHODS////////////////////////////////////////////////////////////////

Keytree::Keytree(size_t Tree_Depth,size_t node_key_length){
    this->depth = Tree_Depth;
    this->allowed_users.assign(pow(2,depth),true);
    this->Key_length = node_key_length;

    // build the complete binary tree, and asign random keys to each node
    this->FCB_tree.resize(pow(2,depth + 1) - 1); // resize the tree vector to represent the complete binary tree
    if(node_key_length % 8 != 0 || node_key_length > 512)
        throw invalid_argument("invalid key_size for the BES tree");

    for(int i = 0 ; i < this->FCB_tree.size() ; i++){
        FCB_tree[i] = new uint8_t[node_key_length/8];
        Fill_With_Random(FCB_tree[i],node_key_length/8); // assign the key a random value using a cryptographic PRNG
    }

}

Keytree::~Keytree(){
    //free all the memory assigned to node keys
    for(int i = 0 ; i < this->FCB_tree.size() ; i++){
        delete[] FCB_tree[i];
    }
}

int Keytree::denegate_user(unsigned int User_index){
    if(User_index >= allowed_users.size()){
        throw invalid_argument("invalid User Index");
        return -1;
    }
    else{
        allowed_users[User_index] = false;
        return 1;
    }
}

void Keytree::print_KeyTree_info(){
    cout << "KeyTree defined as: " << endl;
    cout << "The depth of the tree is: " << this->depth <<", and the number of users is: " << this->allowed_users.size() << endl;
    for(int i = 0 ; i < this->FCB_tree.size() ; i++){
        cout << "Node " << i <<" with key: ";
        printHex(FCB_tree[i],this->Key_length / 8);
    }
    cout << endl << "The users denegated are:" << endl;
    for(int i = 0 ; i < allowed_users.size(); i++){
        if(!allowed_users[i]){
            cout << "the user: " << i << " at the leaf node: " << i + allowed_users.size() - 1 << " is denegated" << endl;
        }
    }
}
