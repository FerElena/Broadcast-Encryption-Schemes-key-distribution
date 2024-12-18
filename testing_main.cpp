#include "Key_Tree.h"

int main(){
    Keytree myKeyTree(4, 256);

    myKeyTree.denegate_user(0);
    myKeyTree.denegate_user(10);

    myKeyTree.print_KeyTree_info();

}