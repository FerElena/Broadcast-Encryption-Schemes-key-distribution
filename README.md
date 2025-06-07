# 🔐 Broadcast Encryption Schemes: Complete Subtree & Subset Difference Methods
This code implements two broadcast encryption schemes, both defined in:  https://eprint.iacr.org/2001/059.pdf 

It does not implement the encryption itelf, but the key generation and state management including user denegation to the scheme, and key distribution.

To compile with g++ the testing main, just execute the command: 
```bash
g++ BES_SDM.cpp BES_CSM.cpp DRBG_AES.cpp testing_main.cpp Key_Tree.cpp -maes

