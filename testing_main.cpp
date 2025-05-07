// compile the code with g++ and the -maes option to tell the compiler to use the INTEL and AMD AES instructions
// g++ BES_SDM.cpp BES_CSM.cpp DRBG_AES.cpp testing_main.cpp Key_Tree.cpp -maes

#include <cstdio>// for remove function

#include "Key_Tree.hpp"
#include "BES_CSM.hpp"
#include "BES_SDM.hpp"

using namespace std;

//this main will be used to informally unit test the BES_CSM and BES_SDM schemes, it have memory leaks in key vectors, but does not matter because
//it is only for testing purposes

//function to write a message in one color
const string GREEN = "\033[32m";
const string RED = "\033[31m";
const string BLUE = "\033[34m";
const string BLUE_CYAN = "\033[36m";


void print_color(string message , string color){
	cout << color << message << "\033[37m" << endl;
}

void print_keys_CSM(vector <unsigned int> key_index ,vector <uint8_t*>keys_vector,size_t key_size){
	for(int i = 0 ; i < keys_vector.size() ; i++){
		cout << "key index: " << key_index[i] << " KEY:";
		printHex(keys_vector[i],key_size/8);
	}
}

void print_keys_SDM(vector <Key_subset> key_index ,vector <uint8_t*>keys_vector,size_t key_size){
	for(int i = 0 ; i < keys_vector.size() ; i++){
		cout << "key index high: " << key_index[i].high_node <<" ,key index low: " <<key_index[i].low_node <<  " KEY:";
		printHex(keys_vector[i],key_size/8);
	}
}

void print_labels_SDM(vector <Key_subset> key_index ,vector <uint8_t*>keys_vector,size_t key_size){
	for(int i = 0 ; i < keys_vector.size() ; i++){
		cout << "label index high: " << key_index[i].high_node <<" ,label index low: " <<key_index[i].low_node <<  " LABEL:";
		printHex(keys_vector[i],key_size/8);
	}
}


int main(){
	//testing variables
	vector <uint8_t*> user_keys_CSM;
	vector <unsigned int> key_indexes_CSM;

	/////////////////////////////////////////CSM SCHEME INFORMAL TESTS////////////////////////////////////////////////

	//Creating a new CSM scheme
	print_color("CSM SCHEME UNITARY TESTING",RED);
	print_color("creating a CSM scheme Key_tree",BLUE_CYAN);
	BES_CSM_scheme CSM_scheme(3,256); // 3 is the depth of the tree, 256 is the key length in bits
	print_color("the content of the Keytree is: ",BLUE_CYAN);
	CSM_scheme.print_KeyTree_info();
	print_color("Current allowed keys are: ",BLUE_CYAN);
	CSM_scheme.get_allowed_keys(key_indexes_CSM,user_keys_CSM);
	print_keys_CSM(key_indexes_CSM,user_keys_CSM,256);

	//check functionality deny users
	user_keys_CSM.clear();
	key_indexes_CSM.clear();
	print_color("deniying some users to check deny funcionality:",BLUE_CYAN);
	CSM_scheme.denegate_user(1); // deny user with id 1
	CSM_scheme.denegate_user(2); // deny user with id 2
	CSM_scheme.denegate_user(7); // deny user with id 7
	print_color("The current denied users are:",BLUE_CYAN);
	CSM_scheme.print_KeyTree_info();
	print_color("Current allowed keys are: ",BLUE_CYAN);
	CSM_scheme.get_allowed_keys(key_indexes_CSM,user_keys_CSM);
	print_keys_CSM(key_indexes_CSM,user_keys_CSM,256);

	//check funcionality get keys for a user
	user_keys_CSM.clear();
	key_indexes_CSM.clear();
	CSM_scheme.get_user_keys(0,key_indexes_CSM,user_keys_CSM);
	print_color("Keys for user 0 are:",BLUE_CYAN);
	print_keys_CSM(key_indexes_CSM,user_keys_CSM,256);

	//check functionality store and load a CSM scheme
	ofstream ofs_CSM("CSM_scheme.dat",ios::binary);
	ofs_CSM << CSM_scheme;
	ofs_CSM.close();

	BES_CSM_scheme LOAD_CSM_scheme(3,256);
	ifstream ifs_CSM("CSM_scheme.dat",ios::binary);
	ifs_CSM >> LOAD_CSM_scheme;
	ifs_CSM.close();
	print_color("CSM KeyTree after store and load in different object is: ",BLUE_CYAN);
	LOAD_CSM_scheme.print_KeyTree_info();
	print_color("END OF CSM SCHEME TESTING ",GREEN);
	cout << endl << endl;

	/////////////////////////////////////////SDM SCHEME INFORMAL TESTS////////////////////////////////////////////////

	//testing variables
	vector <uint8_t*> user_keys_SDM;
	vector <Key_subset> key_indexes_SDM;

	//Creating a new SDM scheme
	print_color("SDM SCHEME UNITARY TESTING",RED);
	print_color("creating a SDM scheme Key_tree",BLUE_CYAN);
	BES_SDM_scheme SDM_scheme(3,256); // 3 is the depth of the tree, 256 is the key length in bits
	print_color("the content of the Keytree is: ",BLUE_CYAN);
	SDM_scheme.print_KeyTree_info(); // remember in SDM scheme, the noide keys are labels, not the finally used keys!
	print_color("Current allowed keys are: ",BLUE_CYAN);
	SDM_scheme.get_allowed_keys(key_indexes_SDM,user_keys_SDM);
	print_keys_SDM(key_indexes_SDM,user_keys_SDM,256); //only all users allowed special key should be displayed

	//check functionality deny users
	user_keys_SDM.clear();
	key_indexes_SDM.clear();
	print_color("deniying some users to check deny funcionality:",BLUE_CYAN);
	SDM_scheme.denegate_user(1); // deny user with id 1
	SDM_scheme.denegate_user(2); // deny user with id 2
	SDM_scheme.denegate_user(7); // deny user with id 7
	SDM_scheme.print_KeyTree_info();
	SDM_scheme.get_allowed_keys(key_indexes_SDM,user_keys_SDM);
	print_keys_SDM(key_indexes_SDM,user_keys_SDM,256);

	//check funcionality get labels for a user
	user_keys_SDM.clear();
	key_indexes_SDM.clear();
	SDM_scheme.get_user_labels(0,key_indexes_SDM,user_keys_SDM);
	print_color("labels for user 0 are:",BLUE_CYAN);
	print_keys_SDM(key_indexes_SDM,user_keys_SDM,256);

	//check functionality store and load a SDM scheme
	ofstream ofs_SDM("SDM_scheme.dat",ios::binary);
	ofs_SDM << SDM_scheme;
	ofs_SDM.close();

	BES_SDM_scheme LOAD_SDM_scheme(3,256);
	ifstream ifs_SDM("SDM_scheme.dat",ios::binary);
	ifs_SDM >> LOAD_SDM_scheme;
	ifs_SDM.close();
	print_color("SDM KeyTree after store and load in different object is: ",BLUE_CYAN);
	LOAD_SDM_scheme.print_KeyTree_info();
	print_color("END OF SDM SCHEME TESTING ",GREEN);
	cout << endl << endl;

	remove("mi_arbol.dat");
	remove("CSM_scheme.dat");
	remove("SDM_scheme.dat");
    return 0;
}
