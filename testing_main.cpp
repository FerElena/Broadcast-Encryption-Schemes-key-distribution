// compilar el código con g++ y la opción -maes para indicar al compilador que utilize las intrucciones de INTEL y AMD de AES
// g++ BES_SDM.cpp BES_CSM.cpp DRBG_AES.cpp testing_main.cpp Key_Tree.cpp -maes

#include "Key_Tree.hpp"
#include "BES_CSM.hpp"
#include "BES_SDM.hpp"

using namespace std;

int main(){
	BES_CSM_scheme BES_CSM_Tree(3 ,256);

	vector <unsigned int> user_keys_id;
	vector <uint8_t*> user_keys;
	BES_CSM_Tree.denegate_user(0);
	BES_CSM_Tree.denegate_user(1);
	BES_CSM_Tree.denegate_user(4);
	BES_CSM_Tree.denegate_user(7);


	BES_CSM_Tree.print_KeyTree_info();
	BES_CSM_Tree.get_user_keys(2,user_keys_id,user_keys);
	
	cout << "el usuario  tiene acceso a las siguientes claves:" << endl;
	for(int i = 0 ; i < user_keys_id.size() ; i++){
		cout << "clave con id: " << user_keys_id[i] << " con valor: ";
		printHex(user_keys[i],32);
		
	}
	user_keys_id.clear();
	user_keys.clear();

	BES_CSM_Tree.get_allowed_keys(user_keys_id,user_keys);
	cout << "las claves que van a ser utilizadas son: " << endl;
	cout << "el tamaño de el vector de claves es: " << user_keys_id.size() << endl;

	for(int i = 0; i < user_keys_id.size(); i++){
		cout << "clave con id: " << user_keys_id[i] << " y valor: ";
		printHex(user_keys[i],32);
	}

	user_keys.clear();
	BES_SDM_scheme BES_SDM_Tree(3 , 256);

	BES_SDM_Tree.denegate_user(0);
	BES_SDM_Tree.denegate_user(1);
	BES_SDM_Tree.denegate_user(4);
	BES_SDM_Tree.denegate_user(7);

	BES_SDM_Tree.print_KeyTree_info();
	
	vector <Key_subset> key_indexes;
	BES_SDM_Tree.get_user_keys(2,key_indexes,user_keys);
	
	cout << "el usuario tiene acceso a las claves:" << endl;

	for(int i = 0 ; i < key_indexes.size() ; i++){
		cout << "index i = " << key_indexes[i].high_node <<" index j = " << key_indexes[i].low_node << "  key : ";
		printHex(user_keys[i],32);
	}

	return 0;
}
