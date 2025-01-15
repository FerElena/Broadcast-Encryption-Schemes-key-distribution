// compilar el código con g++ y la opción -maes para indicar al compilador que utilize las intrucciones de INTEL y AMD de AES
// g++ BES_CSM.cpp testing_main.cpp Key_Tree.cpp  DRBG_AES.cpp BES_SDM.cpp -g -maes

#include "Key_Tree.hpp"
#include "BES_CSM.hpp"

using namespace std;

int main(){
	BES_CSM_scheme BES_Tree(4 ,256);

	vector <unsigned int> user_keys_id;
	vector <uint8_t*> user_keys;
	BES_Tree.denegate_user(0);
	BES_Tree.denegate_user(1);
	BES_Tree.denegate_user(4);
	BES_Tree.denegate_user(7);


	BES_Tree.print_KeyTree_info();
	/*
	BES_Tree.get_user_keys(15,user_keys_id,user_keys);
	
	cout << "el usuario  tiene acceso a las siguientes claves:" << endl;
	for(int i = 0 ; i < user_keys_id.size() ; i++){
		cout << "clave con id: " << user_keys_id[i] << " con valor: ";
		printHex(user_keys[i],32);
		
	}
	*/
	user_keys_id.clear();
	user_keys.clear();

	BES_Tree.get_allowed_keys(user_keys_id,user_keys);
	cout << "las claves que van a ser utilizadas son: " << endl;
	cout << "el tamaño de el vector de claves es: " << user_keys_id.size() << endl;

	for(int i = 0; i < user_keys_id.size(); i++){
		cout << "clave con id: " << user_keys_id[i] << " y valor: ";
		printHex(user_keys[i],32);
	}

	return 0;
}
