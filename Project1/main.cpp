
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <hash_map>
#include <time.h>
#define _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS

#define CHARSIZE 27

using namespace std;
using namespace stdext;

char charlist[] = { ' ','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z' };
int charfreq[] = { 19, 7, 1, 2, 4, 10, 2, 2, 5, 6, 1, 1, 3, 2, 6, 6, 2, 1, 5, 5, 7, 2, 1, 2, 1, 2, 1 };
vector<string> plaintexts;
vector<string> ciphertext;
hash_map<char,int> unit_frequency_char_position_lists;
hash_map<char, int> key_chars;
hash_map<char, int> key;
hash_map<char, int> offset;
//vector<int> offset;
typedef pair<char, int> MAP_PAIR;
typedef pair<int, int> MAP_IPAIR;
//vector<char> unit_frequency_char_position_lists;

//Generate character-frequency map and assign frequencies to each character
void Generatefrequencymap()
{
	
	for (int i = 0; i < CHARSIZE; i++)
	{
		key_chars[charlist[i]] = charfreq[i];
	}
}

void Readfile()
{
	string myline;
	ifstream myfile("Test 1 Candidate Plaintexts.txt");
	if (myfile.is_open())
	{
		while (getline(myfile, myline))
		{
			cout << myline << '\n';
		}
		myfile.close();
	}
	else
	{
		cout << "Unable to open file";
	}
}

void PopulatePlaintexts()
{
	plaintexts.push_back("dipped ligatured cannier cohabitation cuddling coiffeuses pursuance roper eternizes nullo framable paddlings femur bebop demonstrational tuberculoid theocracy women reappraise oblongatae aphasias loftiness consumptive lip neurasthenically dutchmen grift discredited resourcefulness malfeasants swallowed jogger sayable lewder editorials demimondaine tzaritza arrogations wish indisputable reproduces hygrometries gamuts alight borderlines draggle reconsolidated anemometer rowels staggerers grands nu");
	plaintexts.push_back("rereads predestines equippers cavitation bimolecular lucubrations cabin bettas quiverer prussians cosigner dressier bended dethronement inveigled davenport establish ganges rebroadcast supered bastiles willable abetted motionlessness demonic flatter bunyan securely tippiest tongue aw cotyledonal roomettes underlies miffs inducement overintellectually fertilize spasmodic bacchanal birdbrains decoct snakebite galliard boson headmistress unextended provence weakling pirana fiend lairds argils comma");
	plaintexts.push_back("trawling responsiveness tastiest pulsed restamps telescoping pneuma lampoonist divas theosophists pustules checkrowed compactor conditionals envy hairball footslogs wasteful conjures deadfall stagnantly procure barked balmier bowery vagary beaten capitalized undersized towpath envisages thermoplastic rationalizers professions workbench underarm trudger icicled incisive oilbirds citrins chambrays ungainliness weazands prehardened dims determinants fishskin cleanable henceforward misarranges fine");
	plaintexts.push_back("dean iller playbooks resource anesthetic credibilities nonplus tzetzes incursions stooged envelopments girdling risibility thrum repeaters catheterizing misbestowed cursing malingerers ensconces lippiest accost superannuate slush opinionated rememberer councils mishandling drivels juryless slashers tangent roistering scathing apprenticing fleabite sault achier quantize registrable nobbler sheaf natantly kashmirs dittoes scanned emissivity iodize dually refunded portliest setbacks eureka needines");
	plaintexts.push_back("mammate punners octette asylum nonclinically trotters slant collocation cardiology enchants ledge deregulated bottommost capsulate biotechnologies subtended cloddiest training joneses catafalque fieldmice hostels affect shrimper differentiations metacarpus amebas sweeter shiatsu oncoming tubeless menu professing apostatizing moreover eumorphic casked euphemistically programmability campaniles chickpea inactivates crossing defoggers reassures tableland doze reassembled striate precocious noncomba");

}
	
//Generate Character Map for characters with unit frequency
void Generatemapforunitfrequency()
{
	char charry[] = { 'b','j','k','q','x','z' };
	for (int l = 0; l < plaintexts.size(); l++)
	{
		//['b','j','k','q','x','z'].each do |char|
		for (int j = 0; j < 6 ; j++)
		{
			for (int i = 0; i < plaintexts[l].length(); i++)
			{
				if (plaintexts[l][i] == charry[j])
				{
					if (unit_frequency_char_position_lists[l] == NULL)
					{
						unit_frequency_char_position_lists[l] = {};
						if (unit_frequency_char_position_lists[l][charry] == NULL)
						{
							unit_frequency_char_position_lists[l][charry] = {};
							unit_frequency_char_position_lists.insert(MAP_PAIR(charry[j],l));
						}
					}
					
				}
			}
		}
	}
}

//Generating the random key for ciphertext mapping
void GenerateKey()
{
	srand(time(NULL));
	for (int i = 0; i < CHARSIZE; i++)
	{
		for (int j = 1; j < key_chars[charlist[i]]; j++)
		{
			if (key[charlist[i]] == NULL)
			{
				key[charlist[i]] = {};
				key.insert(MAP_PAIR(charlist[i],rand()%106));
			}
		}
	}
}

//Encrypt chosen plaintext
/*void EncryptPlaintext()
{
	srand(time(NULL));
	int num = rand() % 4;
	for (int i = 0; i < plaintexts[num].length(); i++)
	{
		
		if(offset[plaintexts[num][i]]==NULL)
		{ 
			offset[plaintexts[num][i]] = -1;
			offset[plaintexts[num][i]] = (offset[plaintexts[num][i]] + 1) % key[plaintexts[num][i]]; //size of key?
			//ciphertext.push(key[plaintext[random_pick][i]][offset[plaintext[random_pick][i]]])
			ciphertext.push_back(key[plaintexts[num][i]][offset[plaintexts[num][i]]]); //check

		}
		
		
	}

}*/
void PopulateCiphertext()
{
	string myline;
	ifstream myfile("cipher.txt");
	if (myfile.is_open())
	{
		while (getline(myfile, myline))
		{
			cout << myline << '\n';
			ciphertext.push_back(myline);
		}
		myfile.close();
	}
	else
	{
		cout << "Unable to open file";
	}
}

void DecryptCiphertext()
{  
	vector<int> current_list;
	//srand(time(NULL));
	//int num = rand() % 5;
	int right_plaintext_index = -1;
	for (int i = 0; i < unit_frequency_char_position_lists.size(); i++)
	{
		current_list.push_back(unit_frequency_char_position_lists[i]);
		for (int j = 0; j < current_list.size(); j++)
		{
			vector<string> arr;

				for (int k = 0; k < j; k++)
				{
					arr.push_back(ciphertext[k]);
					//cout<<"here";
				}
			
			if (arr.size() == 1)
			{
				right_plaintext_index = 1;
			}
			
			
		}
	}
	if (right_plaintext_index < 0)
	{
		cout << "Could not decode ciphertext";
	}
	else
	{
		cout << "My plaintext guess is:"<<endl << plaintexts[right_plaintext_index];
	}
}

int main()
{
	cout << "Mashaa Allah.\nYou have been gifted by Allah(SWT) and you can do all of this.\n";
	
	Generatefrequencymap();
	//Readfile();
	cout << "Keep praying and asking for help from Allah(SWT)" << endl;
	PopulatePlaintexts();
	Generatemapforunitfrequency();
	GenerateKey();
	PopulateCiphertext();
	DecryptCiphertext();
	system("pause");
	return 0;
}
