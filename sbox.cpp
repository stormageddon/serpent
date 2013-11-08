#include <iostream>
#include <map>

using namespace std;

int sBoxDecimalTable[][16] = { 
	{ 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12},
	{15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4},
	{ 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2},
	{ 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14},
	{ 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13},
	{15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1},
	{ 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0},
	{ 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6}
};
map<string, string> sBoxBitstring[8];
map<string, string> sBoxBitstringInverse[8];

string Bitstring(int num, int length) {
	string result = "";
	while(num > 0) {
		if (num & 1)
			result.append("1");
		else
			result.append("0");

		num >>= 1;
	}

	if (result.length() < length)
		result.append((length - result.length()), '0');

	return result;
}

void Setup(){
	map<string, string> dict;
	map<string, string> inverseDict;
	string index;
	string value;

	for(int x = 0; x < 8; x++) {
		dict.clear();
		inverseDict.clear();
		for(int y = 0; y < 16; y++) {
			index = Bitstring(y, 4);
			value = Bitstring(sBoxDecimalTable[x][y], 4);
			dict[index] = value;
			inverseDict[value] = index;
		}

		sBoxBitstring[x] = dict;
		sBoxBitstringInverse[x] = inverseDict;
	}
}

string S(int box, string input){
	return sBoxBitstring[box%8][input];
}

string SInverse(int box, string output){
	return sBoxBitstringInverse[box%8][output];
}

string SHat(int box, string input){
	string result = "";

	for(int i = 0; i < 32; i++) {
		result.append(S(box, input.substr((4*i), 4)));
	}


	return result;
}

string SHatInverse(int box, string output){
	string result = "";

	for (int i = 0; i < 32; i++) {
		result.append(SInverse(box, output.substr((4*i), 4)));
	}

	return result;
}

string * SBitslice(int box, string words[4][32]){
	static string bitSliceResult[] = {"", "", "", ""};
	string input = "";
	string quad;
	for (int i = 0; i < 32; i++) {
		input.append(words[0][i]);
		input.append(words[1][i]);
		input.append(words[2][i]);
		input.append(words[3][i]);

		quad = S(box, input);

		for (int j = 0; j < 4; j++) {
			bitSliceResult[j] += quad[j];
		}
	}

	return bitSliceResult;
}

string * SBitsliceInverse(int box, string words[][32]){
        static string bitSliceInverseResult[] = {"", "", "", ""};
        string output = "";
        string quad;
        for (int i = 0; i < 32; i++) {
                output.append(words[0][i]);
                output.append(words[1][i]);
                output.append(words[2][i]);
                output.append(words[3][i]);

                quad = SInverse(box, output);

                for (int j = 0; j < 4; j++) {
                        bitSliceInverseResult[j] += quad[j];
                }
        }

        return bitSliceInverseResult;
}

int main(){
	Setup();
	return 0;
}
