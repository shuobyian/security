#include <iostream>
#include <fstream>
#include <vector>
using namespace std;

//AES-128
#define Nk 4 // Key Length
#define Nb 4 // Block size
#define Nr 10 // Number of Rounds
//// AES-192
//#define Nk 6
//#define Nb 4
//#define Nr 12
//// AES-256
//#define Nk 8
//#define Nb 4
//#define Nr 14

#define AES_BUFFER 16
#define BYTESIZ 8
#define ELEMENT_S_BOX 256
#define MOD_POLYNOMIAL 0x14D
#define S_MATRIX 0xF1
#define S_ADD_BYTE 0x15

// BYTE : unsigned char WORD : unsigned int
typedef unsigned char byte;
typedef unsigned int word;

void Cipher(vector<byte> in, byte w[]);
void AddRoundKey(byte state[][Nb], int widx);
void SubBytes(byte state[][Nb]);
void ShiftRows(byte state[][Nb]);
void MixColumns(byte state[][Nb]);

void InvCipher(byte in[], byte w[]);
void InvShiftRows(byte state[][Nb]);
void InvSubBytes(byte state[][Nb]);
void InvMixColumns(byte state[][Nb]);

void KeyExpansion(vector<byte> key, byte w[]);
int HIHEX(byte b);
int LOWHEX(byte b);
word x_time(word x);
void CirshiftRows(byte stsate[]);
void InvCirshiftRows(byte state[]);

void make_RCON();
void make_SBOX();
byte calc_inverseByte(byte);
byte calc_S_MATRIX(byte);
//galoisField
void devideByte(word, word);
byte multiplyByte(byte, byte);

byte S_BOX[256];
byte Inv_S_BOX[256];
byte QUO, RMD;
vector<byte> in(4 * Nb);
vector<byte> out; // output
byte Inv_in[4 * Nb];
vector<byte> Inv_out;
byte* RCON;
vector<byte> key(4*Nk);
byte w[176]; // keys


int main(int argc, char **argv) {
	//key
	//argv[1] = "plain.bin" argv[2] = "key.bin"
	if (argc != 3) {
		cout << "Invalid open" << endl;
		exit(1);
	}
	ifstream inFile("plain.bin", ifstream::binary);
	ifstream keyFile("key.bin", ifstream::binary);
	ofstream outFile("cipher.bin", ofstream::binary);
	ofstream out2File("decrypt.bin", ofstream::binary);
	if (!inFile || !keyFile) {
		cout << "file open error" << endl;
		exit(1);
	}
	make_RCON();
	make_SBOX();

	cout << "PLAIN: ";
	for (int i = 0; i < 4 * Nb; i++) {
		inFile.read((char*)&in[i], sizeof(byte)); // plain.bin
		printf("%02x ", in[i]);
	}
	cout << "\nKEY: ";
	for (int i = 0; i < 4 * Nk; i++) {
		keyFile.read((char*)&key[i], sizeof(byte)); // key.bin
		printf("%02x ", key[i]);
	} 
	keyFile.close();

	cout << "\n\nS_BOX" << endl;
	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 16; j++) {
			printf("%02x ", S_BOX[i * 16 + j]);
		} cout << endl;
	}

	cout << "\n<------ ENCRYPTION ------>\n" << endl;
	KeyExpansion(key, w);
	Cipher(in, w);
	cout << "\nCIPHER: ";
	for (int i = 0; i < 4 * Nb; i++) {
		printf("%02x ", out[i]);
	}
	cout << endl;
	for (int i = 0; i < 4 * Nb; i++) {
		outFile.write((char*)&out[i], sizeof(byte)); // cipher.bin
	}
	outFile.close();
	cout << "\n<------ DECRYPTION ------>\n" << endl;
	InvCipher(Inv_in, w);
	cout << "DECRYPTED: ";
	for (int i = 0; i < 4 * Nb; i++) {
		printf("%02x ", Inv_out[i]);
	}
	cout << endl;
	for (int i = 0; i < 4 * Nb; i++) {
		out2File.write((char*)&Inv_out[i], sizeof(byte)); // decrypt.bin
	}
	out2File.close();
}

void Cipher(vector<byte> in, byte w[]) {
	byte state[4][Nb] = {
		in[0],in[4],in[8],in[12],
		in[1],in[5],in[9],in[13],
		in[2],in[6],in[10],in[14],
		in[3],in[7],in[11],in[15]
	};

	cout << "\nRound 0" << endl;
	AddRoundKey(state, 0);
	for (int round = 1; round < Nr; round++) {
		cout << "Round " << round << endl;
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, round * Nb);
	} // round key 0부터 9까지
	cout << "Round 10" << endl;
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, Nr * Nb); // round key 10
	int j = 0;
	for (int i = 0; i < 16; i++) {
		out.push_back(state[j++][i / Nb]); // 암호화한 결과 저장
		Inv_in[i] = out[i]; // 암호화한 결과 복호화할 input에 저장
		if (j == 4) j = 0;
	}
}
void AddRoundKey(byte state[][Nb], int widx) {
	cout << "AR: ";
	for (int i = widx; i < widx + 4; i++) {
		for (int j = 0; j < Nb; j++) {
			state[j][i - widx] = w[i * 4 + j] ^ state[j][i - widx]; // 확장 키와 원래 state XOR
		}
	}
	int j = 0;
	for (int i = 0; i < 16; i++) {
		printf("%02x ", state[j++][i / 4]);
		if (j == 4) j = 0;
	} cout << endl;
}
void SubBytes(byte state[][Nb]) {
	cout << "SB: ";
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < Nb; j++) {
			byte temp = state[i][j];
			state[i][j] = S_BOX[HIHEX(state[i][j]) * 16 + LOWHEX(state[i][j])]; // S_BOX를 통해 값 변환
		}
	int j = 0;
	for (int i = 0; i < 16; i++) {
		printf("%02x ", state[j++][i / 4]);
		if (j == 4) j = 0;
	} cout << endl;
}
void ShiftRows(byte state[][Nb]) {
	cout << "SR: ";
	for (int i = 1; i < 4; i++)
		for (int j = 0; j < i; j++)
			CirshiftRows(state[i]); // shift
	int j = 0;
	for (int i = 0; i < 16; i++) {
		printf("%02x ", state[j++][i / 4]);
		if (j == 4) j = 0;
	} cout << endl;
}
void MixColumns(byte state[][Nb]) {
	cout << "MC: ";
	word temp1, temp2;
	for (int i = 0; i < 4; i++) {
		temp1 = state[0][i];
		temp2 = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
		state[0][i] ^= x_time(state[0][i] ^ state[1][i]) ^ temp2;
		state[1][i] ^= x_time(state[1][i] ^ state[2][i]) ^ temp2;
		state[2][i] ^= x_time(state[2][i] ^ state[3][i]) ^ temp2;
		state[3][i] ^= x_time(state[3][i] ^ temp1) ^ temp2;
		// 0번째, 1번째 / 1번째, 2번째 ... 차례대로 계산
	} // 각각의 column 처리
	int j = 0;
	for (int i = 0; i < 16; i++) {
		printf("%02x ", state[j++][i / 4]);
		if (j == 4) j = 0;
	} cout << endl;
}

void InvCipher(byte in[], byte w[]) {
	byte state[4][Nb] = {
		in[0],in[4],in[8],in[12],
		in[1],in[5],in[9],in[13],
		in[2],in[6],in[10],in[14],
		in[3],in[7],in[11],in[15]
	};

	cout << "Round 0" << endl;
	AddRoundKey(state, Nr * Nb);
	for (int round = Nr - 1; round > 0; round--) {
		cout << "Round " << Nr - round << endl;
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(state, round * Nb);
		InvMixColumns(state);
	} // round key 10부터 1까지
	cout << "Round 10" << endl;
	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(state, 0); // round key 0

	int j = 0;
	for (int i = 0; i < 16; i++) {
		Inv_out.push_back(state[j++][i / 4]); // 복호화한 결과 저장
		if (j == 4) j = 0;
	}
}
void InvSubBytes(byte state[][Nb]) {
	cout << "SB: ";
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < Nb; j++)
			state[i][j] = Inv_S_BOX[HIHEX(state[i][j]) * 16 + LOWHEX(state[i][j])]; // 암호화에서 생성된 Inverse S_BOX를 통해 변환
	int j = 0;
	for (int i = 0; i < 16; i++) {
		printf("%02x ", state[j++][i / 4]);
		if (j == 4) j = 0;
	} cout << endl;
}
void InvShiftRows(byte state[][Nb]) {
	cout << "SR: ";
	for (int i = 1; i < 4; i++)
		for (int j = 0; j < i; j++)
			InvCirshiftRows(state[i]); // shift
	int j = 0;
	for (int i = 0; i < 16; i++) {
		printf("%02x ", state[j++][i / 4]);
		if (j == 4) j = 0;
	} cout << endl;
}
void InvMixColumns(byte state[][Nb]) {
	cout << "MC: ";
	byte a, b, c, d;
	for (int i = 0; i < 4; i++)
	{
		a = state[0][i];
		b = state[1][i];
		c = state[2][i];
		d = state[3][i];

		state[0][i] = multiplyByte(a, 0x0e) ^ multiplyByte(b, 0x0b) ^ multiplyByte(c, 0x0d) ^ multiplyByte(d, 0x09);
		state[1][i] = multiplyByte(a, 0x09) ^ multiplyByte(b, 0x0e) ^ multiplyByte(c, 0x0b) ^ multiplyByte(d, 0x0d);
		state[2][i] = multiplyByte(a, 0x0d) ^ multiplyByte(b, 0x09) ^ multiplyByte(c, 0x0e) ^ multiplyByte(d, 0x0b);
		state[3][i] = multiplyByte(a, 0x0b) ^ multiplyByte(b, 0x0d) ^ multiplyByte(c, 0x09) ^ multiplyByte(d, 0x0e);
	} // 각각의 column을 고정된 수로 다시 되바꿈
	int j = 0;
	for (int i = 0; i < 16; i++) {
		printf("%02x ", state[j++][i / 4]);
		if (j == 4) j = 0;
	} cout << endl;
}

void KeyExpansion(vector<byte> key, byte w[]) {
	cout << "KEY EXPANSION" << endl;
	byte temp[4];
	int t, j, k;
	for (int i = 0; i < 4; i++) {
		w[(i * 4) + 0] = key[(i * 4) + 0];
		w[(i * 4) + 1] = key[(i * 4) + 1];
		w[(i * 4) + 2] = key[(i * 4) + 2];
		w[(i * 4) + 3] = key[(i * 4) + 3];
	} // 처음 key 초기화
	for (int i = 4; i < 4 * (10 + 1); i++) {
		t = (i - 1) * 4;
		temp[0] = w[t + 0];
		temp[1] = w[t + 1];
		temp[2] = w[t + 2];
		temp[3] = w[t + 3];
		if (i % 4 == 0) {
			// right shift
			byte tmp = temp[0];
			temp[0] = temp[1];
			temp[1] = temp[2];
			temp[2] = temp[3];
			temp[3] = tmp;

			//subword - S_BOX를 통해 변환
			temp[0] = S_BOX[HIHEX(temp[0]) * 16 + LOWHEX(temp[0])];
			temp[1] = S_BOX[HIHEX(temp[1]) * 16 + LOWHEX(temp[1])];
			temp[2] = S_BOX[HIHEX(temp[2]) * 16 + LOWHEX(temp[2])];
			temp[3] = S_BOX[HIHEX(temp[3]) * 16 + LOWHEX(temp[3])];

			temp[0] ^= RCON[i / 4]; // RCON 계산
		}
		j = i * 4; k = (i - 4) * 4;
		w[j + 0] = w[k + 0] ^ temp[0];
		w[j + 1] = w[k + 1] ^ temp[1];
		w[j + 2] = w[k + 2] ^ temp[2];
		w[j + 3] = w[k + 3] ^ temp[3];
		// 계속해서 key 연장
	}
	for (int n = 0; n < 11; n++) {
		cout << "Round " << n << ": ";
		for (int m = 0; m < 16; m++) {
			printf("%02x ", w[n * 16 + m]);
		} cout << endl;
	}
}
int HIHEX(byte b) {
	return (0xF0 & b) >> 4; // byte의 high부분 추출
}
int LOWHEX(byte b) {
	return 0x0F & b; // byte의 low부분 추출
}
word x_time(word x) {
	return ((x << 1) & 0xFF) ^ (((x >> 7) & 1) * 0x4D); // carry가 생겼을 때 처리
}
void CirshiftRows(byte state[]) {
	byte temp = state[0];

	state[0] = state[1];
	state[1] = state[2];
	state[2] = state[3];
	state[3] = temp;
} // right shift
void InvCirshiftRows(byte state[]) {
	byte temp = state[3];

	state[3] = state[2];
	state[2] = state[1];
	state[1] = state[0];
	state[0] = temp;
} // left shift
void make_RCON() {
	int i;
	word temp;

	RCON = new byte[Nr];
	RCON[0] = 1;
	for (i = 1; i < Nr; ++i) {
		if ((temp = RCON[i - 1] << 1) > 0xFF) {
			devideByte(temp, MOD_POLYNOMIAL); // polynomial을 이용하여 나눗셈 계산
			RCON[i] = RMD;
		}
		else
			RCON[i] = (byte)temp;
	}
	cout << "RC: ";
	for (int r = 0; r < Nr; r++) {
		printf("%02x ", RCON[r]);
	} cout << endl;
}
void make_SBOX() {
	word _sequence;
	byte _sequenceInverse;

	for (_sequence = 0; _sequence < ELEMENT_S_BOX; ++_sequence) {
		_sequenceInverse = calc_inverseByte(_sequence);
		S_BOX[_sequence] = calc_S_MATRIX(_sequenceInverse); // S_BOX 생성
		Inv_S_BOX[S_BOX[_sequence]] = _sequence; // 이 부분에서 Inverse S_BOX 생성
	}
}
byte calc_inverseByte(byte _byte)
{
	word preRemainder = MOD_POLYNOMIAL, nextRemainder = _byte, preAuxiliary = 0, nextAuxiliary = 1, temp;

	if (!_byte) return _byte;
	while (nextRemainder != 1) {
		devideByte(preRemainder, nextRemainder);
		preRemainder = nextRemainder;
		nextRemainder = RMD;
		temp = nextAuxiliary;
		nextAuxiliary = multiplyByte(nextAuxiliary, QUO) ^ preAuxiliary;
		preAuxiliary = temp;
	} // 나머지가 1이 될 때까지 나누기 반복 (나머지 저장)

	return (byte)nextAuxiliary; // 역원 반환
} // 역원 계산
byte calc_S_MATRIX(byte _invByte)
{
	int numSet, i, j;
	byte matrix = S_MATRIX, resProduct, resCalc = 0;
	for (i = 0; i < BYTESIZ; ++i) {
		numSet = 0;
		resProduct = _invByte & matrix;	// 행렬곱 AND 연산

		for (j = 0; j < BYTESIZ; ++j) {
			if (resProduct & 1)	++numSet;
			resProduct >>= 1;
		}

		if (numSet & 1)	resCalc |= (1 << i);	// 1의 짝,홀수에 따라 Bit SET
		__asm { rol matrix, 1 }	// 다음 행을 위한 Rotate
	}

	return resCalc ^ S_ADD_BYTE;	// S_ADD_BYTE = 0x15 을 XOR 연산 후 리턴
}
void devideByte(word _lhs, word _rhs)
{
	int quotient = 0, _lhsMSB, _rhsMSB = 0;

	while ((_rhs >> _rhsMSB) > 0) ++_rhsMSB;
	while (1) {
		_lhsMSB = 0;
		while ((_lhs >> _lhsMSB) > 0) ++_lhsMSB;
		if (_rhsMSB > _lhsMSB) break;
		_lhs ^= (_rhs << (_lhsMSB - _rhsMSB));
		quotient |= (1 << (_lhsMSB - _rhsMSB));
	}
	QUO = quotient;
	RMD = _lhs;
} // 나눗셈 계산 - 몫(QUO), 나머지(RMD)
byte multiplyByte(byte _lhs, byte _rhs)
{
	word i = 0, sum = 0, LHS = _lhs;

	for (; i < BYTESIZ; ++i) {
		if ((_rhs >> i) & 1)
			sum ^= LHS << i;
	}
	devideByte(sum, MOD_POLYNOMIAL); // polynomial로 나눠 범위를 넘어가지 않게 함

	return RMD;
} // 곱셈 계산 - 나머지(RMD)