#include <iostream>
#include <cstdlib>
#include <ctime>
#include <time.h>
using namespace std;

typedef unsigned int mint;

mint exp(mint, mint, mint); // modular exponentiation
mint mul_mod(mint, mint, mint);
mint power_mod(mint, mint, mint);
bool miller_rabin(mint); // Primality test
mint extended_euclid(mint, mint); // Extended Euclidean Algorithm
mint crt_decrypt(mint);
mint randInt(mint, mint);
mint gcd(mint, mint);
void keygeneration(mint);
mint p, q, n, phi, e, d;
// 2^14 = 16384, 2^15-1 = 32767

int main() {
	srand(time(NULL));
	keygeneration(15);

	mint input, cipher, decrypt;
	cout << "p = " << p << endl;
	cout << "q = " << q << endl;
	cout << "n = " << n << endl;
	cout << "phi = " << phi << endl;
	cout << "e = " << e << endl;
	cout << "d = " << d << endl;
	cout << "Message Input : ";
	cin >> input;
	cout << "Message = " << input << endl;
	cout << "**Encryption" << endl;
	cipher = exp(input, e, n);
	cout << "cipher = " << cipher << endl;
	cout << "**Decryption" << endl;
	decrypt = crt_decrypt(cipher);
	cout << "decrypted cipher : " << decrypt << endl;
	return 0;
}

mint exp(mint x, mint H, mint n) {
	// Y = x^H mod n
	long h;
	unsigned long long r;
	int bin[32], i; // bin : �ŵ������� ��(��ȣŰ&��ȣŰ) binary�� ������ ������ ����
	r = x; // r�� �������� �ʱ�ȭ
	i = 0;
	while (H > 0) {
		if (H % 2 == 0)
			bin[i] = 0;
		else
			bin[i] = 1;
		H = H/2;
		i++;
	} // �����ʺ��� binary�� ������ ����
	i--; // index�̹Ƿ� -1
	while (i > 0) { // i�� �ݺ�
		r = (r * r) % n; // �ŵ����� modular ���
		if (bin[--i] == 1) // ���ڰ� 1�� ���� modular ���
			r = (r * x) % n;
	}
	return r; // ���(��ȣ��&��ȣ��) ���
}
mint mul_mod(mint a, mint b, mint c) {
	mint x = 0, y = a % c;
	while(b > 0) {
		if (b % 2 == 1) x = (x + y) % c;
		y = (y * 2) % c;
		b /= 2;
	}
	return x % c;
} // overflow�� ������
mint power_mod(mint x, mint y, mint p) {
	mint res = 1;
	x = x % p;
	while (y > 0) {
		if (y % 2 == 1) res = mul_mod(res, x, p);
		y = y / 2;
		x = mul_mod(x, x, p);
	}
	return res % p;
}
bool miller_rabin(mint n) { // �Ҽ����� �Ǻ�
	if (n < 2) return false; // 2�̸��� �Ҽ�x
	if (n == 2 || n == 3) return true; // 2, 3�� �Ҽ�
	if (n % 2 == 0 || n % 3 == 0 || n % 5 == 0) return false; // 2,3,5�� ����� �����Ƿ� �Ҽ�x
	mint d = n - 1;
	while (d % 2 == 0) d /= 2;
	for (int i = 1; i <= 20; i++) { // test 20��
		bool ch = true;
		mint a = 2 + rand() % (n - 4), temp = d;
		mint x = power_mod(a, temp, n);
		if (x == 1 || x == n - 1) continue; // modular ������ 1, n-1�� �� ��� �Ҽ�x
		while(temp!=n-1) {
			x = mul_mod(x, x, n);
			temp *= 2; // �÷����鼭 test
			if (x == 1) return false;
			if (x == n - 1) {
				ch = false;
				break;
			}
		}
		if (ch) return false;
	} // ���� �ɷ����� �ʾҴٸ�
	return true; // �Ҽ��� ���� ���̴�.
}
mint extended_euclid(mint u, mint v) { // u�� v�� ���� ����
	mint inv, u1, u3, v1, v3, t1, t3, q;
	int iter = 1;
	u1 = 1, u3 = u, v1 = 0, v3 = v;
	while (v3 != 0) {
		q = u3 / v3;
		t3 = u3 % v3;
		t1 = u1 + q * v1;
		u1 = v1, v1 = t1, u3 = v3, v3 = t3;
		iter =- iter;
	}
	if (u3 != 1)
		return 0;
	if (iter < 0)
		inv = v - u1;
	else
		inv = u1;
	return inv;
}
mint crt_decrypt(mint cipher) {
	mint dp = d % (p - 1);
	mint dq = d % (q - 1);
	mint m1 = exp(cipher, dp, p); // m1 : modular ù��° ��� ���
	mint m2 = exp(cipher, dq, q); // m2 : modular �ι�° ��� ���
	mint qinv = extended_euclid(q, p); // q�� p�� ���� ����
	mint h = (qinv * (m1 - m2)) % p;
	mint m = m2 + h * q;
	return m; // ��� ���(��ȣ��)
}
mint gcd(mint a, mint b) { // �ִ����� ���ϱ�
	if (b == 0)
		return a;
	else
		return gcd(b, a % b);
}
mint randInt(mint a, mint b) { // a���� b������ random number
	return rand() % b + a;
}
void keygeneration(mint len) { // key ����
	p = randInt(pow(2, len - 1), pow(2, len) - 1);
	while (1) {
		if (miller_rabin(p)) // random number�� �Ҽ����� Ȯ��
			break;
		p = randInt(pow(2, len - 1), pow(2, len) - 1); // �ƴ� �� ��� ���� �Ҽ��� ����
	}
	q = randInt(pow(2, len - 1), pow(2, len) - 1);
	while (1) {
		if (miller_rabin(q))
			if (q != p) // p�� ���� �ʰ� ����
				break;
		q = randInt(pow(2, len - 1), pow(2, len) - 1); // �ݺ�
	}
	n = p * q;
	phi = (p - 1) * (q - 1);
	e = randInt(2, phi - 1);
	while (1) {
		if (gcd(phi, e) == 1) // phi�� e�� ���μ�����
			break;
		e = randInt(2, phi - 1); // �ƴ� �� ��� �ݺ�
	}
	d = extended_euclid(e, phi); // e�� phi�� ���� ����
}

/*
A.Square and multiply algorithm for modular exponentiation
	���� �ŵ�����
B.Miller - Rabin Primality test(�׽�Ʈ�� 20ȸ�� ����)
	�з�-��� �Ҽ��Ǻ���
C.Extended Euclidean Algorithm
	Ȯ��� ��Ŭ���� �˰���
D.Chinese Remainder Theorem
	CRT
*/