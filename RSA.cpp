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
	int bin[32], i; // bin : 거듭제곱할 수(암호키&복호키) binary로 나누어 저장할 공간
	r = x; // r에 원문으로 초기화
	i = 0;
	while (H > 0) {
		if (H % 2 == 0)
			bin[i] = 0;
		else
			bin[i] = 1;
		H = H/2;
		i++;
	} // 오른쪽부터 binary로 나누어 저장
	i--; // index이므로 -1
	while (i > 0) { // i번 반복
		r = (r * r) % n; // 거듭제곱 modular 계산
		if (bin[--i] == 1) // 숫자가 1일 때만 modular 계산
			r = (r * x) % n;
	}
	return r; // 결과(암호문&복호문) 출력
}
mint mul_mod(mint a, mint b, mint c) {
	mint x = 0, y = a % c;
	while(b > 0) {
		if (b % 2 == 1) x = (x + y) % c;
		y = (y * 2) % c;
		b /= 2;
	}
	return x % c;
} // overflow에 안전함
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
bool miller_rabin(mint n) { // 소수인지 판별
	if (n < 2) return false; // 2미만은 소수x
	if (n == 2 || n == 3) return true; // 2, 3은 소수
	if (n % 2 == 0 || n % 3 == 0 || n % 5 == 0) return false; // 2,3,5를 약수로 가지므로 소수x
	mint d = n - 1;
	while (d % 2 == 0) d /= 2;
	for (int i = 1; i <= 20; i++) { // test 20번
		bool ch = true;
		mint a = 2 + rand() % (n - 4), temp = d;
		mint x = power_mod(a, temp, n);
		if (x == 1 || x == n - 1) continue; // modular 연산이 1, n-1이 될 경우 소수x
		while(temp!=n-1) {
			x = mul_mod(x, x, n);
			temp *= 2; // 늘려가면서 test
			if (x == 1) return false;
			if (x == n - 1) {
				ch = false;
				break;
			}
		}
		if (ch) return false;
	} // 만약 걸러지지 않았다면
	return true; // 소수가 맞을 것이다.
}
mint extended_euclid(mint u, mint v) { // u의 v에 대한 역원
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
	mint m1 = exp(cipher, dp, p); // m1 : modular 첫번째 계산 결과
	mint m2 = exp(cipher, dq, q); // m2 : modular 두번째 계산 결과
	mint qinv = extended_euclid(q, p); // q의 p에 대한 역원
	mint h = (qinv * (m1 - m2)) % p;
	mint m = m2 + h * q;
	return m; // 계산 결과(복호문)
}
mint gcd(mint a, mint b) { // 최대공약수 구하기
	if (b == 0)
		return a;
	else
		return gcd(b, a % b);
}
mint randInt(mint a, mint b) { // a부터 b까지의 random number
	return rand() % b + a;
}
void keygeneration(mint len) { // key 설정
	p = randInt(pow(2, len - 1), pow(2, len) - 1);
	while (1) {
		if (miller_rabin(p)) // random number가 소수인지 확인
			break;
		p = randInt(pow(2, len - 1), pow(2, len) - 1); // 아닐 때 계속 돌려 소수로 만듦
	}
	q = randInt(pow(2, len - 1), pow(2, len) - 1);
	while (1) {
		if (miller_rabin(q))
			if (q != p) // p와 같지 않게 만듦
				break;
		q = randInt(pow(2, len - 1), pow(2, len) - 1); // 반복
	}
	n = p * q;
	phi = (p - 1) * (q - 1);
	e = randInt(2, phi - 1);
	while (1) {
		if (gcd(phi, e) == 1) // phi와 e가 서로소인지
			break;
		e = randInt(2, phi - 1); // 아닐 때 계속 반복
	}
	d = extended_euclid(e, phi); // e의 phi에 대한 역원
}

/*
A.Square and multiply algorithm for modular exponentiation
	빠른 거듭제곱
B.Miller - Rabin Primality test(테스트는 20회로 설정)
	밀러-라빈 소수판별법
C.Extended Euclidean Algorithm
	확장된 유클리드 알고리즘
D.Chinese Remainder Theorem
	CRT
*/