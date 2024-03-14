#define _CRT_SECURE_NO_WARNINGS 1
#include<iostream>
#include"seal/seal.h"
#include"include/examples.h"

using namespace std;
using namespace seal;

class Cipher_Matrix
{
public:
    Ciphertext m;
    size_t col[3] = {0};
    size_t row[3] = {0};
    Cipher_Matrix() {};
    ~Cipher_Matrix() {};

    Cipher_Matrix& operator = (Cipher_Matrix& x)
    {
        col[0] = x.col[0];
        col[1] = x.col[1];
        col[2] = x.col[2];
        row[0] = x.row[0];
        row[1] = x.row[1];
        row[2] = x.row[2];
        m = x.m;
        return *this;
    }
};

void Init_Matrix(Cipher_Matrix& src, int col, int row, int D0, int D1, CKKSEncoder &encoder, Encryptor &encryptor, int slot_count, double scale);

void Replicate1DNew(Cipher_Matrix& src, Cipher_Matrix& destination, int dim, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, RelinKeys relin_keys);

int main()
{
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192*4;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 40, 60 }));

    double scale = pow(2.0, 40);

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

/*--------------------------Matrix Initialize----------------------------------------*/

//The number entered must be a power of two
    int m = 0, l = 0, n = 0;
	cout << "Input the number of columns and rows of the matrix" << endl;
	cin >> m >> l >> n;

    int D0, D1 = 0;
    if (l <= m && l <= n)
    {
        D0 = m, D1 = n;
    }
    else if (l >= m && l >= n)
    {
        D0 = D1 = l;
    }
    else
    {
        m > n ? (D0 = m, D1 = l) : (D0 = l, D1 = n);
    }

    Cipher_Matrix x_cipher1;
    Init_Matrix(x_cipher1, m, l, D0, D1, encoder, encryptor, slot_count, scale);

    Cipher_Matrix x_cipher2;
    Init_Matrix(x_cipher2, l, n, D0, D1, encoder, encryptor, slot_count, scale);

/*--------------------------------Replicate1D----------------------------------------*/
    cout << "    + The scale of x_cipher before Replicate1D: " << log2(x_cipher1.m.scale()) << endl;
    cout << "    + The parm_id of x_cipher before Replicate1D: " << x_cipher1.m.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before Replicate1D: " << x_cipher1.m.coeff_modulus_size() << endl;
    cout << endl;


    Cipher_Matrix Replicate1D_result;
    Replicate1DNew(x_cipher2, Replicate1D_result, 1, encoder, evaluator, gal_keys, relin_keys);
    Replicate1DNew(Replicate1D_result, Replicate1D_result, 0, encoder, evaluator, gal_keys, relin_keys);

    cout << "    + The scale of x_cipher after Replicate1D: " << log2(Replicate1D_result.m.scale()) << endl;
    cout << "    + The parm_id of x_cipher after Replicate1D: " << Replicate1D_result.m.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before Replicate1D: " << Replicate1D_result.m.coeff_modulus_size() << endl;
    

/*-------------------------------Sum1D------------------------------------------------*/
    /*for(int k = log2(D1/x_cipher1.row[0]); k >= 1; k--)
    {
        Ciphertext tmp;
        evaluator.rotate_vector(Replicate1D_result.m, -step*d_dim, gal_keys, tmp);
        evaluator.add_inplace(Replicate1D_result.m, tmp);
        step /= 2;
    }*/

/*----------------------------Print the Result----------------------------------------*/

    Plaintext plain_result_m1;
    vector<double> result;
    decryptor.decrypt(Replicate1D_result.m, plain_result_m1);
    encoder.decode(plain_result_m1, result);
    print_vector(result, 16, 5);

}


void Init_Matrix(Cipher_Matrix& src, int col, int row, int D0, int D1, CKKSEncoder &encoder, Encryptor &encryptor, int slot_count, double scale)
{
    cout << "  Init_Matrix:" << endl;
    src.col[0] = col;
    src.row[0] = row;
    src.col[1] = D0;
    src.row[1] = D1;
    vector<double> input(slot_count, 0.0);
    Plaintext x_plain;
    for (int i = 0; i < col; i++)
    {
        for(int j = 0; j < row; j++)
        {
            input[i * D1 + j] = i * row + j + 1;
        }
    }
    cout << "    + col:" << src.col[0] << " row:" << src.row[0] << endl;
    print_vector(input, 16, 5);
    encoder.encode(input, scale, x_plain);
    encryptor.encrypt(x_plain, src.m);
}


void Replicate1DNew(Cipher_Matrix& src, Cipher_Matrix& destination, int dim, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, RelinKeys relin_keys)
{
    if(dim == 1)
    {
        destination = src;
        int d_dim = src.row[0];
        int D1 = src.row[1];
        int step = 1;
        for(int k = 1; k <= log2(D1/d_dim); k++)
        {
            Ciphertext tmp;
            evaluator.rotate_vector(destination.m, -step*d_dim, gal_keys, tmp);
            evaluator.add_inplace(destination.m, tmp);
            step *= 2;
        }
    }
    else if(dim == 0)
    {
        destination = src;
        int d_dim = src.col[0];
        int D0 = src.col[1];
        int step = 1;
        for(int k = 1; k <= log2(D0/d_dim); k++)
        {
            Ciphertext tmp;
            evaluator.rotate_vector(destination.m, -step * src.col[0] * src.row[1], gal_keys, tmp);
            evaluator.add_inplace(destination.m, tmp);
            step *= 2;
        }
    }
}
