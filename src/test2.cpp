#define _CRT_SECURE_NO_WARNINGS 1
#include<iostream>
#include"seal/seal.h"
#include"include/examples.h"

using namespace std;
using namespace seal;

int main()
{
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192*2;
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

    int m = 0, l = 0;
	cout << "Input the number of columns and rows of the matrix" << endl;
	cin >> m >> l;

    vector<double> input(slot_count, 0.0);
    Plaintext x_plain;
    Ciphertext x_cipher;
    for (int i = 0; i < m * l ; i++)
    {
        input[i] = i + 1;
    }
    encoder.encode(input, scale, x_plain);
    encryptor.encrypt(x_plain, x_cipher);

/*---------------------------Create Us slot--------------------------------------*/
/*this for loop is not necessary*/
    int n = m * l;
    vector<double> Us(slot_count * slot_count, 0.0);
    for(int i = 0; i < m; i++)
    {
        for(int j = 0; j < l; j++)
        {
            int k = (l * i + (i + j) % l);
            Us[n * (l * i + j) + k] = 1;
        }
    }
    print_vector(Us, 16, 5);

/*--------------------------------RotateAlign----------------------------------------*/

    Ciphertext rotateAlign_result;
    if(m != 1 && l != 1)
    {
        /*the ciphertext in this code block need to rescale.*/
        evaluator.rotate_vector(x_cipher, -l+1, gal_keys, rotateAlign_result);

        Plaintext Usk_plain_1;
        vector<double> Usk_1(slot_count, 0.0);
        int flag = 0;
        for(int i = 0; i < n; i++)
        {
            Usk_1[i] = Us[i * n + (i + (n - l + 1)) % n];
            //if(Usk_1[i] == 1) flag = 1;
        }
        //print_vector(Usk_1, 16, 5);
        encoder.encode(Usk_1, scale, Usk_plain_1);
        evaluator.multiply_plain_inplace(rotateAlign_result, Usk_plain_1);

        for(int k = -l+2; k < l; k++)
        {
            flag = 0;
            Ciphertext tmp;
            evaluator.rotate_vector(x_cipher, k, gal_keys, tmp);

            Plaintext Usk_plain;
            vector<double> Usk(slot_count, 0.0);
            for(int i = 0; i < n; i++)
            {
                Usk[i] = Us[i * n + (i + (n + k)) % n];
                if(Usk[i] == 1) flag = 1;
            }
            if(flag == 0) continue;
            //print_vector(Usk, 16, 5);
            encoder.encode(Usk, scale, Usk_plain);
            evaluator.multiply_plain_inplace(tmp, Usk_plain);
            evaluator.add_inplace(rotateAlign_result, tmp);
        }
    }
    else{
        rotateAlign_result = x_cipher;
    }
    
/*----------------------------Print the Result----------------------------------------*/

    Plaintext plain_result_m1;
    vector<double> result;
    decryptor.decrypt(rotateAlign_result, plain_result_m1);
    encoder.decode(plain_result_m1, result);
    print_vector(result, 16, 5);
}