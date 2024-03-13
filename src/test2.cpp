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

    int m = 0, l = 0, n = 0;
	cout << "Input the number of columns and rows of the matrix" << endl;
	cin >> m >> l >> n;

    vector<double> input1(slot_count, 0.0);
    Plaintext x_plain1;
    Ciphertext x_cipher1;
    for (int i = 0; i < m * l ; i++)
    {
        input1[i] = i + 1;
    }
    encoder.encode(input1, scale, x_plain1);
    encryptor.encrypt(x_plain1, x_cipher1);

    vector<double> input2(slot_count, 0.0);
    Plaintext x_plain2;
    Ciphertext x_cipher2;
    for (int i = 0; i < l * n ; i++)
    {
        input2[i] = i + 1;
    }
    encoder.encode(input2, scale, x_plain2);
    encryptor.encrypt(x_plain2, x_cipher2);

/*---------------------------Create Us and Ut slot--------------------------------------*/
/*this for loop is not necessary*/
    int Us_edge = m * l;
    vector<double> Us(slot_count * slot_count, 0.0);
    for(int i = 0; i < m; i++)
    {
        for(int j = 0; j < l; j++)
        {
            int k = (l * i + (i + j) % l);
            Us[Us_edge * (l * i + j) + k] = 1;
        }
    }

    int Ut_edge = l * n;
    vector<double> Ut(slot_count * slot_count, 0.0);
    for(int i = 0; i < l; i++)
    {
        for(int j = 0; j < n; j++)
        {
            int k = (n * ((i + j) % l) + j);
            Ut[Ut_edge * (n * i + j) + k] = 1;
        }
    }

    print_vector(Ut, 16, 5);

/*--------------------------------RotateAlign----------------------------------------*/
    cout << "    + The scale of x_cipher before Rotate: " << log2(x_cipher1.scale()) << endl;
    cout << "    + The parm_id of x_cipher before Rotate: " << x_cipher1.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before Rotate: " << x_cipher1.coeff_modulus_size() << endl;
    cout << endl;

    int dim = 0;
    Ciphertext rotateAlign_result;
    if(dim == 1)
    {
        if(m != 1 && l != 1)
        {
            /*the ciphertext in this code block need to rescale.*/
            evaluator.rotate_vector(x_cipher1, -l+1, gal_keys, rotateAlign_result);

            Plaintext Usk_plain_1;
            vector<double> Usk_1(slot_count, 0.0);
            int flag = 0;
            for(int i = 0; i < Us_edge; i++)
            {
                Usk_1[i] = Us[i * Us_edge + (i + (Us_edge - l + 1)) % Us_edge];
                //if(Usk_1[i] == 1) flag = 1;
            }
            //print_vector(Usk_1, 16, 5);
            encoder.encode(Usk_1, scale, Usk_plain_1);
            evaluator.multiply_plain_inplace(rotateAlign_result, Usk_plain_1);

            for(int k = -l+2; k < l; k++)
            {
                flag = 0;
                Ciphertext tmp;
                evaluator.rotate_vector(x_cipher1, k, gal_keys, tmp);

                Plaintext Usk_plain;
                vector<double> Usk(slot_count, 0.0);
                for(int i = 0; i < Us_edge; i++)
                {
                   Usk[i] = Us[i * Us_edge + (i + (Us_edge + k)) % Us_edge];
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
            rotateAlign_result = x_cipher1;
        }
    }
    else if(dim == 0){
        if(l != 1 && n != 1)
        {
            /*the ciphertext in this code block need to rescale.*/
            //evaluator.rotate_vector(x_cipher2, 0, gal_keys, rotateAlign_result);
            rotateAlign_result = x_cipher2;

            Plaintext Utk_plain_1;
            vector<double> Utk_1(slot_count, 0.0);
            int flag = 0;
            for(int i = 0; i < Ut_edge; i++)
            {
                Utk_1[i] = Ut[i * Ut_edge + i];
                //if(Utk_1[i] == 1) flag = 1;
            }
            //print_vector(Utk_1, 16, 5);
            encoder.encode(Utk_1, scale, Utk_plain_1);
            evaluator.multiply_plain_inplace(rotateAlign_result, Utk_plain_1);

            int d_min = l>n?n:l;
            for(int k = 1; k < d_min; k++)
            {
                flag = 0;
                Ciphertext tmp;
                evaluator.rotate_vector(x_cipher2, n * k, gal_keys, tmp);

                Plaintext Utk_plain;
                vector<double> Utk_u(slot_count, 0.0);
                for(int i = 0; i < Ut_edge - k * n; i++)
                {
                   Utk_u[i] = Ut[i * Ut_edge + (i +  k * n) % Ut_edge];
                   if(Utk_u[i] == 1) flag = 1;
                }
                if(flag == 1)
                {
                    //print_vector(Usk, 16, 5);
                    encoder.encode(Utk_u, scale, Utk_plain);
                    evaluator.multiply_plain_inplace(tmp, Utk_plain);
                    evaluator.add_inplace(rotateAlign_result, tmp);
                }

                flag = 0;
                evaluator.rotate_vector(x_cipher2, slot_count - Ut_edge + n * k, gal_keys, tmp);

                vector<double> Utk_d(slot_count, 0.0);
                for(int i = 0; i < n * k; i++)
                {
                    int index = Ut_edge - k * n + i;
                    Utk_d[index] = Ut[index * Ut_edge + (index +  k * n) % Ut_edge];
                    if(Utk_d[index] == 1) flag = 1;
                }
                if(flag == 0) continue;
                encoder.encode(Utk_d, scale, Utk_plain);
                evaluator.multiply_plain_inplace(tmp, Utk_plain);
                evaluator.add_inplace(rotateAlign_result, tmp);
            }
        }
        else{
            rotateAlign_result = x_cipher2;
        }
    }

    cout << "    + The scale of x_cipher after Rotate: " << log2(rotateAlign_result.scale()) << endl;
    cout << "    + The parm_id of x_cipher after Rotate: " << rotateAlign_result.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before Rotate: " << rotateAlign_result.coeff_modulus_size() << endl;
    
    
/*----------------------------Print the Result----------------------------------------*/

    Plaintext plain_result_m1;
    vector<double> result;
    decryptor.decrypt(rotateAlign_result, plain_result_m1);
    encoder.decode(plain_result_m1, result);
    print_vector(result, 16, 5);
}