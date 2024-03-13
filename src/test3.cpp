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

/*----------------------------Create V and W slot-------------------------------------*/
    int step = 1;

    int V_edge = m * l;
    vector<double> V(slot_count, 0.0);
    for(int i = 0; i < m; i++)
    {
        for(int j = 0; j < l; j++)
        {
            int k = l * i + (j + step) % l;
            V[V_edge * (l * i + j) + k] = 1;
        }
    }

    int W_edge = l * n;
    vector<double> W(slot_count, 0.0);
    for(int i = 0; i < l; i++)
    {
        for(int j = 0; j < n; j++)
        {
            int k = n * ((i + step) % l) +j;
            W[W_edge * (n * i + j) + k] = 1;
        }
    }

    print_vector(V, 16, 5);

/*---------------------------------Rotate1D-------------------------------------------*/
    cout << "    + The scale of x_cipher before Rotate: " << log2(x_cipher1.scale()) << endl;
    cout << "    + The parm_id of x_cipher before Rotate: " << x_cipher1.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before Rotate: " << x_cipher1.coeff_modulus_size() << endl;
    cout << endl;

    int dim = 0;
    Ciphertext Rotate_result;
    if(dim == 1)
    {
        int step_t = (step + l - 1) % l + 1;
        Plaintext mask1;
        Plaintext mask2;
        vector<double> input1(slot_count, 0.0);
        vector<double> input2(slot_count, 1.0);
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < step_t; j++)
            {
                input1[i * l + j] = 1;
                input2[i * l + j] = 0;
            }
        }
        encoder.encode(input1, scale, mask1);
        encoder.encode(input2, scale, mask2);

        Ciphertext rotate_data1;
        Ciphertext rotate_data2;

        evaluator.multiply_plain(x_cipher1, mask1, rotate_data1);
        evaluator.multiply_plain(x_cipher1, mask2, rotate_data2);

        evaluator.rotate_vector_inplace(rotate_data1, -(l-step_t), gal_keys);
        evaluator.rotate_vector_inplace(rotate_data2, step_t, gal_keys);

        evaluator.add_inplace(rotate_data1, rotate_data2);
        Rotate_result = rotate_data1;
    }
    else if(dim == 0)
    {
        int step_t = (step + l - 1) % l + 1;
        Plaintext mask1;
        Plaintext mask2;
        vector<double> input1(slot_count, 0.0);
        vector<double> input2(slot_count, 1.0);
        for (int i = 0; i < step_t; i++)
        {
            for (int j = 0; j < n; j++)
            {
                input1[i * n + j] = 1;
                input2[i * n + j] = 0;
            }
        }
        encoder.encode(input1, scale, mask1);
        encoder.encode(input2, scale, mask2);

        Ciphertext rotate_data1;
        Ciphertext rotate_data2;

        evaluator.multiply_plain(x_cipher2, mask1, rotate_data1);
        evaluator.multiply_plain(x_cipher2, mask2, rotate_data2);

        evaluator.rotate_vector_inplace(rotate_data1, -(l - step_t)*n, gal_keys);
        evaluator.rotate_vector_inplace(rotate_data2, step_t*n, gal_keys);

        evaluator.add_inplace(rotate_data1, rotate_data2);
        Rotate_result = rotate_data1;
    }

    cout << "    + The scale of x_cipher after Rotate: " << log2(Rotate_result.scale()) << endl;
    cout << "    + The parm_id of x_cipher after Rotate: " << Rotate_result.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before Rotate: " << Rotate_result.coeff_modulus_size() << endl;

    
/*----------------------------Print the Result----------------------------------------*/

    Plaintext plain_result_m1;
    vector<double> result;
    decryptor.decrypt(Rotate_result, plain_result_m1);
    encoder.decode(plain_result_m1, result);
    print_vector(result, 16, 5);
}