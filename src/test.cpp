#include<iostream>
#include "seal/seal.h"
#include "include/examples.h"

using namespace std;
using namespace seal;

//class Plain_Matrix
//{
//public:
//    Plaintext m;
//    size_t col;
//    size_t row;
//    Plain_Matrix(Plaintext p, size_t col, size_t row)
//    {
//        this->col = col;
//        this->row = row;
//        this->m = p;
//    }
//    ~Plain_Matrix() {};
//};

class Cipher_Matrix
{
public:
    Ciphertext m;
    size_t col;
    size_t row;
    Cipher_Matrix(Ciphertext p, size_t col, size_t row)
    {
        this->col = col;
        this->row = row;
        this->m = p;
    }
    ~Cipher_Matrix() {};
};

int RoundUP_2_Power(int num)
{
    int i = 1;
    while (i < num)
    {
        i *= 2;
    }
    return i;
}

int Matrix_Padding_by_zero(Cipher_Matrix m1, Cipher_Matrix m2)
{
    for (int i = 0; i < m2.col; i++)
    {
        for (int j = 0; j < m2.row; j++)
        {
            
        }
    }
    return 0;

}

int main()
{
    /*
    Note that scheme_type is now "bgv".
    */
    EncryptionParameters parms(scheme_type::bgv);
    size_t poly_modulus_degree =  8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    /*
    We can certainly use BFVDefault coeff_modulus. In later parts of this example,
    we will demonstrate how to choose coeff_modulus that is more useful in BGV.
    */
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);

    /*
    Print the parameters that we have chosen.
    */
    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    /*
    Batching and slot operations are the same in BFV and BGV.
    */
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();

    //define two Matrix and initialize them
    int m = 0, l = 0, n = 0;
    cout << "input the m, l, n:";
    cin >> m >> l >> n;
    cout << m << " " << l << " " << n << endl;
    vector<uint64_t> pod_matrix1(slot_count, 0ULL);
    vector<uint64_t> pod_matrix2(slot_count, 0ULL);
    cout << "input the matrix1:" << endl;
    for (int i = 0; i < m; i++)
    {
        for (int j = 0; j < l; j++)
        {
            cin >> pod_matrix1[i * l + j];
        }
    }
    cout << "input the matrix2:" << endl;
    for (int i = 0; i < l; i++)
    {
        for (int j = 0; j < n; j++)
        {
            cin >> pod_matrix2[i * n + j];
        }
    }

    cout << "Input plaintext matrix1:" << endl;
    print_matrix(pod_matrix1, l);
    Plaintext m1_plain;
    cout << "Encode plaintext matrix to x_plain:" << endl;
    batch_encoder.encode(pod_matrix1, m1_plain);
    //Plain_Matrix m1(m1_plain, m, l);

    cout << "Input plaintext matrix2:" << endl;
    print_matrix(pod_matrix2, n);
    Plaintext m2_plain;
    cout << "Encode plaintext matrix to x_plain:" << endl;
    batch_encoder.encode(pod_matrix2, m2_plain);
    //Plain_Matrix m2(m2_plain, l, n);

    /*
    Next we encrypt the encoded plaintext.
    */
    Ciphertext m1_encrypted;
    print_line(__LINE__);
    cout << "Encrypt m1_plain to m1_encrypted." << endl;
    encryptor.encrypt(m1_plain, m1_encrypted);
    cout << "    + noise budget in freshly encrypted m1: " << decryptor.invariant_noise_budget(m1_encrypted) << " bits"
        << endl;
    cout << endl;
    Cipher_Matrix m1(m1_encrypted, m, l);

    Ciphertext m2_encrypted;
    print_line(__LINE__);
    cout << "Encrypt m2_plain to m2_encrypted." << endl;
    encryptor.encrypt(m2_plain, m2_encrypted);
    cout << "    + noise budget in freshly encrypted m2: " << decryptor.invariant_noise_budget(m2_encrypted) << " bits"
        << endl;
    cout << endl;
    Cipher_Matrix m2(m2_encrypted, l, n);

    //calculate on the ciphertext
    int m0 = RoundUP_2_Power(m1.col),
        l0 = RoundUP_2_Power(m1.row),
        n0 = RoundUP_2_Power(m2.row);
    int D0, D1 = 0;
    if (l0 <= m0 && l0 <= n0)
    {
        D0 = m0, D1 = n0;
    }
    else if (l0 >= m0 && l0 >= n0)
    {
        D0 = D1 = l0;
    }
    else
    {
        m0 > n0 ? (D0 = m0, D1 = l0) : (D0 = l0, D1 = n0);
    }




    //to be continues

    return 0;
}
