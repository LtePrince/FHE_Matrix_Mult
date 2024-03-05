#include<iostream>
#include "seal/seal.h"
#include "include/examples.h"

using namespace std;
using namespace seal;

class Cipher_Matrix
{
public:
    Ciphertext m;
    size_t col[2] = {0};
    size_t row[2] = {0};
    Cipher_Matrix() {};
    ~Cipher_Matrix() {};
};

void Init_Matrix(Cipher_Matrix &m, CKKSEncoder &encoder, Encryptor &encryptor, int slot_count, double scale)
{
    cout << "Please input the number of columns and rows of the Matrix:" << endl;
    //cin >> m.col[0] >> m.row[0];
    m.col[0] = m.row[0] = 3;
    int tmp = 0;
    vector<double> input;
    Plaintext x_plain;
    input.reserve(slot_count);
    cout << "Please input the data of the Matrix:" << endl;
    for (int i = 0; i < 9; i++)
    {
        input.push_back(i + 1);
    }
    print_vector(input, 3, 7);
    cout << endl;
    encoder.encode(input, scale, x_plain);
    encryptor.encrypt(x_plain, m.m);
}

int RoundUP_2_Power(int num)
{
    int i = 1;
    while (i < num)
    {
        i *= 2;
    }
    return i;
}

void Mat_dim_process(Cipher_Matrix& m, CKKSEncoder& encoder, Evaluator &evaluator, GaloisKeys &gal_keys, int slot_count, double scale)
{
    //暂不进行矩阵大小是否超过数据槽的验证
    m.col[1] = RoundUP_2_Power(m.col[0]);
    m.row[1] = RoundUP_2_Power(m.row[0]);
    int a = m.row[1], b = m.row[0];
    int i = m.row[0] - 1;
    for (; i > 0; i--)
    {
        Plaintext mask1;
        Plaintext mask2;
        vector<double> input1(slot_count, 0.0);
        vector<double> input2(slot_count, 1.0);
        int step = i * (a - b);
        for (int j = 0; j < m.row[0]; j++)
        {
            input1[i * m.row[0] + j] = 1.0;
            input2[i * m.row[0] + j] = 0.0;
        }
        encoder.encode(input1, scale, mask1);
        encoder.encode(input2, scale, mask2);

        Ciphertext row_data;
        parms_id_type last_parms_id = m.m.parms_id();
        evaluator.mod_switch_to_inplace(mask1, last_parms_id);
        evaluator.mod_switch_to_inplace(mask2, last_parms_id);
        evaluator.multiply_plain(m.m, mask1, row_data);
        evaluator.rescale_to_inplace(row_data, last_parms_id);

        evaluator.multiply_plain_inplace(m.m, mask2);
        evaluator.rescale_to_inplace(m.m, last_parms_id);

        evaluator.rotate_vector_inplace(row_data, -step, gal_keys);
        evaluator.add_inplace(m.m, row_data);
    }
}

void Mat_Extern(Cipher_Matrix& m, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, int slot_count, double scale, int D0, int D1)
{
    //暂不进行矩阵大小是否超过数据槽的验证
    int a = D1, b = m.row[1];
    int i = m.col[0] - 1;
    for (; i > 0; i--)
    {
        Plaintext mask1;
        Plaintext mask2;
        vector<double> input1(slot_count, 0.0);
        vector<double> input2(slot_count, 1.0);
        int step = i * (a - b);
        for (int j = 0; j < m.row[1]; j++)
        {
            input1[i * m.row[1] + j] = 1.0;
            input2[i * m.row[1] + j] = 0.0;
        }
        encoder.encode(input1, scale, mask1);
        encoder.encode(input2, scale, mask2);

        Ciphertext row_data;
        parms_id_type last_parms_id = m.m.parms_id();
        evaluator.mod_switch_to_inplace(mask1, last_parms_id);
        evaluator.mod_switch_to_inplace(mask2, last_parms_id);

        evaluator.multiply_plain(m.m, mask1, row_data);
        evaluator.rescale_to_next_inplace(row_data);

        evaluator.multiply_plain_inplace(m.m, mask2);
        evaluator.rescale_to_next_inplace(m.m);

        evaluator.rotate_vector_inplace(row_data, -step, gal_keys);
        evaluator.add_inplace(m.m, row_data);
    }
    m.col[1] = D0;
    m.col[1] = D1;
}

void Rotate1D(Cipher_Matrix& m, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, int dim, int step, int slot_count, int scale)
{
    int c1 = m.col[0], r1 = m.row[0];
    int c2 = m.col[1], r2 = m.row[1];
    int step_t = (step % r1 + r1) % r1;
    
    if (dim == 1)//水平方向旋转，正方向为左
    {
        Plaintext mask1;
        Plaintext mask2;
        vector<double> input1(slot_count, 0.0);
        vector<double> input2(slot_count, 1.0);
        for (int i = 0; i < c1; i++)
        {
            for (int j = 0; j < step_t; j++)
            {
                input1[i * r2 + j] = 1;
                input2[i * r2 + j] = 0;
            }
        }
        encoder.encode(input1, scale, mask1);
        encoder.encode(input2, scale, mask2);

        Ciphertext rotate_data1;
        Ciphertext rotate_data2;
        parms_id_type last_parms_id = m.m.parms_id();
        evaluator.mod_switch_to_inplace(mask1, last_parms_id);
        evaluator.mod_switch_to_inplace(mask2, last_parms_id);

        evaluator.multiply_plain(m.m, mask1, rotate_data1);
        evaluator.rescale_to_next_inplace(rotate_data1);

        evaluator.multiply_plain(m.m, mask2, rotate_data2);
        evaluator.rescale_to_next_inplace(rotate_data2);

        evaluator.rotate_vector_inplace(rotate_data1, -(r1-step_t), gal_keys);
        evaluator.rotate_vector_inplace(rotate_data2, step_t, gal_keys);

        evaluator.add_inplace(rotate_data1, rotate_data2);
        m.m = rotate_data1;

    }
    else if (dim == 0)//垂直方向旋转，正方向为上
    {
        Plaintext mask1;
        Plaintext mask2;
        vector<double> input1(slot_count, 0.0);
        vector<double> input2(slot_count, 1.0);
        for (int i = 0; i < step_t; i++)
        {
            for (int j = 0; j < r2; j++)
            {
                input1[i * r2 + j] = 1;
                input2[i * r2 + j] = 0;
            }
        }
        encoder.encode(input1, scale, mask1);
        encoder.encode(input2, scale, mask2);

        Ciphertext rotate_data1;
        Ciphertext rotate_data2;
        parms_id_type last_parms_id = m.m.parms_id();
        evaluator.mod_switch_to_inplace(mask1, last_parms_id);
        evaluator.mod_switch_to_inplace(mask2, last_parms_id);

        evaluator.multiply_plain(m.m, mask1, rotate_data1);
        evaluator.rescale_to_next_inplace(rotate_data1);

        evaluator.multiply_plain(m.m, mask2, rotate_data2);
        evaluator.rescale_to_next_inplace(rotate_data2);

        evaluator.rotate_vector_inplace(rotate_data1, -(c1 - step_t)*r2, gal_keys);
        evaluator.rotate_vector_inplace(rotate_data2, step_t*r2, gal_keys);

        evaluator.add_inplace(rotate_data1, rotate_data2);
        m.m = rotate_data1;
    }
}

void RotateAlign(Cipher_Matrix& m, Cipher_Matrix& destination, Evaluator& evaluator, GaloisKeys& gal_keys, int dim, /*int l, */int slot_count, int scale)
{
    int l = (dim == 1) ? m.row[0] : m.col[0];
}

void Replicate1D()
{

}

int main()
{
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192*2;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 40, 40, 40, 40, 60 }));

    double scale = pow(2.0, 30);

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

    Cipher_Matrix m1;
    //Cipher_Matrix m2;
    Init_Matrix(m1, encoder, encryptor, slot_count, scale);
    //Init_Matrix(m2, encoder, encryptor, slot_count, scale);

    Mat_dim_process(m1, encoder, evaluator, gal_keys, slot_count, scale);
    //Mat_dim_process(m2, encoder, evaluator, gal_keys, slot_count, scale);

    cout << "Rotate1D:" << endl;
    Rotate1D(m1, encoder, evaluator, gal_keys, 0, 1, slot_count, scale);

    //cout << "Extern:" << endl;
    //Mat_Extern(m1, encoder, evaluator, gal_keys, slot_count, scale, 8, 8);

    Plaintext plain_result_m1;
    vector<double> result;
    decryptor.decrypt(m1.m, plain_result_m1);
    encoder.decode(plain_result_m1, result);
    print_vector(result, 16, 5);

    return 0;
}