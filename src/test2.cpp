#include<iostream>
#include "seal/seal.h"
#include "include/examples.h"

using namespace std;
using namespace seal;

class Plain_Matrix
{
public:
    Plaintext m;
    size_t col[2] = { 0 };
    size_t row[2] = { 0 };
    Plain_Matrix() {};
    ~Plain_Matrix() {};
};

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
        cout << endl;
        cout << "    + Scale of m before multiply: " << log2(m.m.scale()) << " bits" << endl;
        evaluator.multiply_plain(m.m, mask1, row_data);
        cout << "    + Scale of r before rescale: " << log2(row_data.scale()) << " bits" << endl;
        evaluator.rescale_to_next_inplace(row_data);
        cout << "    + Scale of r after rescale: " << log2(row_data.scale()) << " bits" << endl;

        cout << endl;
        evaluator.multiply_plain_inplace(m.m, mask2);
        cout << "    + Scale of m before rescale: " << log2(m.m.scale()) << " bits" << endl;
        evaluator.rescale_to_next_inplace(m.m);
        cout << "    + Scale of m after rescale: " << log2(m.m.scale()) << " bits" << endl;

        cout << endl;
        evaluator.rotate_vector_inplace(row_data, -step, gal_keys);
        cout << "    + Scale of after rotate: " << log2(row_data.scale()) << " bits" << endl;

        evaluator.add_inplace(m.m, row_data);
        cout << "    + Scale of after add: " << log2(m.m.scale()) << " bits" << endl;
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

void Rotate1D(Cipher_Matrix& m, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, int dim, int step, int slot_count, double scale)
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

        cout << "m scale: " << m.m.scale() << endl;
        cout << "mask1 scale: " << mask1.scale() << endl;

        cout << "m parm_id: " << last_parms_id << endl;
        cout << "mask1 parm_id: " << mask1.parms_id() << endl;
        cout << endl;



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

void RotateAlign(Cipher_Matrix& m, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, int dim, /*int l, */int slot_count, double scale)
{
    

    int l = (dim == 1) ? m.row[0] : m.col[0];
    for (int k = 0; k < l; k++)
    {
        Cipher_Matrix pm;
        pm.col[0] = m.col[0], pm.col[1] = m.col[1], pm.row[0] = m.row[0], pm.row[1] = m.row[1];

        Plaintext mask;
        vector<double> input(slot_count, 0.0);
        for (int i = 0; i < m.col[0]; i++)
        {
            for (int j = 0; j < m.row[0]; j++)
            {
                if (dim == 1 && i == k)
                {
                    input[i * m.row[0] + j] = 1;
                }
                else if (dim == 0 && j == k)
                {
                    input[i * m.row[0] + j] = 1;
                }
            }
        }
        encoder.encode(input, scale, mask);

        Ciphertext rotate_data;
        parms_id_type last_parms_id = m.m.parms_id();
        cout << "m parm_id: " << last_parms_id << endl;
        cout << "m scale: " << m.m.scale() << endl;
        evaluator.mod_switch_to_inplace(mask, last_parms_id);

        evaluator.multiply_plain(m.m, mask, rotate_data);

        cout << "row_data parm_id: " << rotate_data.parms_id() << endl;
        cout << "rotate_data scale: " << rotate_data.scale() << endl;
        
        rotate_data.scale() = pow(2, 40);
        evaluator.mod_switch_to_inplace(rotate_data, last_parms_id);
        //evaluator.rescale_to_inplace(rotate_data, last_parms_id);
        cout << "row_data parm_id: " << rotate_data.parms_id() << endl;
        cout << "rotate_data scale: " << rotate_data.scale() << endl;
        //m.m = rotate_data;
        cout << "m scale: " << m.m.scale() << endl;

        pm.m = rotate_data;
        cout << "pm parm_id: " << pm.m.parms_id() << endl;
        cout << "pm scale: " << pm.m.scale() << endl;
        cout << endl;
        Rotate1D(pm, encoder, evaluator, gal_keys, dim, k, slot_count, scale);


        evaluator.add_inplace(destination.m, pm.m);
    }
}

void Replicate1D(Cipher_Matrix& m, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, int dim, int d_dim, int D0, int D1, int slot_count, double scale)
{
    destination.m = m.m;
    destination.col[0] = m.col[0];
    destination.col[1] = m.col[1];
    destination.row[0] = m.row[0];
    destination.row[1] = m.row[1];

    Mat_Extern(destination, encoder, evaluator, gal_keys, slot_count, scale, D0, D1);
    int D_dim = (dim == 1) ? D1 : D0;
    int k_max = log(D_dim / d_dim) / log(2);
    for (int k = 1; k <= k_max; k++)
    {
        Plaintext mask;
        vector<double> input(slot_count, 1.0);
        encoder.encode(input, scale, mask);

        Cipher_Matrix rotate_data;
        evaluator.multiply_plain(destination.m, mask, rotate_data.m);

        Rotate1D(rotate_data, encoder, evaluator, gal_keys, dim, k* d_dim, slot_count, scale);
        
        evaluator.add_inplace(destination.m, rotate_data.m);
    }
}

void Sum1D(Cipher_Matrix& m, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, int dim, int d_dim, int D0, int D1, int slot_count, double scale)
{

    //未作scale和parm_id的调整
    for (int k = log(D1 / d_dim) / log(2); k > 0; k--)
    {
        Plaintext mask;
        encoder.encode(1.0, scale, mask);

        Cipher_Matrix rotate_data;
        rotate_data.col[0] = m.col[0];
        rotate_data.col[1] = m.col[1];
        rotate_data.row[0] = m.row[0];
        rotate_data.row[1] = m.row[1];

        parms_id_type last_parms_id = m.m.parms_id();
        evaluator.mod_switch_to_inplace(mask, last_parms_id);
        evaluator.multiply_plain(m.m, mask, rotate_data.m);
        evaluator.rescale_to_next_inplace(rotate_data.m);

        Rotate1D(rotate_data, encoder, evaluator, gal_keys, dim, k*d_dim, slot_count, scale);
        cout << "m scale: " << m.m.scale() << endl;
        cout << "rotate_data scale: " << rotate_data.m.scale() << endl;

        cout << "m parm_id: " << last_parms_id << endl;
        cout << "rotate_data parm_id: " << rotate_data.m.parms_id() << endl;
        cout << endl;
        
        evaluator.add_inplace(m.m, rotate_data.m);
    }
}

int main()
{
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192*2;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 40, 40, 40, 40, 40, 60 }));

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

    Cipher_Matrix m1;
    //Cipher_Matrix m2;
    Init_Matrix(m1, encoder, encryptor, slot_count, scale);
    //Init_Matrix(m2, encoder, encryptor, slot_count, scale);

    cout << "    + Scale of M_d_p before rescale: " << log2(m1.m.scale()) << " bits" << endl;
    Mat_dim_process(m1, encoder, evaluator, gal_keys, slot_count, scale);
    cout << "    + Scale of M_d_p after rescale: " << log2(m1.m.scale()) << " bits" << endl;
    //Mat_dim_process(m2, encoder, evaluator, gal_keys, slot_count, scale);
    cout << "Rotate1D:" << endl;
    Rotate1D(m1, encoder, evaluator, gal_keys, 0, 1, slot_count, scale);

    //Cipher_Matrix r_m;
    //cout << "RotateAlign:" << endl;
    //RotateAlign(m1, r_m, encoder, evaluator, gal_keys, 1, slot_count, scale);

    cout << "Sum1D:" << endl;
    Sum1D(m1, encoder, evaluator, gal_keys, 1, 2, m1.col[1], m1.row[1], slot_count, scale);

    //cout << "Extern:" << endl;
    //Mat_Extern(m1, encoder, evaluator, gal_keys, slot_count, scale, 8, 8);

    Plaintext plain_result_m1;
    vector<double> result;
    decryptor.decrypt(m1.m, plain_result_m1);
    encoder.decode(plain_result_m1, result);
    print_vector(result, 16, 5);

    return 0;
}