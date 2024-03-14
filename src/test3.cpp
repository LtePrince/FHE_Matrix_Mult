#define _CRT_SECURE_NO_WARNINGS 1
#include<iostream>
#include<time.h>
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

void Rotate1DNew(Cipher_Matrix& src, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, RelinKeys relin_keys, int dim, int step, int slot_count, double scale);

void RotateAlignNew(Cipher_Matrix& src, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, RelinKeys relin_keys, int dim, int slot_count, double scale);

void Sum1DNew(Cipher_Matrix& src, Cipher_Matrix& destination, Evaluator& evaluator, GaloisKeys& gal_keys, int slot_count);

int main()
{
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192*4;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 40, 40, 40, 60 }));

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

    time_t t1, t2;
    t1 = time(NULL);

    cout << "    + The scale of x_cipher before Replicate1D: " << log2(x_cipher1.m.scale()) << endl;
    cout << "    + The parm_id of x_cipher before Replicate1D: " << x_cipher1.m.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before Replicate1D: " << x_cipher1.m.coeff_modulus_size() << endl;
    cout << endl;

    Cipher_Matrix Replicate1D_result1;
    Replicate1DNew(x_cipher1, Replicate1D_result1, 1, encoder, evaluator, gal_keys, relin_keys);
    Cipher_Matrix Replicate1D_result2;
    Replicate1DNew(x_cipher2, Replicate1D_result2, 0, encoder, evaluator, gal_keys, relin_keys);

    cout << "    + The scale of x_cipher after Replicate1D: " << log2(Replicate1D_result1.m.scale()) << endl;
    cout << "    + The parm_id of x_cipher after Replicate1D: " << Replicate1D_result1.m.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before Replicate1D: " << Replicate1D_result1.m.coeff_modulus_size() << endl;
    cout << endl;

/*---------------------------------RotateAlign----------------------------------------*/
    
    cout << "    + The scale of x_cipher before RotateAlign: " << log2(x_cipher1.m.scale()) << endl;
    cout << "    + The parm_id of x_cipher before RotateAlign: " << x_cipher1.m.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before RotateAlign: " << x_cipher1.m.coeff_modulus_size() << endl;
    cout << endl;

    Cipher_Matrix rotateAlign_result1;
    RotateAlignNew(Replicate1D_result1, rotateAlign_result1, encoder, evaluator, gal_keys, relin_keys, 1, slot_count, scale);
    Cipher_Matrix rotateAlign_result2;
    RotateAlignNew(Replicate1D_result2, rotateAlign_result2, encoder, evaluator, gal_keys, relin_keys, 0, slot_count, scale);

    cout << "    + The scale of x_cipher after RotateAlign: " << log2(rotateAlign_result1.m.scale()) << endl;
    cout << "    + The parm_id of x_cipher after RotateAlign: " << rotateAlign_result1.m.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before RotateAlign: " << rotateAlign_result1.m.coeff_modulus_size() << endl;
    cout << endl;

/*-----------------------------Mult and Add------------------------------------------*/
    
    Ciphertext Mult_result;

    int min_edge = (m < l) ? ((m < n) ? m : n) : ((l < n) ? l : n);
    for (int i = 0; i < min_edge; i++)
    {
        cout << "    for loop:" << i << endl;

        Cipher_Matrix Rotate_result1;
        Cipher_Matrix Rotate_result2;

        Rotate1DNew(rotateAlign_result1, Rotate_result1, encoder, evaluator, gal_keys, relin_keys, 1, i, slot_count, scale);
        Rotate1DNew(rotateAlign_result2, Rotate_result2, encoder, evaluator, gal_keys, relin_keys, 0, i, slot_count, scale);

        if (i == 0)
        {
            evaluator.multiply(Rotate_result1.m, Rotate_result2.m, Mult_result);
        }
        else
        {
            evaluator.multiply_inplace(Rotate_result1.m, Rotate_result2.m);
            evaluator.add_inplace(Mult_result, Rotate_result1.m);
        }
        
    }
    cout << endl;
    cout << "    + The scale of Mult_result after Multiply and Add: " << log2(Mult_result.scale()) << endl;
    cout << "    + The parm_id of Mult_result after Multiply and Add: " << Mult_result.parms_id() << endl;
    cout << "    + The coeff_modulus_size of Mult_result before Multiply and Add: " << Mult_result.coeff_modulus_size() << endl;
    cout << endl;
    t2 = time(NULL);
    
/*----------------------------Print the Result----------------------------------------*/

    Plaintext plain_result_m1;
    vector<double> result;
    decryptor.decrypt(Mult_result, plain_result_m1);
    encoder.decode(plain_result_m1, result);
    print_vector(result, 16, 5);
    cout << "    + The time of this Matrix Multiply: " << t2 - t1 << "s." << endl;
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
    cout << "  Replicate1DNew:" << endl;
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
            evaluator.rotate_vector(destination.m, -step * src.col[0] * src.row[0], gal_keys, tmp);
            evaluator.add_inplace(destination.m, tmp);
            step *= 2;
        }
    }
}


void Rotate1DNew(Cipher_Matrix& src, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, RelinKeys relin_keys, int dim, int step, int slot_count, double scale)
{
    cout << "  Rotate1DNew:" << endl;
    destination = src;
    if(dim == 1)
    {
        int m = src.col[1], l = src.row[1];
        int step_t = (step + l - 1) % l + 1;
        Plaintext mask1;
        Plaintext mask2;
        vector<double> input1(slot_count, 0.0);
        vector<double> input2(slot_count, 1.0);
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < step_t; j++)
            {
                input1[i * l + j] = 1.0;
                input2[i * l + j] = 0.0;
            }
        }
        encoder.encode(input1, scale, mask1);
        encoder.encode(input2, scale, mask2);

        parms_id_type last_parms_id = src.m.parms_id();
        evaluator.mod_switch_to_inplace(mask1, last_parms_id);
        evaluator.mod_switch_to_inplace(mask2, last_parms_id);

        Ciphertext rotate_data1;
        Ciphertext rotate_data2;

        evaluator.multiply_plain(src.m, mask1, rotate_data1);
        evaluator.rotate_vector_inplace(rotate_data1, -(l-step_t), gal_keys);

        if(step_t * step_t != slot_count)
        {
            evaluator.multiply_plain(src.m, mask2, rotate_data2);
            evaluator.rotate_vector_inplace(rotate_data2, step_t, gal_keys);

            evaluator.add_inplace(rotate_data1, rotate_data2);
        }
        destination.m = rotate_data1;
    }
    else if(dim == 0)
    {
        int l = src.col[1], n = src.row[1];
        int step_t = (step + l - 1) % l + 1;
        Plaintext mask1;
        Plaintext mask2;
        vector<double> input1(slot_count, 0.0);
        vector<double> input2(slot_count, 1.0);
        for (int i = 0; i < step_t; i++)
        {
            for (int j = 0; j < n; j++)
            {
                input1[i * n + j] = 1.0;
                input2[i * n + j] = 0.0;
            }
        }
        encoder.encode(input1, scale, mask1);
        encoder.encode(input2, scale, mask2);

        parms_id_type last_parms_id = src.m.parms_id();
        evaluator.mod_switch_to_inplace(mask1, last_parms_id);
        evaluator.mod_switch_to_inplace(mask2, last_parms_id);

        Ciphertext rotate_data1;
        Ciphertext rotate_data2;

        evaluator.multiply_plain(src.m, mask1, rotate_data1);
        evaluator.rotate_vector_inplace(rotate_data1, -(l - step_t)*n, gal_keys);

        if(step_t * step_t != slot_count)
        {
            evaluator.multiply_plain(src.m, mask2, rotate_data2);
            evaluator.rotate_vector_inplace(rotate_data2, step_t*n, gal_keys);

            evaluator.add_inplace(rotate_data1, rotate_data2);
        }   
        destination.m = rotate_data1;
    }
    evaluator.rescale_to_next_inplace(destination.m);
}

void RotateAlignNew(Cipher_Matrix& src, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, RelinKeys relin_keys, int dim, int slot_count, double scale)
{
    cout << "  RotateAlignNew:" << endl;
    if(dim == 1)
    {
        int m = src.col[1], l = src.row[1];
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
        print_vector(Us, 16, 5);

        if(m != 1 && l != 1)
        {
            destination.col[0] = src.col[0];
            destination.row[0] = src.row[0];
            destination.col[1] = src.col[1];
            destination.row[1] = src.row[1];
            /*the ciphertext in this code block need to rescale.*/
            evaluator.rotate_vector(src.m, -l+1, gal_keys, destination.m);

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
            evaluator.multiply_plain_inplace(destination.m, Usk_plain_1);

            for(int k = -l+2; k < l; k++)
            {
                flag = 0;
                Ciphertext tmp;
                evaluator.rotate_vector(src.m, k, gal_keys, tmp);

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
                evaluator.add_inplace(destination.m, tmp);
            }
            evaluator.rescale_to_next_inplace(destination.m);
        }
        else{
            destination = src;//need to mult a plain full of 1.0!!!!!
        }
    }
    else if(dim == 0)
    {
        int l = src.col[1], n = src.row[1];
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

        if(l != 1 && n != 1)
        {
            /*the ciphertext in this code block need to rescale.*/
            //evaluator.rotate_vector(x_cipher2, 0, gal_keys, rotateAlign_result);
            destination = src;

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
            evaluator.multiply_plain_inplace(destination.m, Utk_plain_1);

            int d_min = l>n?n:l;
            for(int k = 1; k < d_min; k++)
            {
                flag = 0;
                Ciphertext tmp;
                evaluator.rotate_vector(src.m, n * k, gal_keys, tmp);

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
                    evaluator.add_inplace(destination.m, tmp);
                }

                flag = 0;
                evaluator.rotate_vector(src.m, slot_count - Ut_edge + n * k, gal_keys, tmp);

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
                evaluator.add_inplace(destination.m, tmp);
            }
            evaluator.rescale_to_next_inplace(destination.m);
        }
        else{
            destination = src;
        }
    }
}


void Sum1DNew(Cipher_Matrix& src, Cipher_Matrix& destination, Evaluator& evaluator, GaloisKeys& gal_keys, int slot_count)
{
    destination = src;
    int D0 = src.col[1];
    int D1 = src.row[1];
    int d_dim = D0 * D1;
    int step = 1;//question: log2(slot_count/d_dim) is an interger?
    for(int k = 1; k <= log2(slot_count/d_dim); k++)
    {
        Ciphertext tmp;
        evaluator.rotate_vector(destination.m, -step*d_dim, gal_keys, tmp);
        evaluator.add_inplace(destination.m, tmp);
        step *= 2;
    }
    int k = log2(D1/src.row[0]);
    step = pow(2, k - 1);
    for(; k >= 1; k--)
    {
        Ciphertext tmp;
        evaluator.rotate_vector(destination.m, - step * src.row[0], gal_keys, tmp);
        evaluator.add_inplace(destination.m, tmp);
        step /= 2;
    }
}