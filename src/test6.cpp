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
    size_t col[2] = {0};
    size_t row[2] = {0};
    Cipher_Matrix() {};
    ~Cipher_Matrix() {};

    Cipher_Matrix& operator = (Cipher_Matrix& x)
    {
        col[0] = x.col[0];
        col[1] = x.col[1];
        row[0] = x.row[0];
        row[1] = x.row[1];
        m = x.m;
        return *this;
    }
};

void Init_Matrix(Cipher_Matrix& src, int col, int row, int D0, int D1, CKKSEncoder &encoder, Encryptor &encryptor, int slot_count, double scale);

void Replicate1DNew(Cipher_Matrix& src, Cipher_Matrix& destination, int dim, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys);

void Rotate1DNew(Cipher_Matrix& src, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, int dim, int step, int slot_count, double scale);

void RotateAlignNew(Cipher_Matrix& src, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, int dim, int slot_count, double scale);

void Sum1DNew(Cipher_Matrix& src, Cipher_Matrix& destination, Evaluator& evaluator, GaloisKeys& gal_keys, int slot_count);

void FHE_MatMultMain(Cipher_Matrix& m1, Cipher_Matrix& m2, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, Encryptor& encryptor, GaloisKeys& gal_keys, int slot_count, double scale);

void Homo_mat_mult_min(Cipher_Matrix& m1, Cipher_Matrix& m2, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, Encryptor& encryptor, GaloisKeys& gal_keys, int slot_count, double scale);

void Homo_mat_mult_med(Cipher_Matrix& m1, Cipher_Matrix& m2, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, Encryptor& encryptor, GaloisKeys& gal_keys, int slot_count, double scale);

void Homo_mat_mult_max(Cipher_Matrix& m1, Cipher_Matrix& m2, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, Encryptor& encryptor, GaloisKeys& gal_keys, int slot_count, double scale);

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
    int m = 0, l = 0, n = 0,flag;
	cout << "Input the number of columns and rows of the matrix" << endl;
	cin >> m >> l >> n;

    int D0, D1 = 0;
    if (l <= m && l <= n)
    {
        D0 = m, D1 = n;
        flag = 0;
    }
    else if (l >= m && l >= n)
    {
        D0 = D1 = l;
        flag = 1;
    }
    else
    {
        m > n ? (D0 = m, D1 = l) : (D0 = l, D1 = n);
        flag = 2;
    }

    Cipher_Matrix x_cipher1;
    Init_Matrix(x_cipher1, m, l, D0, D1, encoder, encryptor, slot_count, scale);

    Cipher_Matrix x_cipher2;
    Init_Matrix(x_cipher2, l, n, D0, D1, encoder, encryptor, slot_count, scale);
    
/*-------------------------Matrix_Multiply-------------------------------------------------*/
    
    Cipher_Matrix dest;
    time_t t1, t2;
    t1 = time(NULL);
    switch(flag)
    {
    case 0:
        Homo_mat_mult_min(x_cipher1, x_cipher2, dest, encoder, evaluator, encryptor, gal_keys, slot_count, scale);
        break;
    case 1:
        Homo_mat_mult_max(x_cipher1, x_cipher2, dest, encoder, evaluator, encryptor, gal_keys, slot_count, scale);
        break;
    default:
        Homo_mat_mult_med(x_cipher1, x_cipher2, dest, encoder, evaluator, encryptor, gal_keys, slot_count, scale);
    }


    t2 = time(NULL);
    
/*----------------------------Print the Result----------------------------------------*/

    cout << "    Result:" << endl;
    Plaintext plain_result_m1;
    vector<double> result;
    decryptor.decrypt(dest.m, plain_result_m1);
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


void Replicate1DNew(Cipher_Matrix& src, Cipher_Matrix& destination, int dim, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys)
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


void Rotate1DNew(Cipher_Matrix& src, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, int dim, int step, int slot_count, double scale)
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


void RotateAlignNew(Cipher_Matrix& src, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, GaloisKeys& gal_keys, int dim, int slot_count, double scale)
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
    cout << "  Sum1DNew:" << endl;
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


void FHE_MatMultMain(Cipher_Matrix& m1, Cipher_Matrix& m2, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, Encryptor& encryptor, GaloisKeys& gal_keys, int slot_count, double scale)
{
    cout << "  FHE_MatMultMain:" << endl;
    Cipher_Matrix A0;
    Cipher_Matrix B0;
    Cipher_Matrix Ax;
    Cipher_Matrix Bx;

    destination.col[0] = m1.col[0];
    destination.row[0] = m2.row[0];
    destination.col[1] = m1.col[1];
    destination.row[1] = m2.row[1];

    cout << "    + The scale of x_cipher before RotateAlign: " << log2(m1.m.scale()) << endl;
    cout << "    + The parm_id of x_cipher before RotateAlign: " << m1.m.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before RotateAlign: " << m1.m.coeff_modulus_size() << endl;
    cout << endl;

    RotateAlignNew(m1, A0, encoder, evaluator, gal_keys, 1, slot_count, scale);
    RotateAlignNew(m2, B0, encoder, evaluator, gal_keys, 0, slot_count, scale);
    
    cout << "    + The scale of x_cipher after RotateAlign: " << log2(A0.m.scale()) << endl;
    cout << "    + The parm_id of x_cipher after RotateAlign: " << A0.m.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before RotateAlign: " << A0.m.coeff_modulus_size() << endl;
    cout << endl;
    
    int m = m1.col[0], l = m1.row[0], n = m2.row[0];
    int min_edge = (m < l) ? ((m < n) ? m : n) : ((l < n) ? l : n);
    for (int i = 0; i < min_edge; i++)
    {
        cout << "    for loop:" << i << endl;

        Rotate1DNew(A0, Ax, encoder, evaluator, gal_keys, 1, i, slot_count, scale);
        Rotate1DNew(B0, Bx, encoder, evaluator, gal_keys, 0, i, slot_count, scale);
        Ciphertext tmp;
        
        if (i == 0)evaluator.multiply(Ax.m,Bx.m,destination.m);
        else { evaluator.multiply(Ax.m, Bx.m, tmp); evaluator.add_inplace(destination.m, tmp); }
    }
    evaluator.rescale_to_next_inplace(destination.m);
}


void Homo_mat_mult_min(Cipher_Matrix& m1, Cipher_Matrix& m2, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, Encryptor& encryptor, GaloisKeys& gal_keys, int slot_count, double scale)
{
    Cipher_Matrix A0;
    Cipher_Matrix B0;

    cout << "    + The scale of x_cipher before Replicate1D: " << log2(m1.m.scale()) << endl;
    cout << "    + The parm_id of x_cipher before Replicate1D: " << m1.m.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before Replicate1D: " << m1.m.coeff_modulus_size() << endl;
    cout << endl;

    Replicate1DNew(m1, A0,1, encoder, evaluator, gal_keys);
    Replicate1DNew(m2, B0,0, encoder, evaluator, gal_keys);

    cout << "    + The scale of x_cipher after Replicate1D: " << log2(A0.m.scale()) << endl;
    cout << "    + The parm_id of x_cipher after Replicate1D: " << A0.m.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before Replicate1D: " << A0.m.coeff_modulus_size() << endl;
    cout << endl;

    FHE_MatMultMain(A0, B0, destination, encoder, evaluator, encryptor, gal_keys, slot_count, scale);
}


void Homo_mat_mult_med(Cipher_Matrix& m1, Cipher_Matrix& m2, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, Encryptor& encryptor, GaloisKeys& gal_keys, int slot_count, double scale)
{
    Cipher_Matrix A0;
    Cipher_Matrix B0;
    Cipher_Matrix tmp;

    cout << "    + The scale of x_cipher before Replicate1D: " << log2(m1.m.scale()) << endl;
    cout << "    + The parm_id of x_cipher before Replicate1D: " << m1.m.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before Replicate1D: " << m1.m.coeff_modulus_size() << endl;
    cout << endl;

    //need to judge which matrix is smaller!!!!
    Replicate1DNew(m2, A0, 1, encoder, evaluator, gal_keys);
    Replicate1DNew(A0, B0, 0, encoder, evaluator, gal_keys);

    cout << "    + The scale of x_cipher after Replicate1D: " << log2(B0.m.scale()) << endl;
    cout << "    + The parm_id of x_cipher after Replicate1D: " << B0.m.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before Replicate1D: " << B0.m.coeff_modulus_size() << endl;
    cout << endl;

    evaluator.mod_switch_to_inplace(m1.m, B0.m.parms_id());
    FHE_MatMultMain(m1, B0, tmp, encoder, evaluator, encryptor, gal_keys, slot_count, scale);
    destination = tmp;
    //Sum1DNew(tmp, destination, evaluator, gal_keys,  slot_count);
}


void Homo_mat_mult_max(Cipher_Matrix& m1, Cipher_Matrix& m2, Cipher_Matrix& destination, CKKSEncoder& encoder, Evaluator& evaluator, Encryptor& encryptor, GaloisKeys& gal_keys, int slot_count, double scale)
{
    Cipher_Matrix A0;
    Cipher_Matrix B0;
    Cipher_Matrix tmp;

    cout << "    + The scale of x_cipher before Replicate1D: " << log2(m1.m.scale()) << endl;
    cout << "    + The parm_id of x_cipher before Replicate1D: " << m1.m.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before Replicate1D: " << m1.m.coeff_modulus_size() << endl;
    cout << endl;

    Replicate1DNew(m1, A0,0, encoder, evaluator, gal_keys);
    Replicate1DNew(m2, B0,1, encoder, evaluator, gal_keys);

    cout << "    + The scale of x_cipher after Replicate1D: " << log2(A0.m.scale()) << endl;
    cout << "    + The parm_id of x_cipher after Replicate1D: " << A0.m.parms_id() << endl;
    cout << "    + The coeff_modulus_size of x_cipher before Replicate1D: " << A0.m.coeff_modulus_size() << endl;
    cout << endl;

    FHE_MatMultMain(A0, B0, tmp, encoder, evaluator, encryptor, gal_keys, slot_count, scale);
    destination = tmp;
    //Sum1DNew(tmp, destination, evaluator, gal_keys, slot_count);
}