// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// #include "examples.h"
//
// using namespace std;
// using namespace seal;

#include<iostream>
using namespace std;
#include "seal/seal.h"
#include "time.h"
// #include "seal/example.h"
// #include "seal/seal_helper.h"
using namespace seal;

int main()
{
    int loop = 1;

    long long encode_1 = 0;
    long long encode_x = 0;
    long long enc_x = 0;
    long long relin_xx = 0;
    long long rescale_xx = 0;
    long long sq_x = 0;
    long long rescale_1 = 0;
    long long add_x_1 = 0;
    long long dec_x_1 = 0;
    long long decode_x_1 = 0;

    for (int i = 0; i < loop; i ++){

      EncryptionParameters parms(scheme_type::CKKS);


      size_t poly_modulus_degree = 8192;
      parms.set_poly_modulus_degree(poly_modulus_degree);
      // parms.set_coeff_modulus(CoeffModulus::Create(
      //     poly_modulus_degree, {56,35,35,35,56}));
      parms.set_coeff_modulus(CoeffModulus::Create(
          poly_modulus_degree, { 60, 40, 40, 60 }));


      double scale = pow(2.0, 40);

      auto context = SEALContext::Create(parms);//クラスの宣言のみ
      // print_parameters(context);
      // cout << endl;

      // cout << __FILE__ <<" : "<< __LINE__<<endl;
      KeyGenerator keygen(context);//クラスの宣言のみ
      // cout << __FILE__ <<" : "<< __LINE__<<endl;
      auto public_key = keygen.public_key();
      // cout << __FILE__ <<" : "<< __LINE__<<endl;
      auto secret_key = keygen.secret_key();
      // cout << __FILE__ <<" : "<< __LINE__<<endl;
      auto relin_keys = keygen.relin_keys();
      Encryptor encryptor(context, public_key);
      Evaluator evaluator(context);
      Decryptor decryptor(context, secret_key);

      CKKSEncoder encoder(context);
      size_t slot_count = encoder.slot_count();
      // cout << "Number of slots: " << slot_count << endl;


      Plaintext plain_one;
      clock_t start = clock();
      encoder.encode(1.0, scale, plain_one);
      clock_t end = clock();
      encode_1 += end - start;
      // cout << "print plain_one" <<endl;
      // for (int i = 0; i < 3; i++){
      //   cout << "mod : " << i<<endl;
      //   for (int j = 0; j < 8192; j++){
      //     cout << hex << plain_one.data()[i * 8192 + j] << endl;
      //   }
      // }

      vector<double> input;
      vector<double> true_result;
      input.reserve(slot_count);
      double curr_point = 0;
      double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
      for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
      {
          input.push_back(curr_point);
          true_result.push_back(curr_point * curr_point + 1.0);
      }

      Plaintext x_plain;
      // print_line(__LINE__);
      // cout << "### Encode input vectors. ###" << endl;
      start = clock();
      encoder.encode(input, scale, x_plain);
      end = clock();
      encode_x += end - start;
      // cout << "print x_plain" <<endl;
      // for (int i = 0; i < 3; i++){
      //   cout << "mod : " << i<<endl;
      //   for (int j = 0; j < 8192; j++){
      //     cout << hex << x_plain.data()[i * 8192 + j] << endl;
      //   }
      // }

      Ciphertext x_encrypted;
      // cout << "### Encrypt x ###" << endl;
      start = clock();
      encryptor.encrypt(x_plain, x_encrypted);
      end = clock();
      enc_x += end - start;
      // cout << "print x" << endl;
      // for (int k = 0; k < 2; k++){
      //   for (int i = 0; i < 3; i++){
      //     cout << "key : "<< k << " mod : " << i<<endl;
      //     for (int j = 0; j < 8192; j++){
      //       cout << hex << x_encrypted.data(k)[i * 8192 + j] << endl;
      //     }
      //   }
      // }

      Ciphertext xx_encrypted;
      // print_line(__LINE__);
      // cout << "### Compute x^2 ###" << endl;
      start = clock();
      evaluator.square(x_encrypted, xx_encrypted);
      end = clock();
      sq_x += end - start;
      // cout << "print xx" << endl;
      // for (int k = 0; k < 3; k++){
      //   for (int mod = 0; mod < 3; mod++){
      //     cout << "key " << k << " mod " << mod << endl;
      //     for (int i = 0; i < 8192; i++){
      //       cout << hex << xx_encrypted.data(k)[i + mod * 8192] << endl;
      //     }
      //   }
      // }

      // cout << "### relinearize x^2 ###" << endl;
      start = clock();
      evaluator.relinearize_inplace(xx_encrypted, relin_keys);
      end = clock();
      relin_xx += end - start;
  	  // printf("time:%f[ms]\n", time2);
      // cout << "print xx_relin" << endl;
      // for (int k = 0; k < 2; k++){
      //   for (int mod = 0; mod < 3; mod++){
      //     cout << "key " << k << " mod " << mod << endl;
      //     for (int i = 0; i < 8192; i++){
      //       cout << hex << xx_encrypted.data(k)[i + mod * 8192] << endl;
      //     }
      //   }
      // }

      // cout << "### Rescale x^2 ###"<< endl;
      start = clock();
      evaluator.rescale_to_next_inplace(xx_encrypted);
      end = clock();
      rescale_xx += end - start;
      // cout << "print xx_rescale" << endl;
      // for (int k = 0; k < 2; k++){
      //   for (int mod = 0; mod < 2; mod++){
      //     cout << "key " << k << " mod " << mod << endl;
      //     for (int i = 0; i < 8192; i++){
      //       cout << hex << xx_encrypted.data(k)[i + mod * 8192] << endl;
      //     }
      //   }
      // }


      // cout << "Normalize scales to 2^40." << endl;
      // x1_encrypted.scale() = pow(2.0, 35);
      // x3_encrypted.scale() = pow(2.0, 35);
      xx_encrypted.scale() = pow(2.0, 40);
      // x_encrypted.scale() = pow(2.0, 40);


      // cout << "Normalize encryption parameters to the lowest level." << endl;
      parms_id_type last_parms_id = xx_encrypted.parms_id();

      // cout << "### 1.0 switch last ###" << endl;
      start = clock();
      evaluator.mod_switch_to_inplace(plain_one, last_parms_id);//パラメータの変更のみ
      end = clock();
      rescale_1 += end - start;
      // cout << "print 1.0_last" << endl;
      // for (int k = 0; k < 1; k++){
      //   for (int mod = 0; mod < 1; mod++){
      //     cout << "key " << k << " mod " << mod << endl;
      //     for (int i = 0; i < 8192; i++){
      //       cout << hex << plain_one.data(k)[i + mod * 8192] << endl;
      //     }
      //   }
      // }

      // cout << "### x ^ 2 + 1 ###" << endl;
      start = clock();
      evaluator.add_plain_inplace(xx_encrypted, plain_one);
      end = clock();
      add_x_1 += end - start;
      // cout << "print xx_1 " << endl;
      // for (int k = 0; k < 2; k++){
      //   for (int mod = 0; mod < 1; mod++){
      //     cout << "key " << k << " mod " << mod << endl;
      //     for (int i = 0; i < 8192; i++){
      //       cout << hex << xxx_xx_x_encrypted.data(k)[i + mod * 8192] << endl;
      //     }
      //   }
      // }

      /*
      First print the true result.
      */
      Plaintext plain_result;

      start = clock();
      decryptor.decrypt(xx_encrypted, plain_result);
      end = clock();
      dec_x_1 += end - start;
      // cout << "print plain_result" <<endl;
      // for (int i = 0; i < 1; i++){
      //   cout << "mod : " << i<<endl;
      //   for (int j = 0; j < 8192; j++){
      //     cout << hex << plain_result.data()[i * 8192 + j] << endl;
      //   }
      // }

      vector<double> result;
      start = clock();
      encoder.decode(plain_result, result);
      end = clock();
      decode_x_1 += end - start;
      // cout << "    + Computed result ...... Correct." << endl;
      // cout << "### true_result ###" << endl;
      // for (size_t i = 0; i < input.size(); i++){
      //   cout << true_result[i] << endl;
      // }
      // cout << "### result ###" << endl;
      // cout << "print result" << endl;
      // for (size_t i = 0; i < input.size(); i++){
      //   cout << result[i] << endl;
      // }

      // print_vector(result, 3, 7);
  }

  cout << "encode_1 : " << (double)(encode_1) / CLOCKS_PER_SEC * 1000 / loop << endl;
  cout << "encode_x : " << (double)(encode_x) / CLOCKS_PER_SEC * 1000 / loop << endl;
  cout << "enc_x : " << (double)(enc_x) / CLOCKS_PER_SEC * 1000 / loop << endl;
  cout << "relin_xx : " << (double)(relin_xx) / CLOCKS_PER_SEC * 1000 / loop << endl;
  cout << "rescale_xx : " << (double)(rescale_xx) / CLOCKS_PER_SEC * 1000 / loop << endl;
  cout << "sq_x : " << (double)(sq_x) / CLOCKS_PER_SEC * 1000 / loop << endl;
  cout << "rescale_1 : " << (double)(rescale_1) / CLOCKS_PER_SEC * 1000 / loop << endl;
  cout << "add_x_1 : " << (double)(add_x_1) / CLOCKS_PER_SEC * 1000 / loop << endl;
  cout << "dec_x_1 : " << (double)(dec_x_1) / CLOCKS_PER_SEC * 1000 / loop << endl;
  cout << "decode_x_1 : " << (double)(decode_x_1) / CLOCKS_PER_SEC * 1000 / loop << endl;


}
