#include "sgx_trts.h"

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "enclave.h"
#include "enclave_t.h" 
#include <string.h> 
#include <ctype.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>
#include <sgx_tcrypto.h>
uint8_t gmac_out[16];
const uint8_t key[16]={'1'};
/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}


/* ecall_array_in_out:
 *   arr[] will be allocated inside the enclave, content of arr[] will be copied either.
 *   After ECALL returns, the results will be copied to the outside.
 */
void ecall_array_in_out(int arr[4])
{
    for (int i = 0; i < 4; i++) {
        assert(arr[i] == i);
        arr[i] = (3 - i);
    }
    size_t n=4, m=6;
    double src[]={
        1. , 2. , 3. , 4. , 5. , 6. ,
        7. , 8. , 9. , 10., 11., 12.,
        13., 14., 15., 16., 17., 18.,
        19., 20., 21., 22., 23., 24.
    };

    //ocall_dimatcopy('R','T', 3, 4, 1, src, 6, 6, n*m);
    
    uint32_t length = 16;
    uint8_t secret[length];
    uint32_t size = sgx_calc_sealed_data_size(0,sizeof(secret));
    uint8_t sealeddata[size];
    uint32_t ret =0;
    uint8_t unsecret[16];
    ret = sgx_read_rand(secret, 16);
    
    ret = sgx_seal_data(0, NULL, 
                sizeof(secret), (uint8_t *)secret,
                size, (sgx_sealed_data_t *)sealeddata);
    ret = sgx_unseal_data((const sgx_sealed_data_t*)sealeddata, NULL, 0,
        (uint8_t*)unsecret, &length);
    int i=0;
    ocall_print_uint(secret,16);
    ocall_print_uint(sealeddata, size);
    
    uint8_t love[8]={'m', 'e', 'n', 'g', 'j', 'i', 'a', 'n'};
    uint8_t loveec[8];
    uint8_t iv[12]={0};
    uint8_t mac_out[16]; 
    ret = sgx_rijndael128GCM_encrypt(
        &secret,
        &love[0],
        8,
        &loveec[0],
        &iv[0],
        12,
        NULL,
        0,
        &mac_out
    );
    ocall_print_uint(love,8);
    ocall_print_uint(loveec, 8);
    
    uint8_t delove[8];
    //ocall_print_uint(secret, 16);
    ret = sgx_rijndael128GCM_decrypt(
        &secret,
        &loveec[0],
        8,
        &delove[0],
        &iv[0],
        12,
        NULL,
        0,
        &mac_out
    );
    ocall_print_uint(delove,8);

    // CBLAS_LAYOUT    layout;
    // CBLAS_TRANSPOSE transA, transB;

    // const int M=4;//A的行数，C的行数
    // const int N=2;//B的列数，C的列数
    // const int K=3;//A的列数，B的行数
    // const float alpha=1;
    // const float beta=0;
    // const int lda=K;//A的列
    // const int ldb=N;//B的列
    // const int ldc=N;//C的列
    // const float A[12]={1,2,3,4,5,6,7,8,9,8,7,6};
    // const float B[6]={5,4,3,2,1,0};
    // float C[8];
    //If we use mkl in enclave, we can not link enclave.so successfully.
    //cblas_sgemm(layout, transA, transB, M, N, K, alpha, A, lda, B, ldb, beta, C, ldc);
     
}

void ecall_encrypt(uint8_t *plain, uint8_t *crypt, size_t size)
{

    uint32_t ret =0;
    uint8_t iv[12]={0};
    uint8_t mac_out[16];
    ret = sgx_rijndael128GCM_encrypt(
        &key,
        plain,
        size,
        crypt,
        &iv[0],
        12,
        NULL,
        0,
        &gmac_out
    );

}
void ecall_decrypt(uint8_t *crypt, uint8_t *plain, size_t size)
{

    uint32_t ret =0;
    uint8_t iv[12]={0};
    uint8_t mac_out[16];
    ret = sgx_rijndael128GCM_decrypt(
        &key,
        crypt,
        size,
        plain,
        &iv[0],
        12,
        NULL,
        0,
        &gmac_out
    );

}

