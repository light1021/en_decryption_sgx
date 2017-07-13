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
#define KEYLEN  16
#define IVLEN   12
#define GMACLEN 16

const char * path = "encryptcontext";

uint8_t gmac_out[16];
const uint8_t key[16]={'1'};

typedef struct encrypt_ctx
{
    uint8_t key[KEYLEN];
    uint8_t iv[IVLEN];
    uint8_t gmac[GMACLEN];
}encrypt_ctx;

encrypt_ctx ctx;

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
}


/*ecall function for file encrypt
* crypt: encrypted file buffer
* plain: Plain text buffer
* size:  plain size
*/

void ecall_encrypt(uint8_t *plain, uint8_t *crypt, size_t size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
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

/*ecall function for file decrypt
* crypt: encrypted file buffer
* plain: Plain text buffer
* size:  crypt size
*/
void ecall_decrypt(uint8_t *crypt, uint8_t *plain, size_t size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
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


/*generate AES key
    key: buffer to store key
    size: key size
*/
void generate_key(uint8_t * key, size_t size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_read_rand(key , size);
}

/*generate AES IV
    key: buffer to store IV
    size: IV size
*/
void generate_iv(uint8_t * iv, size_t size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_read_rand(iv, size);
}

/*initialize encrypt context
    
*/
void encrypt_ctx_init()
{
    if()
    {
        generate_iv(ctx.iv, IVLEN);
        generate_key(ctx.key, KEYLEN);
        for (int i = 0; i < GMACLEN; ++i)
        {
            ctx.gmac[i]=0;
        }
        encrypt_ctx_seal();
    }else{
        encrypt_ctx_unseal();
    }
}

/*seal context to disk file
*/
void encrypt_ctx_seal()
{

    size_t size = sgx_calc_sealed_data_size(0,sizeof(ctx));
    uint8_t * temp = malloc(sizeof(ctx));
    uint8_t * sealeddata = malloc(size*sizeof(uint8_t);
    memcpy(temp, &ctx, sizeof(ctx));
    ret = sgx_seal_data(
        0, 
        NULL, 
        sizeof(ctx),
        (uint8_t *)temp,
        size, 
        (sgx_sealed_data_t *)sealeddata
        );

    ocall_save_ctx(path, sealeddata, size);
}

/*unseal context from disk file
*/
void encrypt_ctx_unseal()
{
    size_t size = sgx_calc_sealed_data_size(0,sizeof(ctx));
    uint8_t * data = malloc(size*sizeof(uint8_t));
    uint8_t * temp = malloc(sizeof(ctx)); 
    
    /*get secret from disk file*/
    ocall_get_secret(path, data, size);
    
    ret = sgx_unseal_data(
        (const sgx_sealed_data_t*)data,
        NULL, 
        0,
        temp,
        &length
        );
    memcpy(&ctx, temp, sizeof(ctx));
}