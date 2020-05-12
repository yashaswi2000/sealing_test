#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "seal.h"
#include "seal_t.h" /* print_string */
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_utils.h"
#include "sgx_key.h"
#include "string.h"
#include "stdlib.h"

char secrets[BUFSIZ] = "Yashaswi";
char aad_mac_text[BUFSIZ] = "mac text";

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
    ocall_seal_sample(buf);
}

int ecall_seal_sample(int *value)
{
  printf("IN SEAL\n");
  printf("%d\n",*value);
  int temp = *value;
  temp = temp*temp+1;
  *value = temp;
  return 0;
}

void ecall_example(const char* str)
{
	//const char *key = (char*)str;
	ocall_seal_sample(str);
}

uint32_t get_sealed_data_size()
{
	return sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text),(uint32_t)strlen(secrets));
}

sgx_status_t seal_data(uint8_t* sealed_blob, uint32_t data_size)
{
	uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text),(uint32_t)strlen(secrets));
	if (sealed_data_size == UINT32_MAX)
	        return SGX_ERROR_UNEXPECTED;
	if (sealed_data_size > data_size)
	      	return SGX_ERROR_INVALID_PARAMETER;
	uint8_t* temp = (uint8_t *)malloc(sealed_data_size);
	if(temp==NULL)
	{
		return SGX_ERROR_OUT_OF_MEMORY;
	}
	sgx_status_t result = sgx_seal_data((uint32_t)strlen(aad_mac_text),(const uint8_t*)aad_mac_text,(uint32_t)strlen(secrets),
	(const uint8_t*)secrets,
	sealed_data_size,
	(sgx_sealed_data_t*)temp
	);
	if(result == SGX_SUCCESS)
	{
		memcpy(sealed_blob,temp,sealed_data_size);
	}
	const sgx_report_t *out = sgx_self_report();
	if(out!=NULL)
	{
		ocall_sample(out->key_id.id);

	}
	free(temp);
	return result;
}



