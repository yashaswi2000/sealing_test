#include "seal_u.h"
#include <errno.h>

typedef struct ms_ecall_seal_sample_t {
	int ms_retval;
	int* ms_value;
} ms_ecall_seal_sample_t;

typedef struct ms_ecall_example_t {
	const char* ms_str;
	size_t ms_str_len;
} ms_ecall_example_t;

typedef struct ms_get_sealed_data_size_t {
	uint32_t ms_retval;
} ms_get_sealed_data_size_t;

typedef struct ms_seal_data_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_blob;
	uint32_t ms_data_size;
} ms_seal_data_t;

typedef struct ms_ocall_seal_sample_t {
	const char* ms_str;
} ms_ocall_seal_sample_t;

typedef struct ms_ocall_sample_t {
	const uint8_t* ms_A;
} ms_ocall_sample_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL seal_ocall_seal_sample(void* pms)
{
	ms_ocall_seal_sample_t* ms = SGX_CAST(ms_ocall_seal_sample_t*, pms);
	ocall_seal_sample(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL seal_ocall_sample(void* pms)
{
	ms_ocall_sample_t* ms = SGX_CAST(ms_ocall_sample_t*, pms);
	ocall_sample(ms->ms_A);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL seal_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL seal_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL seal_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL seal_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL seal_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[7];
} ocall_table_seal = {
	7,
	{
		(void*)seal_ocall_seal_sample,
		(void*)seal_ocall_sample,
		(void*)seal_sgx_oc_cpuidex,
		(void*)seal_sgx_thread_wait_untrusted_event_ocall,
		(void*)seal_sgx_thread_set_untrusted_event_ocall,
		(void*)seal_sgx_thread_setwait_untrusted_events_ocall,
		(void*)seal_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_seal_sample(sgx_enclave_id_t eid, int* retval, int* value)
{
	sgx_status_t status;
	ms_ecall_seal_sample_t ms;
	ms.ms_value = value;
	status = sgx_ecall(eid, 0, &ocall_table_seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_example(sgx_enclave_id_t eid, const char* str)
{
	sgx_status_t status;
	ms_ecall_example_t ms;
	ms.ms_str = str;
	ms.ms_str_len = str ? strlen(str) + 1 : 0;
	status = sgx_ecall(eid, 1, &ocall_table_seal, &ms);
	return status;
}

sgx_status_t get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval)
{
	sgx_status_t status;
	ms_get_sealed_data_size_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t seal_data(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_blob, uint32_t data_size)
{
	sgx_status_t status;
	ms_seal_data_t ms;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	status = sgx_ecall(eid, 3, &ocall_table_seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

