#ifndef TF_PSA_CRYPTO_ENTERPRISE_DRIVER_ENTRYPOINTS_H
#define TF_PSA_CRYPTO_ENTERPRISE_DRIVER_ENTRYPOINTS_H

#if defined(MBEDTLS_PSA_ENTERPRISE_DRIVER_ENABLED)
#ifndef PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#define PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
#endif /* MBEDTLS_PSA_ENTERPRISE_DRIVER_ENABLED */

#include "psa/crypto_types.h"

psa_status_t enterprise_transparent_import_key(
        const psa_key_attributes_t *attributes,
        const uint8_t *data,
        size_t data_length,
        uint8_t *key_buffer,
        size_t key_buffer_size,
        size_t *key_buffer_length,
        size_t *bits);

psa_status_t enterprise_transparent_export_public_key(
        const psa_key_attributes_t *attributes,
        const uint8_t *key_buffer,
        size_t key_buffer_size,
        uint8_t *data,
        size_t data_size,
        size_t *data_length);

#endif /* TF_PSA_CRYPTO_ENTERPRISE_DRIVER_ENTRYPOINTS_H */