#include <psa/crypto.h>

// PSA_ALG_HMAC(PSA_ALG_SHA_256)
// PSA_ALG_HKDF(PSA_ALG_SHA_256)
// PSA_ALG_CCM

psa_status_t CLI_CreateEccKey(psa_key_id_t keyId);

int main(int argc, char **argv) {
    int exitCode = 1;
    psa_key_id_t masterKeyId = PSA_KEY_ID_USER_MIN;
    psa_key_id_t hostKeyId = PSA_KEY_ID_USER_MIN + 1;
    psa_key_id_t smibKeyId = PSA_KEY_ID_USER_MIN + 2;
    psa_key_id_t sessionKeyId = PSA_KEY_ID_USER_MIN + 3;
    psa_key_derivation_operation_t keyDerivationOperation = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_id_t sourceKeyIds[3] = {masterKeyId, hostKeyId, smibKeyId};
    uint8_t sourceKeyIdCount = sizeof(sourceKeyIds) / sizeof(sourceKeyIds[0]);

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize the PSA Crypto library. Status = %d\n", status);
        goto CLEAN_UP;
    }

    for (uint8_t i = 0; i < sourceKeyIdCount; i++) {
        status = CLI_CreateEccKey(sourceKeyIds[i]);
        if (status != PSA_SUCCESS) {
            printf("Failed to create ECC key with ID %d. Status = %d\n", sourceKeyIds[i], status);
            goto CLEAN_UP;
        }
    }

    status = psa_key_derivation_setup(&keyDerivationOperation, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) {
        printf("Failed to set up a key derivation operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    status = psa_key_derivation_set_capacity(&keyDerivationOperation, 256);
    if (status != PSA_SUCCESS) {
        printf("Failed to set the capacity of the key derivation operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    for (uint8_t i = 0; i < sourceKeyIdCount; i++) {
        status = psa_key_derivation_input_key(
                &keyDerivationOperation,
                PSA_KEY_DERIVATION_INPUT_SECRET,
                sourceKeyIds[i]);
        if (status != PSA_SUCCESS) {
            printf(
                    "Failed to input key with ID %d into the key derivation operation. Status = %d\n",
                    sourceKeyIds[i],
                    status);
            goto CLEAN_UP;
        }
    }

    uint8_t derivationInput[19] = {
            // Host Session Seed
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            // SMIB Session Seed
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            // Session UID
            0xc1, 0xc2, 0xc3
    };
    status = psa_key_derivation_input_bytes(
            &keyDerivationOperation,
            PSA_KEY_DERIVATION_INPUT_INFO,
            derivationInput,
            sizeof(derivationInput));
    if (status != PSA_SUCCESS) {
        printf("Failed to input bytes into the key derivation operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    psa_key_attributes_t sessionKeyAttributes = psa_key_attributes_init();
    psa_set_key_id(&sessionKeyAttributes, sessionKeyId);
    psa_set_key_lifetime(&sessionKeyAttributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_type(&sessionKeyAttributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&sessionKeyAttributes, 256);
    psa_set_key_usage_flags(&sessionKeyAttributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&sessionKeyAttributes, PSA_ALG_CCM);

    status = psa_key_derivation_output_key(&sessionKeyAttributes, &keyDerivationOperation, &sessionKeyId);
    if (status != PSA_SUCCESS) {
        printf("Failed to output the derived key with ID %d. Status = %d\n", sessionKeyId, status);
        goto CLEAN_UP;
    }

    exitCode = 0;

    CLEAN_UP:
    for (uint8_t i = 0; i < sourceKeyIdCount; i++) {
        (void) psa_destroy_key(sourceKeyIds[i]);
    }

    (void) psa_destroy_key(sessionKeyId);
    (void) psa_key_derivation_abort(&keyDerivationOperation);

    return exitCode;
}

psa_status_t CLI_CreateEccKey(psa_key_id_t keyId) {
    psa_key_attributes_t keyAttributes = psa_key_attributes_init();
    psa_set_key_id(&keyAttributes, keyId);
    psa_set_key_lifetime(&keyAttributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_type(&keyAttributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&keyAttributes, 256);
    psa_set_key_usage_flags(&keyAttributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&keyAttributes, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_status_t status = psa_generate_key(&keyAttributes, &keyId);

    psa_reset_key_attributes(&keyAttributes);
    return status;
}