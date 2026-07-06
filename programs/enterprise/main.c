#include <psa/crypto.h>
#include <string.h>

static uint8_t l_HostPlaintext[] = "Salutations from HOST.";
static uint8_t l_SmibPlaintext[] = "Salutations from SMIB.";

psa_status_t CLI_PrintKey(psa_key_id_t keyId);

psa_status_t CLI_CreateEccKey(psa_key_id_t keyId);

psa_status_t CLI_GetPublicKey(
        psa_key_id_t keyId,
        uint8_t *pPublicKey,
        size_t publicKeyByteSize,
        size_t *pPublicKeyWrittenByteCount);

psa_status_t CLI_CreateSharedKey(
        psa_key_id_t privateKeyId,
        const uint8_t *pPeerKey,
        size_t peerKeyByteSize,
        psa_key_id_t derivedKeyId);

psa_status_t CLI_CreateSessionKey(
        psa_key_id_t sharedKeyId,
        const uint8_t *pInputData,
        size_t inputDataByteSize,
        psa_key_id_t sessionKeyId);

psa_status_t CLI_Encrypt(
        psa_key_id_t keyId,
        uint64_t salt,
        uint32_t counter,
        const uint8_t *pPlaintext,
        size_t plaintextByteSize,
        uint8_t *pCiphertext,
        size_t ciphertextByteSize,
        size_t *pCiphertextWrittenByteCount,
        uint8_t *pMac,
        size_t macByteSize,
        size_t *pMacWrittenByteCount);

psa_status_t CLI_Decrypt(
        psa_key_id_t keyId,
        uint64_t salt,
        uint32_t counter,
        const uint8_t *pCiphertext,
        size_t ciphertextByteSize,
        const uint8_t *pMac,
        size_t macByteSize,
        uint8_t *pPlaintext,
        size_t plaintextByteSize,
        size_t *pPlaintextWrittenByteCount);

int main(int argc, char **argv) {
    int exitCode = 1;
    // TODO: Utilize.
    psa_key_id_t masterKeyId = PSA_KEY_ID_USER_MIN;
    psa_key_id_t hostOriginKeyId = PSA_KEY_ID_USER_MIN + 1;
    psa_key_id_t smibOriginKeyId = PSA_KEY_ID_USER_MIN + 2;
    psa_key_id_t hostSharedKeyId = PSA_KEY_ID_USER_MIN + 3;
    psa_key_id_t smibSharedKeyId = PSA_KEY_ID_USER_MIN + 4;
    psa_key_id_t hostSessionKeyId = PSA_KEY_ID_USER_MIN + 5;
    psa_key_id_t smibSessionKeyId = PSA_KEY_ID_USER_MIN + 6;
    psa_key_id_t sourceKeyIds[3] = {masterKeyId, hostOriginKeyId, smibOriginKeyId};
    uint8_t sourceKeyIdCount = sizeof(sourceKeyIds) / sizeof(sourceKeyIds[0]);
    psa_key_id_t derivedKeyIds[4] = {hostSharedKeyId, smibSharedKeyId, hostSessionKeyId, smibSessionKeyId};
    uint8_t derivedKeyIdCount = sizeof(derivedKeyIds) / sizeof(derivedKeyIds[0]);

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize the PSA Crypto library. Status = %d\n", status);
        goto CLEAN_UP;
    }

    for (uint8_t i = 0; i < sourceKeyIdCount; i++) {
        status = CLI_CreateEccKey(sourceKeyIds[i]);
        if (status != PSA_SUCCESS) {
            printf("Failed to create an ECC key with ID %d. Status = %d\n", sourceKeyIds[i], status);
            goto CLEAN_UP;
        }

        status = CLI_PrintKey(sourceKeyIds[i]);
        if (status != PSA_SUCCESS) {
            printf("Failed to print the key with ID %d. Status = %d\n", sourceKeyIds[i], status);
            goto CLEAN_UP;
        }
    }

    size_t writtenByteCount = 0;

    uint8_t hostOriginPublicKey[65];
    status = CLI_GetPublicKey(
            hostOriginKeyId,
            hostOriginPublicKey,
            sizeof(hostOriginPublicKey),
            &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
                "Failed to get the public key for a key with ID %d. Status = %d\n",
                hostOriginKeyId,
                status);
        goto CLEAN_UP;
    }

    uint8_t smibOriginPublicKey[65];
    status = CLI_GetPublicKey(
            smibOriginKeyId,
            smibOriginPublicKey,
            sizeof(smibOriginPublicKey),
            &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
                "Failed to get the public key for a key with ID %d. Status = %d\n",
                smibOriginKeyId,
                status);
        goto CLEAN_UP;
    }

    status = CLI_CreateSharedKey(
            hostOriginKeyId,
            smibOriginPublicKey,
            sizeof(smibOriginPublicKey),
            hostSharedKeyId);
    if (status != PSA_SUCCESS) {
        printf(
                "Failed to create a shared key with ID %d. Status = %d\n",
                hostSharedKeyId,
                status);
        goto CLEAN_UP;
    }

    status = CLI_PrintKey(hostSharedKeyId);
    if (status != PSA_SUCCESS) {
        printf("Failed to print the key with ID %d. Status = %d\n", hostSharedKeyId, status);
        goto CLEAN_UP;
    }

    status = CLI_CreateSharedKey(
            smibOriginKeyId,
            hostOriginPublicKey,
            sizeof(hostOriginPublicKey),
            smibSharedKeyId);
    if (status != PSA_SUCCESS) {
        printf(
                "Failed to create a shared key with ID %d. Status = %d\n",
                smibSharedKeyId,
                status);
        goto CLEAN_UP;
    }

    status = CLI_PrintKey(smibSharedKeyId);
    if (status != PSA_SUCCESS) {
        printf("Failed to print the key with ID %d. Status = %d\n", smibSharedKeyId, status);
        goto CLEAN_UP;
    }

    uint8_t derivationInput[19] = {
            // Host Session Seed
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            // SMIB Session Seed
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            // Session UID
            0xc1, 0xc2, 0xc3
    };

    status = CLI_CreateSessionKey(
            hostSharedKeyId,
            derivationInput,
            sizeof(derivationInput),
            hostSessionKeyId);
    if (status != PSA_SUCCESS) {
        printf("Failed to create a session key with ID %d. Status = %d\n", hostSessionKeyId, status);
        goto CLEAN_UP;
    }

    status = CLI_PrintKey(hostSessionKeyId);
    if (status != PSA_SUCCESS) {
        printf("Failed to print the key with ID %d. Status = %d\n", hostSessionKeyId, status);
        goto CLEAN_UP;
    }

    status = CLI_CreateSessionKey(
            smibSharedKeyId,
            derivationInput,
            sizeof(derivationInput),
            smibSessionKeyId);
    if (status != PSA_SUCCESS) {
        printf("Failed to create a session key with ID %d. Status = %d\n", smibSessionKeyId, status);
        goto CLEAN_UP;
    }

    status = CLI_PrintKey(smibSessionKeyId);
    if (status != PSA_SUCCESS) {
        printf("Failed to print the key with ID %d. Status = %d\n", smibSessionKeyId, status);
        goto CLEAN_UP;
    }

    uint64_t salt = 25;
    uint32_t counter = 4;
    uint8_t plaintext[128];
    uint8_t ciphertext[128];
    uint8_t mac[16];

    size_t ciphertextWrittenByteCount = 0;
    size_t macWrittenByteCount = 0;
    status = CLI_Encrypt(
            hostSessionKeyId,
            salt,
            counter,
            l_HostPlaintext,
            sizeof(l_HostPlaintext),
            ciphertext,
            sizeof(ciphertext),
            &ciphertextWrittenByteCount,
            mac,
            sizeof(mac),
            &macWrittenByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to encrypt data with a key with ID %d. Status = %d\n", hostSessionKeyId, status);
        goto CLEAN_UP;
    }

    status = CLI_Decrypt(
            smibSessionKeyId,
            salt,
            counter,
            ciphertext,
            ciphertextWrittenByteCount,
            mac,
            macWrittenByteCount,
            plaintext,
            sizeof(plaintext),
            &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to decrypt data with a key with ID %d. Status = %d\n", smibSessionKeyId, status);
        goto CLEAN_UP;
    }

    printf("Plaintext Decrypted by SMIB = '");
    for (size_t i = 0; i < writtenByteCount; i++) {
        if (plaintext[i] == 0) {
            continue;
        }

        printf("%c", plaintext[i]);
    }
    printf("'\n");

    status = CLI_Encrypt(
            smibSessionKeyId,
            salt,
            counter,
            l_SmibPlaintext,
            sizeof(l_SmibPlaintext),
            ciphertext,
            sizeof(ciphertext),
            &ciphertextWrittenByteCount,
            mac,
            sizeof(mac),
            &macWrittenByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to encrypt data with a key with ID %d. Status = %d\n", smibSessionKeyId, status);
        goto CLEAN_UP;
    }

    status = CLI_Decrypt(
            hostSessionKeyId,
            salt,
            counter,
            ciphertext,
            ciphertextWrittenByteCount,
            mac,
            macWrittenByteCount,
            plaintext,
            sizeof(plaintext),
            &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to decrypt data with a key with ID %d. Status = %d\n", hostSessionKeyId, status);
        goto CLEAN_UP;
    }

    printf("Plaintext Decrypted by HOST = '");
    for (size_t i = 0; i < writtenByteCount; i++) {
        if (plaintext[i] == 0) {
            continue;
        }

        printf("%c", plaintext[i]);
    }
    printf("'\n");

    exitCode = 0;

    CLEAN_UP:
    for (uint8_t i = 0; i < sourceKeyIdCount; i++) {
        (void) psa_destroy_key(sourceKeyIds[i]);
    }

    for (uint8_t i = 0; i < derivedKeyIdCount; i++) {
        (void) psa_destroy_key(derivedKeyIds[i]);
    }

    return exitCode;
}

psa_status_t CLI_PrintKey(psa_key_id_t keyId) {
    uint8_t keyBuffer[128];
    size_t writtenByteCount = 0;
    psa_status_t status = psa_export_key(
            keyId,
            keyBuffer,
            sizeof(keyBuffer),
            &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to export a key with ID %d. Status = %d\n", keyId, status);
        return status;
    }

    printf("Key with ID %d = ", keyId);
    for (size_t i = 0; i < writtenByteCount; i++) {
        printf("%02x", keyBuffer[i]);
    }
    printf("\n");

    return PSA_SUCCESS;
}

psa_status_t CLI_CreateEccKey(psa_key_id_t keyId) {
    psa_key_attributes_t keyAttributes = psa_key_attributes_init();
    psa_set_key_id(&keyAttributes, keyId);
    psa_set_key_lifetime(&keyAttributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_type(&keyAttributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&keyAttributes, 256);
    psa_set_key_usage_flags(&keyAttributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&keyAttributes, PSA_ALG_ECDH);
    psa_status_t status = psa_generate_key(&keyAttributes, &keyId);

    psa_reset_key_attributes(&keyAttributes);
    return status;
}

psa_status_t CLI_GetPublicKey(
        psa_key_id_t keyId,
        uint8_t *pPublicKey,
        size_t publicKeyByteSize,
        size_t *pPublicKeyWrittenByteCount) {
    if (pPublicKey == NULL || pPublicKeyWrittenByteCount == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (publicKeyByteSize < 65) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    return psa_export_public_key(
            keyId,
            pPublicKey,
            publicKeyByteSize,
            pPublicKeyWrittenByteCount);

    // This code is for calculating the compressed public key.
//    if (publicKeyByteCount < 33) {
//        return PSA_ERROR_BUFFER_TOO_SMALL;
//    }
//
//    uint8_t uncompressedPublicKey[65];
//    size_t writtenByteCount = 0;
//    psa_status_t status = psa_export_public_key(
//            keyId,
//            uncompressedPublicKey,
//            sizeof(uncompressedPublicKey),
//            &writtenByteCount);
//    if (status != PSA_SUCCESS) {
//        return status;
//    }
//
//    if (writtenByteCount != 65 || uncompressedPublicKey[0] != 0x04) {
//        return PSA_ERROR_INVALID_ARGUMENT;
//    }
//
//    publicKey[0] = (uncompressedPublicKey[64] % 2 == 0) ? 0x02 : 0x03;
//    (void)memcpy(&publicKey[1], &uncompressedPublicKey[1], 32);
//    return PSA_SUCCESS;
}

psa_status_t CLI_CreateSharedKey(
        psa_key_id_t privateKeyId,
        const uint8_t *pPeerKey,
        size_t peerKeyByteSize,
        psa_key_id_t derivedKeyId) {
    psa_key_attributes_t keyAttributes = psa_key_attributes_init();
    psa_set_key_id(&keyAttributes, derivedKeyId);
    psa_set_key_lifetime(&keyAttributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_type(&keyAttributes, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&keyAttributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&keyAttributes, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_status_t status = psa_key_agreement(
            privateKeyId,
            pPeerKey,
            peerKeyByteSize,
            PSA_ALG_ECDH,
            &keyAttributes,
            &derivedKeyId);

    psa_reset_key_attributes(&keyAttributes);
    return status;
}

psa_status_t CLI_CreateSessionKey(
        psa_key_id_t sharedKeyId,
        const uint8_t *pInputData,
        size_t inputDataByteSize,
        psa_key_id_t sessionKeyId) {
    if (pInputData == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_key_derivation_operation_t operation = psa_key_derivation_operation_init();

    status = psa_key_derivation_setup(&operation, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) {
        printf("Failed to set up a key derivation operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    status = psa_key_derivation_set_capacity(&operation, 256);
    if (status != PSA_SUCCESS) {
        printf("Failed to set the capacity of the key derivation operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    status = psa_key_derivation_input_key(
            &operation,
            PSA_KEY_DERIVATION_INPUT_SECRET,
            sharedKeyId);
    if (status != PSA_SUCCESS) {
        printf(
                "Failed to input the shared key with ID %d into the key derivation operation. Status = %d\n",
                sharedKeyId,
                status);
        goto CLEAN_UP;
    }

    status = psa_key_derivation_input_bytes(
            &operation,
            PSA_KEY_DERIVATION_INPUT_INFO,
            pInputData,
            inputDataByteSize);
    if (status != PSA_SUCCESS) {
        printf("Failed to input bytes into the key derivation operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    psa_key_attributes_t sessionKeyAttributes = psa_key_attributes_init();
    psa_set_key_id(&sessionKeyAttributes, sessionKeyId);
    psa_set_key_lifetime(&sessionKeyAttributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_type(&sessionKeyAttributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&sessionKeyAttributes, 256);
    psa_set_key_usage_flags(
            &sessionKeyAttributes,
            PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&sessionKeyAttributes, PSA_ALG_CCM);
    status = psa_key_derivation_output_key(&sessionKeyAttributes, &operation, &sessionKeyId);
    if (status != PSA_SUCCESS) {
        printf("Failed to output the session key with ID %d. Status = %d\n", sessionKeyId, status);
        goto CLEAN_UP;
    }

    status = PSA_SUCCESS;

    CLEAN_UP:
    (void) psa_key_derivation_abort(&operation);
    return status;
}

psa_status_t CLI_Encrypt(
        psa_key_id_t keyId,
        uint64_t salt,
        uint32_t counter,
        const uint8_t *pPlaintext,
        size_t plaintextByteSize,
        uint8_t *pCiphertext,
        size_t ciphertextByteSize,
        size_t *pCiphertextWrittenByteCount,
        uint8_t *pMac,
        size_t macByteSize,
        size_t *pMacWrittenByteCount) {
    if (pPlaintext == NULL ||
        pCiphertext == NULL ||
        pCiphertextWrittenByteCount == NULL ||
        pMac == NULL ||
        pMacWrittenByteCount == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (macByteSize < 16) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_aead_operation_t operation = psa_aead_operation_init();
    status = psa_aead_encrypt_setup(&operation, keyId, PSA_ALG_CCM);
    if (status != PSA_SUCCESS) {
        printf("Failed to set up an AEAD encryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    status = psa_aead_set_lengths(&operation, 0, plaintextByteSize);
    if (status != PSA_SUCCESS) {
        printf("Failed to set the lengths of the AEAD encryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    uint8_t nonce[12] = {0};
    nonce[0] = (uint8_t) (salt << 56);
    nonce[1] = (uint8_t) (salt << 48);
    nonce[2] = (uint8_t) (salt << 40);
    nonce[3] = (uint8_t) (salt << 32);
    nonce[4] = (uint8_t) (salt << 24);
    nonce[5] = (uint8_t) (salt << 16);
    nonce[6] = (uint8_t) (salt << 8);
    nonce[7] = (uint8_t) (salt);
    nonce[8] = (uint8_t) (counter << 24);
    nonce[9] = (uint8_t) (counter << 16);
    nonce[10] = (uint8_t) (counter << 8);
    nonce[11] = (uint8_t) (counter);
    status = psa_aead_set_nonce(&operation, nonce, sizeof(nonce));
    if (status != PSA_SUCCESS) {
        printf("Failed to set the nonce for an AEAD encryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    uint8_t *pCiphertextItr = pCiphertext;
    size_t ciphertextUpdateByteCount = 0;
    status = psa_aead_update(
            &operation,
            pPlaintext,
            plaintextByteSize,
            pCiphertextItr,
            ciphertextByteSize,
            &ciphertextUpdateByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to update an AEAD encryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    pCiphertextItr += ciphertextUpdateByteCount;
    status = psa_aead_finish(
            &operation,
            pCiphertextItr,
            ciphertextByteSize - ciphertextUpdateByteCount,
            pCiphertextWrittenByteCount,
            pMac,
            macByteSize,
            pMacWrittenByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to finish an AEAD encryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    *pCiphertextWrittenByteCount += ciphertextUpdateByteCount;
    status = PSA_SUCCESS;

    CLEAN_UP:
    (void) psa_aead_abort(&operation);
    return status;
}

psa_status_t CLI_Decrypt(
        psa_key_id_t keyId,
        uint64_t salt,
        uint32_t counter,
        const uint8_t *pCiphertext,
        size_t ciphertextByteSize,
        const uint8_t *pMac,
        size_t macByteSize,
        uint8_t *pPlaintext,
        size_t plaintextByteSize,
        size_t *pPlaintextWrittenByteCount) {
    if (pCiphertext == NULL ||
        pMac == NULL ||
        pPlaintext == NULL ||
        pPlaintextWrittenByteCount == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (macByteSize < 16) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_aead_operation_t operation = psa_aead_operation_init();
    status = psa_aead_decrypt_setup(&operation, keyId, PSA_ALG_CCM);
    if (status != PSA_SUCCESS) {
        printf("Failed to set up an AEAD decryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    status = psa_aead_set_lengths(&operation, 0, ciphertextByteSize);
    if (status != PSA_SUCCESS) {
        printf("Failed to set the lengths of the AEAD decryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    uint8_t nonce[12] = {0};
    nonce[0] = (uint8_t) (salt << 56);
    nonce[1] = (uint8_t) (salt << 48);
    nonce[2] = (uint8_t) (salt << 40);
    nonce[3] = (uint8_t) (salt << 32);
    nonce[4] = (uint8_t) (salt << 24);
    nonce[5] = (uint8_t) (salt << 16);
    nonce[6] = (uint8_t) (salt << 8);
    nonce[7] = (uint8_t) (salt);
    nonce[8] = (uint8_t) (counter << 24);
    nonce[9] = (uint8_t) (counter << 16);
    nonce[10] = (uint8_t) (counter << 8);
    nonce[11] = (uint8_t) (counter);
    status = psa_aead_set_nonce(&operation, nonce, sizeof(nonce));
    if (status != PSA_SUCCESS) {
        printf("Failed to set the nonce for an AEAD decryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    uint8_t *pPlaintextItr = pPlaintext;
    size_t plaintextUpdateByteCount = 0;
    status = psa_aead_update(
            &operation,
            pCiphertext,
            ciphertextByteSize,
            pPlaintextItr,
            plaintextByteSize,
            &plaintextUpdateByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to update an AEAD decryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    pPlaintextItr += plaintextUpdateByteCount;
    status = psa_aead_verify(
            &operation,
            pPlaintextItr,
            plaintextByteSize - plaintextUpdateByteCount,
            pPlaintextWrittenByteCount,
            pMac,
            macByteSize);
    if (status != PSA_SUCCESS) {
        printf("Failed to verify an AEAD decryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    *pPlaintextWrittenByteCount += plaintextUpdateByteCount;
    status = PSA_SUCCESS;

    CLEAN_UP:
    (void) psa_aead_abort(&operation);
    return status;
}