// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/bip324_suite.h>

#include <crypto/common.h>
#include <crypto/poly1305.h>
#include <crypto/sha256.h>
#include <support/cleanse.h>

#include <assert.h>
#include <cstring>
#include <string.h>

#ifndef HAVE_TIMINGSAFE_BCMP

int timingsafe_bcmp(const unsigned char* b1, const unsigned char* b2, size_t n)
{
    const unsigned char *p1 = b1, *p2 = b2;
    int ret = 0;

    for (; n > 0; n--)
        ret |= *p1++ ^ *p2++;
    return (ret != 0);
}

#endif // TIMINGSAFE_BCMP

BIP324CipherSuite::~BIP324CipherSuite()
{
    memory_cleanse(key_P.data(), key_P.size());
}

void BIP324CipherSuite::CommitToKeys(const Span<const std::byte> data, bool commit_to_L, bool commit_to_P)
{
    if (commit_to_L) {
        fsc20.CommitToKey(data);
    }

    if (commit_to_P) {
        assert(CSHA256::OUTPUT_SIZE == BIP324_KEY_LEN);
        auto hasher = rekey_hasher;
        hasher << MakeUCharSpan(data) << MakeUCharSpan(key_P);
        auto new_key = hasher.GetSHA256();
        memcpy(key_P.data(), new_key.data(), BIP324_KEY_LEN);
    }

    set_nonce();
}

bool BIP324CipherSuite::Crypt(const Span<const std::byte> aad,
                              const Span<const std::byte> input,
                              Span<std::byte> output,
                              BIP324HeaderFlags& flags, bool encrypt)
{
    // check buffer boundaries
    if (
        // if we encrypt, make sure the destination has the space for the encrypted length field, header, contents and MAC
        (encrypt && (output.size() < BIP324_LENGTH_FIELD_LEN + BIP324_HEADER_LEN + input.size() + RFC8439_EXPANSION)) ||
        // if we decrypt, make sure the source contains at least the encrypted header + mac and the destination has the space for the input - MAC - header
        (!encrypt && (input.size() < BIP324_HEADER_LEN + RFC8439_EXPANSION || output.size() < input.size() - BIP324_HEADER_LEN - RFC8439_EXPANSION))) {
        return false;
    }

    if (encrypt) {
        // input is just the contents
        // output will be encrypted contents length + encrypted (header and contents) + mac tag
        uint32_t contents_len = input.size();
        WriteLE32(reinterpret_cast<unsigned char*>(&contents_len), contents_len);

        std::vector<std::byte> header_and_contents(BIP324_HEADER_LEN + input.size());

        memcpy(header_and_contents.data(), &flags, BIP324_HEADER_LEN);
        if (!input.empty()) {
            memcpy(header_and_contents.data() + BIP324_HEADER_LEN, input.data(), input.size());
        }

        auto write_pos = output.data();
        fsc20.Crypt({reinterpret_cast<std::byte*>(&contents_len), BIP324_LENGTH_FIELD_LEN},
                    {write_pos, BIP324_LENGTH_FIELD_LEN});
        write_pos += BIP324_LENGTH_FIELD_LEN;
        RFC8439Encrypt(aad, key_P, nonce, header_and_contents, {write_pos, BIP324_HEADER_LEN + input.size() + RFC8439_EXPANSION});
    } else {
        // we must use BIP324CipherSuite::DecryptLength before calling BIP324CipherSuite::Crypt
        // input is encrypted (header + contents) and the MAC tag i.e. the RFC8439 ciphertext blob
        // decrypted header will be put in flags and output will be plaintext contents.
        std::vector<std::byte> decrypted_header_and_contents(input.size() - RFC8439_EXPANSION);
        auto authenticated = RFC8439Decrypt(aad, key_P, nonce, input, decrypted_header_and_contents);
        if (!authenticated) {
            return false;
        }

        memcpy(&flags, decrypted_header_and_contents.data(), BIP324_HEADER_LEN);
        if (!output.empty()) {
            memcpy(output.data(),
                   decrypted_header_and_contents.data() + BIP324_HEADER_LEN,
                   input.size() - BIP324_HEADER_LEN - RFC8439_EXPANSION);
        }
    }

    packet_counter++;
    if (packet_counter % REKEY_INTERVAL == 0) {
        // Rekey key_P. key_L is automatically re-keyed since we're using a forward-secure version
        // of ChaCha20, FSChacha20
        CommitToKeys({(std::byte*)nullptr, 0}, false, true);
    }
    set_nonce();
    return true;
}

uint32_t BIP324CipherSuite::DecryptLength(const std::array<std::byte, BIP324_LENGTH_FIELD_LEN>& encrypted_length)
{
    std::array<uint8_t, BIP324_LENGTH_FIELD_LEN> length_buffer;
    fsc20.Crypt(encrypted_length, MakeWritableByteSpan(length_buffer));

    return (uint32_t{length_buffer[0]}) |
           (uint32_t{length_buffer[1]} << 8) |
           (uint32_t{length_buffer[2]} << 16);
}
