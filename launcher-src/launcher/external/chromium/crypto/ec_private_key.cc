// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/ec_private_key.h"

#include <stddef.h>
#include <stdint.h>

#include <utility>

#include "base/logging.h"
#include "crypto/openssl_util.h"
#include "third_party/boringssl/src/include/openssl/bn.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/ec.h"
#include "third_party/boringssl/src/include/openssl/ec_key.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/pkcs8.h"

namespace crypto {

ECPrivateKey::~ECPrivateKey() = default;

// static
std::unique_ptr<ECPrivateKey> ECPrivateKey::Create() {
  OpenSSLErrStackTracer err_tracer(FROM_HERE);

  bssl::UniquePtr<EC_KEY> ec_key(
      EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  if (!ec_key || !EC_KEY_generate_key(ec_key.get()))
    return nullptr;

  std::unique_ptr<ECPrivateKey> result(new ECPrivateKey());
  result->key_.reset(EVP_PKEY_new());
  if (!result->key_ || !EVP_PKEY_set1_EC_KEY(result->key_.get(), ec_key.get()))
    return nullptr;

  CHECK_EQ(EVP_PKEY_EC, EVP_PKEY_id(result->key_.get()));
  return result;
}

// static
std::unique_ptr<ECPrivateKey> ECPrivateKey::CreateFromPrivateKeyInfo(
    const std::vector<uint8_t>& input) {
  OpenSSLErrStackTracer err_tracer(FROM_HERE);

  CBS cbs;
  CBS_init(&cbs, input.data(), input.size());
  bssl::UniquePtr<EVP_PKEY> pkey(EVP_parse_private_key(&cbs));
  if (!pkey || CBS_len(&cbs) != 0 || EVP_PKEY_id(pkey.get()) != EVP_PKEY_EC)
    return nullptr;

  std::unique_ptr<ECPrivateKey> result(new ECPrivateKey());
  result->key_ = std::move(pkey);
  return result;
}

// static
std::unique_ptr<ECPrivateKey> ECPrivateKey::CreateFromEncryptedPrivateKeyInfo(
    const std::vector<uint8_t>& encrypted_private_key_info) {
  OpenSSLErrStackTracer err_tracer(FROM_HERE);

  CBS cbs;
  CBS_init(&cbs, encrypted_private_key_info.data(),
           encrypted_private_key_info.size());
  bssl::UniquePtr<EVP_PKEY> pkey(
      PKCS8_parse_encrypted_private_key(&cbs, "", 0));

  // Hack for reading keys generated by an older version of the OpenSSL code.
  // Some implementations encode the empty password as "\0\0" (passwords are
  // normally encoded in big-endian UCS-2 with a NUL terminator) and some
  // encode as the empty string. PKCS8_parse_encrypted_private_key
  // distinguishes the two by whether the password is nullptr.
  if (!pkey) {
    CBS_init(&cbs, encrypted_private_key_info.data(),
             encrypted_private_key_info.size());
    pkey.reset(PKCS8_parse_encrypted_private_key(&cbs, nullptr, 0));
  }

  if (!pkey || CBS_len(&cbs) != 0 || EVP_PKEY_id(pkey.get()) != EVP_PKEY_EC)
    return nullptr;

  std::unique_ptr<ECPrivateKey> result(new ECPrivateKey());
  result->key_ = std::move(pkey);
  return result;
}

std::unique_ptr<ECPrivateKey> ECPrivateKey::Copy() const {
  std::unique_ptr<ECPrivateKey> copy(new ECPrivateKey());
  if (key_) {
    EVP_PKEY_up_ref(key_.get());
    copy->key_.reset(key_.get());
  }
  return copy;
}

bool ECPrivateKey::ExportPrivateKey(std::vector<uint8_t>* output) const {
  OpenSSLErrStackTracer err_tracer(FROM_HERE);
  uint8_t* der;
  size_t der_len;
  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), 0) ||
      !EVP_marshal_private_key(cbb.get(), key_.get()) ||
      !CBB_finish(cbb.get(), &der, &der_len)) {
    return false;
  }
  output->assign(der, der + der_len);
  OPENSSL_free(der);
  return true;
}

bool ECPrivateKey::ExportEncryptedPrivateKey(
    std::vector<uint8_t>* output) const {
  OpenSSLErrStackTracer err_tracer(FROM_HERE);

  // Encrypt the object.
  // NOTE: NSS uses SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC
  // so use NID_pbe_WithSHA1And3_Key_TripleDES_CBC which should be the OpenSSL
  // equivalent.
  uint8_t* der;
  size_t der_len;
  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), 0) ||
      !PKCS8_marshal_encrypted_private_key(
          cbb.get(), NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
          nullptr /* cipher */, nullptr /* no password */, 0 /* pass_len */,
          nullptr /* salt */, 0 /* salt_len */, 1 /* iterations */,
          key_.get()) ||
      !CBB_finish(cbb.get(), &der, &der_len)) {
    return false;
  }
  output->assign(der, der + der_len);
  OPENSSL_free(der);
  return true;
}

bool ECPrivateKey::ExportPublicKey(std::vector<uint8_t>* output) const {
  OpenSSLErrStackTracer err_tracer(FROM_HERE);
  uint8_t *der;
  size_t der_len;
  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), 0) ||
      !EVP_marshal_public_key(cbb.get(), key_.get()) ||
      !CBB_finish(cbb.get(), &der, &der_len)) {
    return false;
  }
  output->assign(der, der + der_len);
  OPENSSL_free(der);
  return true;
}

bool ECPrivateKey::ExportRawPublicKey(std::string* output) const {
  OpenSSLErrStackTracer err_tracer(FROM_HERE);

  // Export the x and y field elements as 32-byte, big-endian numbers. (This is
  // the same as X9.62 uncompressed form without the leading 0x04 byte.)
  EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(key_.get());
  bssl::UniquePtr<BIGNUM> x(BN_new());
  bssl::UniquePtr<BIGNUM> y(BN_new());
  uint8_t buf[64];
  if (!x || !y ||
      !EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(ec_key),
                                           EC_KEY_get0_public_key(ec_key),
                                           x.get(), y.get(), nullptr) ||
      !BN_bn2bin_padded(buf, 32, x.get()) ||
      !BN_bn2bin_padded(buf + 32, 32, y.get())) {
    return false;
  }

  output->assign(reinterpret_cast<const char*>(buf), sizeof(buf));
  return true;
}

ECPrivateKey::ECPrivateKey() = default;

}  // namespace crypto
