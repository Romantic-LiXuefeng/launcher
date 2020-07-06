// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/logging.h"
#include "base/optional.h"
#include "net/dns/dns_protocol.h"
#include "net/base/ip_endpoint.h"
#include "net/socket/socket_descriptor.h"
#include <vector>

#ifdef _WIN32
typedef int uid_t;
#endif

namespace net {
namespace android {

// copy from <chromium>/net/android/cert_verify_result_android.h
enum CertVerifyStatusAndroid {
  // Certificate is trusted.
  CERT_VERIFY_STATUS_ANDROID_OK = 0,
  // Certificate verification could not be conducted.
  CERT_VERIFY_STATUS_ANDROID_FAILED = -1,
  // Certificate is not trusted due to non-trusted root of the certificate
  // chain.
  CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT = -2,
  // Certificate is not trusted because it has expired.
  CERT_VERIFY_STATUS_ANDROID_EXPIRED = -3,
  // Certificate is not trusted because it is not valid yet.
  CERT_VERIFY_STATUS_ANDROID_NOT_YET_VALID = -4,
  // Certificate is not trusted because it could not be parsed.
  CERT_VERIFY_STATUS_ANDROID_UNABLE_TO_PARSE = -5,
  // Certificate is not trusted because it has an extendedKeyUsage field, but
  // its value is not correct for a web server.
  CERT_VERIFY_STATUS_ANDROID_INCORRECT_KEY_USAGE = -6,
};

void VerifyX509CertChain(const std::vector<std::string>& cert_chain,
                         const std::string& auth_type,
                         const std::string& host,
                         CertVerifyStatusAndroid* status,
                         bool* is_issued_by_known_root,
                         std::vector<std::string>* verified_chain) {
  // in using, require impletement.
  *status = CERT_VERIFY_STATUS_ANDROID_FAILED;
  *is_issued_by_known_root = false;
}

void AddTestRootCertificate(const uint8_t* cert, size_t len) {
}

void ClearTestRootCertificates() {
}

bool IsCleartextPermitted(const std::string& host) {
  return true;
}

bool HaveOnlyLoopbackAddresses() {
  return true;
}

bool GetMimeTypeFromExtension(const std::string& extension,
                              std::string* result) {
  *result = extension;
  return true;
}

std::string GetTelephonyNetworkCountryIso() {
  return "";
}

std::string GetTelephonyNetworkOperator() {
  return "";
}

std::string GetTelephonySimOperator() {
  return "";
}

bool GetIsRoaming() {
  return false;
}

bool GetIsCaptivePortal() {
  return false;
}

std::string GetWifiSSID() {
  return "";
}

void GetDnsServers(std::vector<IPEndPoint>* dns_servers) {
}

void TagSocket(SocketDescriptor socket, uid_t uid, int32_t tag) {
}

namespace cellular_signal_strength {

base::Optional<int32_t> GetSignalStrengthLevel() {
  int32_t signal_strength_level = 0;

  DCHECK_LE(0, signal_strength_level);
  DCHECK_GE(4, signal_strength_level);

  return signal_strength_level;
}

}  // namespace cellular_signal_strength

}  // namespace android
}  // namespace net
