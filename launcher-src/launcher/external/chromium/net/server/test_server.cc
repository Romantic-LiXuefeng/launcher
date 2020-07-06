// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/server/test_server.h"

#include <utility>

#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/sys_byteorder.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
#include "net/base/net_errors.h"
#include "net/server/http_connection.h"
#include "net/server/http_server_request_info.h"
#include "net/server/http_server_response_info.h"
#include "net/socket/server_socket.h"
#include "net/socket/stream_socket.h"
#include "net/socket/tcp_server_socket.h"

#include <SDL_stdinc.h>
#include <SDL_log.h>

#include "rose_config.hpp"


#include "net/socket/ssl_server_socket.h"

#include <stdint.h>
#include <stdlib.h>
#include <utility>

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/compiler_specific.h"
#include "base/containers/queue.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/stl_util.h"
// #include "base/test/task_environment.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
#include "crypto/nss_util.h"
#include "crypto/rsa_private_key.h"
#include "crypto/signature_creator.h"
#include "net/base/address_list.h"
#include "net/base/completion_once_callback.h"
#include "net/base/host_port_pair.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/mock_client_cert_verifier.h"
#include "net/cert/signed_certificate_timestamp_and_status.h"
#include "net/cert/x509_certificate.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/client_socket_factory.h"
// #include "net/socket/socket_test_util.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/stream_socket.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_cipher_suite_names.h"
#include "net/ssl/ssl_client_session_cache.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/ssl_server_config.h"
// #include "net/ssl/test_ssl_config_service.h"
// #include "net/ssl/test_ssl_private_key.h"
// #include "net/test/cert_test_util.h"
// #include "net/test/gtest_util.h"
// #include "net/test/test_data_directory.h"
// #include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
// #include "testing/gmock/include/gmock/gmock.h"
// #include "testing/gtest/include/gtest/gtest.h"
// #include "testing/platform_test.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

#include "net/ssl/threaded_ssl_private_key.h"
#include "net/ssl/test_ssl_private_key.h"
#include "net/socket/client_socket_handle.h"
#include "net/base/test_completion_callback.h"

#include "json/json.h"

// using net::test::IsError;
// using net::test::IsOk;

namespace net {

namespace {

const char kClientCertFileName[] = "client_1.pem";
const char kClientPrivateKeyFileName[] = "client_1.pk8";
const char kWrongClientCertFileName[] = "client_2.pem";
const char kWrongClientPrivateKeyFileName[] = "client_2.pk8";

class MockCTPolicyEnforcer : public CTPolicyEnforcer {
 public:
  MockCTPolicyEnforcer() = default;
  ~MockCTPolicyEnforcer() override = default;
  ct::CTPolicyCompliance CheckCompliance(
      X509Certificate* cert,
      const SCTList& verified_scts,
      const NetLogWithSource& net_log) override {
    return ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS;
  }
};

class FakeDataChannel {
 public:
  FakeDataChannel()
      : read_buf_len_(0),
        closed_(false),
        write_called_after_close_(false),
        weak_factory_(this) {
  }

  int Read(IOBuffer* buf, int buf_len, const CompletionCallback& callback) {
    DCHECK(read_callback_.is_null());
    DCHECK(!read_buf_.get());
    if (closed_)
      return 0;
    if (data_.empty()) {
      read_callback_ = callback;
      read_buf_ = buf;
      read_buf_len_ = buf_len;
      return ERR_IO_PENDING;
    }
    return PropagateData(buf, buf_len);
  }

  int Write(IOBuffer* buf,
            int buf_len,
            const CompletionCallback& callback,
            const NetworkTrafficAnnotationTag& traffic_annotation) {
    DCHECK(write_callback_.is_null());
    if (closed_) {
      if (write_called_after_close_)
        return ERR_CONNECTION_RESET;
      write_called_after_close_ = true;
      write_callback_ = callback;
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(&FakeDataChannel::DoWriteCallback,
                                weak_factory_.GetWeakPtr()));
      return ERR_IO_PENDING;
    }
    // This function returns synchronously, so make a copy of the buffer.
    data_.push(new DrainableIOBuffer(
        new StringIOBuffer(std::string(buf->data(), buf_len)),
        buf_len));
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&FakeDataChannel::DoReadCallback,
                              weak_factory_.GetWeakPtr()));
    return buf_len;
  }

  // Closes the FakeDataChannel. After Close() is called, Read() returns 0,
  // indicating EOF, and Write() fails with ERR_CONNECTION_RESET. Note that
  // after the FakeDataChannel is closed, the first Write() call completes
  // asynchronously, which is necessary to reproduce bug 127822.
  void Close() {
    closed_ = true;
    if (!read_callback_.is_null()) {
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(&FakeDataChannel::DoReadCallback,
                                weak_factory_.GetWeakPtr()));
    }
  }

 private:
  void DoReadCallback() {
    if (read_callback_.is_null())
      return;

    if (closed_) {
      base::ResetAndReturn(&read_callback_).Run(ERR_CONNECTION_CLOSED);
      return;
    }

    if (data_.empty())
      return;

    int copied = PropagateData(read_buf_, read_buf_len_);
    read_buf_ = NULL;
    read_buf_len_ = 0;
    base::ResetAndReturn(&read_callback_).Run(copied);
  }

  void DoWriteCallback() {
    if (write_callback_.is_null())
      return;

    base::ResetAndReturn(&write_callback_).Run(ERR_CONNECTION_RESET);
  }

  int PropagateData(scoped_refptr<IOBuffer> read_buf, int read_buf_len) {
    scoped_refptr<DrainableIOBuffer> buf = data_.front();
    int copied = std::min(buf->BytesRemaining(), read_buf_len);
    memcpy(read_buf->data(), buf->data(), copied);
    buf->DidConsume(copied);

    if (!buf->BytesRemaining())
      data_.pop();
    return copied;
  }

  CompletionCallback read_callback_;
  scoped_refptr<IOBuffer> read_buf_;
  int read_buf_len_;

  CompletionCallback write_callback_;

  base::queue<scoped_refptr<DrainableIOBuffer>> data_;

  // True if Close() has been called.
  bool closed_;

  // Controls the completion of Write() after the FakeDataChannel is closed.
  // After the FakeDataChannel is closed, the first Write() call completes
  // asynchronously.
  bool write_called_after_close_;

  base::WeakPtrFactory<FakeDataChannel> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(FakeDataChannel);
};

class FakeSocket : public StreamSocket {
 public:
  FakeSocket(FakeDataChannel* incoming_channel,
             FakeDataChannel* outgoing_channel)
      : incoming_(incoming_channel), outgoing_(outgoing_channel) {}

  ~FakeSocket() override = default;

  int Read(IOBuffer* buf,
           int buf_len,
           const CompletionCallback& callback) override {
    // Read random number of bytes.
    buf_len = rand() % buf_len + 1;
    return incoming_->Read(buf, buf_len, callback);
  }

  int Write(IOBuffer* buf,
            int buf_len,
            const CompletionCallback& callback,
            const NetworkTrafficAnnotationTag& traffic_annotation) override {
    // Write random number of bytes.
    buf_len = rand() % buf_len + 1;
    return outgoing_->Write(buf, buf_len, callback,
                            TRAFFIC_ANNOTATION_FOR_TESTS);
  }

  int SetReceiveBufferSize(int32_t size) override { return OK; }

  int SetSendBufferSize(int32_t size) override { return OK; }

  int Connect(const CompletionCallback& callback) override { return OK; }

  void Disconnect() override {
    incoming_->Close();
    outgoing_->Close();
  }

  bool IsConnected() const override { return true; }

  bool IsConnectedAndIdle() const override { return true; }

  int GetPeerAddress(IPEndPoint* address) const override {
    *address = IPEndPoint(IPAddress::IPv4AllZeros(), 0 /*port*/);
    return OK;
  }

  int GetLocalAddress(IPEndPoint* address) const override {
    *address = IPEndPoint(IPAddress::IPv4AllZeros(), 0 /*port*/);
    return OK;
  }

  const NetLogWithSource& NetLog() const override { return net_log_; }

  void SetSubresourceSpeculation() override {}
  void SetOmniboxSpeculation() override {}

  bool WasEverUsed() const override { return true; }

  bool WasAlpnNegotiated() const override { return false; }

  NextProto GetNegotiatedProtocol() const override { return kProtoUnknown; }

  bool GetSSLInfo(SSLInfo* ssl_info) override { return false; }

  void GetConnectionAttempts(ConnectionAttempts* out) const override {
    out->clear();
  }

  void ClearConnectionAttempts() override {}

  void AddConnectionAttempts(const ConnectionAttempts& attempts) override {}

  int64_t GetTotalReceivedBytes() const override {
    NOTIMPLEMENTED();
    return 0;
  }

  void ApplySocketTag(const SocketTag& tag) override {}

 private:
  NetLogWithSource net_log_;
  FakeDataChannel* incoming_;
  FakeDataChannel* outgoing_;

  DISALLOW_COPY_AND_ASSIGN(FakeSocket);
};

}  // namespace

// Verify the correctness of the test helper classes first.
void FakeSocketTest_DataTransfer()
{
  // Establish channels between two sockets.
  FakeDataChannel channel_1;
  FakeDataChannel channel_2;
  FakeSocket client(&channel_1, &channel_2);
  FakeSocket server(&channel_2, &channel_1);

  const char kTestData[] = "testing123";
  const int kTestDataSize = strlen(kTestData);
  const int kReadBufSize = 1024;
  scoped_refptr<IOBuffer> write_buf = new StringIOBuffer(kTestData);
  scoped_refptr<IOBuffer> read_buf = new IOBuffer(kReadBufSize);

  // Write then read.
  int written =
      server.Write(write_buf.get(), kTestDataSize, CompletionCallback(),
                   TRAFFIC_ANNOTATION_FOR_TESTS);
  // EXPECT_GT(written, 0);
  // EXPECT_LE(written, kTestDataSize);

  int read = client.Read(read_buf.get(), kReadBufSize, CompletionCallback());
  // EXPECT_GT(read, 0);
  // EXPECT_LE(read, written);
  // EXPECT_EQ(0, memcmp(kTestData, read_buf->data(), read));

  // Read then write.
  TestCompletionCallback callback;
  int ret = server.Read(read_buf.get(), kReadBufSize, callback.callback());
  // EXPECT_EQ(ERR_IO_PENDING, ret);

  written = client.Write(write_buf.get(), kTestDataSize, CompletionCallback(),
                         TRAFFIC_ANNOTATION_FOR_TESTS);
  // EXPECT_GT(written, 0);
  // EXPECT_LE(written, kTestDataSize);

  read = callback.WaitForResult();
  // EXPECT_GT(read, 0);
  // EXPECT_LE(read, written);
  // EXPECT_EQ(0, memcmp(kTestData, read_buf->data(), read));
}

static scoped_refptr<X509Certificate> ImportCertFromFile(
    const base::FilePath& certs_dir,
    const std::string& cert_file) {
  // base::ScopedAllowBlockingForTesting allow_blocking;
  base::FilePath cert_path = certs_dir.AppendASCII(cert_file);
  std::string cert_data;
  if (!base::ReadFileToString(cert_path, &cert_data))
    return nullptr;

  CertificateList certs_in_file =
      X509Certificate::CreateCertificateListFromBytes(
          cert_data.data(), cert_data.size(), X509Certificate::FORMAT_AUTO);
  if (certs_in_file.empty())
    return nullptr;
  return certs_in_file[0];
}
/*
// Net data directory, relative to source root.
const base::FilePath::CharType kNetDataRelativePath[] =
    FILE_PATH_LITERAL("net/data");

// Test certificates directory, relative to kNetDataRelativePath.
const base::FilePath::CharType kCertificateDataSubPath[] =
    FILE_PATH_LITERAL("ssl/certificates");

}

base::FilePath GetTestNetDataDirectory() {
  base::FilePath src_root;
  {
    base::ScopedAllowBlockingForTesting allow_blocking;
    base::PathService::Get(base::DIR_SOURCE_ROOT, &src_root);
  }

  return src_root.Append(kNetDataRelativePath);
}

base::FilePath GetTestCertsDirectory() {
  return GetTestNetDataDirectory().Append(kCertificateDataSubPath);
}
*/

static base::FilePath GetTestCertsDirectory() {
  return base::FilePath(FILE_PATH_LITERAL("c:/ddksample"));
}

// class SSLServerSocketTest : public PlatformTest {
class SSLServerSocketTest{
 public:
  SSLServerSocketTest()
      : socket_factory_(ClientSocketFactory::GetDefaultFactory()),
        cert_verifier_(new MockCertVerifier()),
        client_cert_verifier_(new MockClientCertVerifier()),
        transport_security_state_(new TransportSecurityState),
        ct_verifier_(new DoNothingCTVerifier),
        ct_policy_enforcer_(new MockCTPolicyEnforcer) {}

  void SetUp() {
    // PlatformTest::SetUp();

    cert_verifier_->set_default_result(ERR_CERT_AUTHORITY_INVALID);
    client_cert_verifier_->set_default_result(ERR_CERT_AUTHORITY_INVALID);

    server_cert_ =
        ImportCertFromFile(base::FilePath(FILE_PATH_LITERAL("c:/ddksample")), "unittest.selfsigned.der");
    // ASSERT_TRUE(server_cert_);
    server_private_key_ = ReadTestKey("unittest.key.bin");
    // ASSERT_TRUE(server_private_key_);

    std::unique_ptr<crypto::RSAPrivateKey> key =
        ReadTestKey("unittest.key.bin");
    // ASSERT_TRUE(key);
    EVP_PKEY_up_ref(key->key());
    server_ssl_private_key_ =
        WrapOpenSSLPrivateKey(bssl::UniquePtr<EVP_PKEY>(key->key()));

    client_ssl_config_.false_start_enabled = false;
    client_ssl_config_.channel_id_enabled = false;

    // Certificate provided by the host doesn't need authority.
    client_ssl_config_.allowed_bad_certs.emplace_back(
        server_cert_, CERT_STATUS_AUTHORITY_INVALID);
  }

  void Handshake();

 protected:
  void CreateContext() {
    client_socket_.reset();
    server_socket_.reset();
    channel_1_.reset();
    channel_2_.reset();
    server_context_.reset();
    server_context_ = CreateSSLServerContext(
        server_cert_.get(), *server_private_key_, server_ssl_config_);
  }

  void CreateContextSSLPrivateKey() {
    client_socket_.reset();
    server_socket_.reset();
    channel_1_.reset();
    channel_2_.reset();
    server_context_.reset();
    server_context_ = CreateSSLServerContext(
        server_cert_.get(), server_ssl_private_key_, server_ssl_config_);
  }

  void CreateSockets() {
    client_socket_.reset();
    server_socket_.reset();
    channel_1_.reset(new FakeDataChannel());
    channel_2_.reset(new FakeDataChannel());
    std::unique_ptr<ClientSocketHandle> client_connection(
        new ClientSocketHandle);
    client_connection->SetSocket(std::unique_ptr<StreamSocket>(
        new FakeSocket(channel_1_.get(), channel_2_.get())));
    std::unique_ptr<StreamSocket> server_socket(
        new FakeSocket(channel_2_.get(), channel_1_.get()));

    HostPortPair host_and_pair("unittest", 0);
    SSLClientSocketContext context;
    context.cert_verifier = cert_verifier_.get();
    context.transport_security_state = transport_security_state_.get();
    context.cert_transparency_verifier = ct_verifier_.get();
    context.ct_policy_enforcer = ct_policy_enforcer_.get();
    // Set a dummy session cache shard to enable session caching.
    context.ssl_session_cache_shard = "shard";

    client_socket_ = socket_factory_->CreateSSLClientSocket(
        std::move(client_connection), host_and_pair, client_ssl_config_,
        context);
    // ASSERT_TRUE(client_socket_);

    server_socket_ =
        server_context_->CreateSSLServerSocket(std::move(server_socket));
    // ASSERT_TRUE(server_socket_);
  }

  void ConfigureClientCertsForClient(const char* cert_file_name,
                                     const char* private_key_file_name) {
    client_ssl_config_.send_client_cert = true;
    client_ssl_config_.client_cert =
        ImportCertFromFile(GetTestCertsDirectory(), cert_file_name);
    // ASSERT_TRUE(client_ssl_config_.client_cert);

    std::unique_ptr<crypto::RSAPrivateKey> key =
        ReadTestKey(private_key_file_name);
    // ASSERT_TRUE(key);

    EVP_PKEY_up_ref(key->key());
    client_ssl_config_.client_private_key =
        WrapOpenSSLPrivateKey(bssl::UniquePtr<EVP_PKEY>(key->key()));
  }

  void ConfigureClientCertsForServer() {
    server_ssl_config_.client_cert_type =
        SSLServerConfig::ClientCertType::REQUIRE_CLIENT_CERT;

    // "CN=B CA" - DER encoded DN of the issuer of client_1.pem
    static const uint8_t kClientCertCAName[] = {
        0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0c, 0x04, 0x42, 0x20, 0x43, 0x41};
    server_ssl_config_.cert_authorities_.push_back(std::string(
        std::begin(kClientCertCAName), std::end(kClientCertCAName)));

    scoped_refptr<X509Certificate> expected_client_cert(
        ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName));
    // ASSERT_TRUE(expected_client_cert);

    client_cert_verifier_->AddResultForCert(expected_client_cert.get(), OK);

    server_ssl_config_.client_cert_verifier = client_cert_verifier_.get();
  }

  std::unique_ptr<crypto::RSAPrivateKey> ReadTestKey(
      const base::StringPiece& name) {
    base::FilePath certs_dir(GetTestCertsDirectory());
    base::FilePath key_path = certs_dir.AppendASCII(name);
    std::string key_string;
    if (!base::ReadFileToString(key_path, &key_string))
      return nullptr;
    std::vector<uint8_t> key_vector(
        reinterpret_cast<const uint8_t*>(key_string.data()),
        reinterpret_cast<const uint8_t*>(key_string.data() +
                                         key_string.length()));
    std::unique_ptr<crypto::RSAPrivateKey> key(
        crypto::RSAPrivateKey::CreateFromPrivateKeyInfo(key_vector));
    return key;
  }

  std::unique_ptr<FakeDataChannel> channel_1_;
  std::unique_ptr<FakeDataChannel> channel_2_;
  SSLConfig client_ssl_config_;
  SSLServerConfig server_ssl_config_;
  std::unique_ptr<SSLClientSocket> client_socket_;
  std::unique_ptr<SSLServerSocket> server_socket_;
  ClientSocketFactory* socket_factory_;
  std::unique_ptr<MockCertVerifier> cert_verifier_;
  std::unique_ptr<MockClientCertVerifier> client_cert_verifier_;
  std::unique_ptr<TransportSecurityState> transport_security_state_;
  std::unique_ptr<DoNothingCTVerifier> ct_verifier_;
  std::unique_ptr<MockCTPolicyEnforcer> ct_policy_enforcer_;
  std::unique_ptr<SSLServerContext> server_context_;
  std::unique_ptr<crypto::RSAPrivateKey> server_private_key_;
  scoped_refptr<SSLPrivateKey> server_ssl_private_key_;
  scoped_refptr<X509Certificate> server_cert_;
};

// This test executes Connect() on SSLClientSocket and Handshake() on
// SSLServerSocket to make sure handshaking between the two sockets is
// completed successfully.
void SSLServerSocketTest::Handshake()
{
    SetUp();

  CreateContext();
  CreateSockets();

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  client_ret = connect_callback.GetResult(client_ret);
  server_ret = handshake_callback.GetResult(server_ret);

  // ASSERT_THAT(client_ret, IsOk());
  // ASSERT_THAT(server_ret, IsOk());

  // Make sure the cert status is expected.
  SSLInfo ssl_info;
  client_socket_->GetSSLInfo(&ssl_info);
  // ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info));
  // EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, ssl_info.cert_status);

  // The default cipher suite should be ECDHE and an AEAD.
  uint16_t cipher_suite =
      SSLConnectionStatusToCipherSuite(ssl_info.connection_status);
  const char* key_exchange;
  const char* cipher;
  const char* mac;
  bool is_aead;
  bool is_tls13;
  SSLCipherSuiteToStrings(&key_exchange, &cipher, &mac, &is_aead, &is_tls13,
                          cipher_suite);
  // EXPECT_TRUE(is_aead);
  // ASSERT_FALSE(is_tls13);
  // EXPECT_STREQ("ECDHE_RSA", key_exchange);
}

static bssl::UniquePtr<EVP_PKEY> LoadEVP_PKEY(const base::FilePath& filepath) {
  std::string data;
  if (!base::ReadFileToString(filepath, &data)) {
    LOG(ERROR) << "Could not read private key file: " << filepath.value();
    return nullptr;
  }
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(const_cast<char*>(data.data()),
                                           static_cast<int>(data.size())));
  if (!bio) {
    LOG(ERROR) << "Could not allocate BIO for buffer?";
    return nullptr;
  }
  bssl::UniquePtr<EVP_PKEY> result(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  if (!result) {
    LOG(ERROR) << "Could not decode private key file: " << filepath.value();
    return nullptr;
  }
  return result;
}

IPAddress IPv4Localhost2() {
  const uint8_t kLocalhostIPv4[] = {192, 168, 1, 103};
  return IPAddress(kLocalhostIPv4);
}

int do_one_accept(TCPServerSocket& server_listener, SSLServerContext* server_context, std::vector<std::unique_ptr<SSLServerSocket> >& session_sockets)
{
  TestCompletionCallback server_callback;
  std::unique_ptr<StreamSocket> server_transport;
  int server_rv = server_listener.Accept(&server_transport, server_callback.callback());

  // std::unique_ptr<TCPClientSocket> client_transport(new TCPClientSocket(
  //    AddressList(server_address), NULL, NULL, NetLogSource()));
  // int client_rv = client_transport->Connect(client_callback.callback());

  server_callback.GetResult(server_rv);

  IPEndPoint address;
  int rv = server_transport->GetPeerAddress(&address);
  // EXPECT_THAT(server_callback.GetResult(server_rv), IsOk());
  // EXPECT_THAT(client_callback.GetResult(client_rv), IsOk());

  std::unique_ptr<SSLServerSocket> server2(
      server_context->CreateSSLServerSocket(std::move(server_transport)));

  session_sockets.push_back(std::move(server2));
  SSLServerSocket* server = session_sockets.back().get();

  server_rv = server->Handshake(server_callback.callback());
  rv = server_callback.GetResult(server_rv);

  int64_t t = time(nullptr);
  Json::Value json_root;
	json_root["peer address"] = address.ToString();
	json_root["now"] = t;

	Json::FastWriter writer;
	std::string body = writer.write(json_root);
    body = address.ToString();

  scoped_refptr<IOBuffer> write_buf(new StringIOBuffer(body));
  server_rv = server->Write(write_buf.get(), body.size(), server_callback.callback(),
                            TRAFFIC_ANNOTATION_FOR_TESTS);
  rv = server_callback.GetResult(server_rv);
  return rv;
}

void ssl_server_socket()
{
  // Set up an SSL server.
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<net::X509Certificate> cert =
      ImportCertFromFile(certs_dir, "ok_cert.pem");
  // ASSERT_TRUE(cert);
  bssl::UniquePtr<EVP_PKEY> pkey =
      LoadEVP_PKEY(certs_dir.AppendASCII("ok_cert.pem"));
  // ASSERT_TRUE(pkey);
  std::unique_ptr<crypto::RSAPrivateKey> key =
      crypto::RSAPrivateKey::CreateFromKey(pkey.get());
  // ASSERT_TRUE(key);
  std::unique_ptr<SSLServerContext> server_context =
      CreateSSLServerContext(cert.get(), *key.get(), SSLServerConfig());

  // Set up a TCP server.
  TCPServerSocket server_listener(NULL, NetLogSource());
  server_listener.Listen(IPEndPoint(IPv4Localhost2(), 443), 1);
  IPEndPoint server_address;
  int rv = server_listener.GetLocalAddress(&server_address);

  std::vector<std::unique_ptr<SSLServerSocket> > session_sockets;
  for (int n = 0; n < 1; n ++) {
      do_one_accept(server_listener, server_context.get(), session_sockets);
      session_sockets.clear();
  }

  session_sockets.clear();
  server_context.reset();

/*
  TestCompletionCallback server_callback;
  std::unique_ptr<StreamSocket> server_transport;
  int server_rv = server_listener.Accept(&server_transport, server_callback.callback());

  // std::unique_ptr<TCPClientSocket> client_transport(new TCPClientSocket(
  //    AddressList(server_address), NULL, NULL, NetLogSource()));
  // int client_rv = client_transport->Connect(client_callback.callback());

  server_callback.GetResult(server_rv);
  // EXPECT_THAT(server_callback.GetResult(server_rv), IsOk());
  // EXPECT_THAT(client_callback.GetResult(client_rv), IsOk());

  std::unique_ptr<SSLServerSocket> server(
      server_context->CreateSSLServerSocket(std::move(server_transport)));

  server_rv = server->Handshake(server_callback.callback());
  rv = server_callback.GetResult(server_rv);

  scoped_refptr<IOBuffer> write_buf(new StringIOBuffer("ancientcc 1234567890"));
  server_rv = server->Write(write_buf.get(), 15, server_callback.callback(),
                            TRAFFIC_ANNOTATION_FOR_TESTS);
  rv = server_callback.GetResult(server_rv);
*/
}

}  // namespace net

void SSLServerSocketTest_Handshake()
{
    net::ssl_server_socket();
/*
    // net::FakeSocketTest_DataTransfer();

    net::SSLServerSocketTest test;
    test.Handshake();
*/
}