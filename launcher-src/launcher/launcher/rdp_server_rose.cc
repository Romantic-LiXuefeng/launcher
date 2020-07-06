// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rdp_server_rose.h"

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
#include "net/server/rdp_connection.h"
#include "net/socket/server_socket.h"
#include "net/socket/stream_socket.h"
#include "net/socket/tcp_server_socket.h"

#include <SDL_stdinc.h>
#include <SDL_log.h>

#include "game_config.hpp"
#include "base_instance.hpp"
#include "gui/widgets/grid.hpp"
#include <boost/bind.hpp>
#include "base/files/file_util.h"
#include "net/cert/x509_certificate.h"
#include "crypto/rsa_private_key.h"
#include "net/ssl/ssl_server_config.h"

#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"
#include "json/json.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "base/strings/utf_string_conversions.h"

#include "freerdp/peer.h"
#include <boost/bind.hpp>

#include <freerdp/server/cliprdr.h>
#include <freerdp/freerdp.h>

#include "shadow_subsystem.h"
#include "shadow_client.h"
#include "kos/kos_shadow.h"

namespace net {

RdpServerRose::RdpServerRose(base::Thread& thread)
	: thread_(thread)
	, fake_peer_socket_(10)
	, freerdp_server_(nullptr)
	, weak_ptr_factory_(this)
	, check_slice_timeout_(300) // 300 ms
	, slice_running_(false)
	, startup_verbose_ticks_(0)
	, last_verbose_ticks_(0)
	, may_disconnect_write_buf_bytes_(0)
{
	freerdp_server_ = rose_init_subsystem();
}

RdpServerRose::~RdpServerRose()
{
	DCHECK_CALLED_ON_VALID_THREAD(server_->thread_checker_);

	SDL_Log("RdpServerRose::~RdpServerRose()---");
	// don't call serve_.reset(), after server_->Release(), some require it's some variable keep valid.
	server_->CloseAllConnection();
	rose_release_subsystem(freerdp_server_);
	thread_.message_loop()->DeletePendingTasksEx(true);
	SDL_Log("---RdpServerRose::~RdpServerRose() X");
}

void RdpServerRose::SetUp(uint32_t ipaddr)
{
	std::unique_ptr<ServerSocket> server_socket(new TCPServerSocket(NULL, NetLogSource()));
	// server_socket->ListenWithAddressAndPort("127.0.0.1", 8080, 1);

	// Must not use 127.0.0.1
	// make sure we have a value in a known byte order: big endian
	uint32_t addrNBO = htonl(ipaddr);
	std::stringstream addr_ss;
	addr_ss << (int)((addrNBO >> 24) & 0xFF) << "." << (int)((addrNBO>>16) & 0xFF);
	addr_ss << "." << (int)((addrNBO>>8)&0xFF) << "." << (int)(addrNBO & 0xFF);
	server_socket->ListenWithAddressAndPort(addr_ss.str(), 3389, 1);

	server_.reset(new RdpServer(std::move(server_socket), this));
	server_->GetLocalAddress(&server_address_);
	server_url_ = server_address_.ToString();
}

void RdpServerRose::TearDown()
{
	// Run the event loop some to make sure that the memory handed over to
	// DeleteSoon gets fully freed.
	base::RunLoop().RunUntilIdle();
}

static SSIZE_T did_rose_read_layer(freerdp_peer* client, BYTE* data, size_t bytes)
{
	RdpServerRose* rose = reinterpret_cast<RdpServerRose*>(client->rose_delegate);
	RdpConnection* connection = reinterpret_cast<RdpConnection*>(client->rose_connection);
	VALIDATE(connection != nullptr, null_str);
	if (connection->closing()) {
		return 0;
	}
	VALIDATE(connection->client_ptr == client, null_str);
	return connection->did_read_layer(data, bytes);
}

static int did_rose_write_layer(freerdp_peer* client, BYTE* data, size_t bytes)
{
	RdpServerRose* rose = reinterpret_cast<RdpServerRose*>(client->rose_delegate);
	RdpConnection* connection = reinterpret_cast<RdpConnection*>(client->rose_connection);
	VALIDATE(connection != nullptr && connection->client_ptr == client, null_str);
	if (connection->closing()) {
		return 0;
	}
	VALIDATE(connection->client_ptr == client, null_str);
	return connection->did_write_layer(data, bytes);
}

void RdpServerRose::clipboard_updated(const std::string& text)
{
	threading::lock lock(server_->connections_mutex_);
	std::map<int, std::unique_ptr<RdpConnection> >& id_to_connection = server_->id_to_connection_;
	for (std::map<int, std::unique_ptr<RdpConnection> >::const_iterator it = id_to_connection.begin(); it != id_to_connection.end(); ++ it) {
		RdpConnection& connection = *it->second.get();
		freerdp_peer* peer = static_cast<freerdp_peer*>(connection.client_ptr);
		if (peer != nullptr) {
			rdpShadowClient* client = (rdpShadowClient*)peer->context;
			if (client->cliprdr->TextClipboardUpdated != nullptr) {
				client->cliprdr->TextClipboardUpdated(client->cliprdr, text.c_str());
			}
		}
	}
}

void RdpServerRose::hdrop_copied(const std::string& files)
{
	rdpShadowClient* client = nullptr;
	// send pdu require RdpdThread running, don't block it when HdropCopied.
	{
		threading::lock lock(server_->connections_mutex_);
		std::map<int, std::unique_ptr<RdpConnection> >& id_to_connection = server_->id_to_connection_;
		for (std::map<int, std::unique_ptr<RdpConnection> >::const_iterator it = id_to_connection.begin(); it != id_to_connection.end(); ++ it) {
			RdpConnection& connection = *it->second.get();
			freerdp_peer* peer = static_cast<freerdp_peer*>(connection.client_ptr);
			if (peer != nullptr) {
				client = (rdpShadowClient*)peer->context;
			}
		}
	}
	if (client != nullptr && client->cliprdr->HdropCopied != nullptr) {
		client->cliprdr->HdropCopied(client->cliprdr, files.c_str(), files.size());
	}
}

int RdpServerRose::hdrop_paste(gui2::tprogress_& progress, const std::string& path, char* err_msg, int max_bytes)
{
	rdpShadowClient* client = nullptr;
	// send pdu require RdpdThread running, don't block it when HdropPaste.
	{
		threading::lock lock(server_->connections_mutex_);
		std::map<int, std::unique_ptr<RdpConnection> >& id_to_connection = server_->id_to_connection_;
		for (std::map<int, std::unique_ptr<RdpConnection> >::const_iterator it = id_to_connection.begin(); it != id_to_connection.end(); ++ it) {
			RdpConnection& connection = *it->second.get();
			freerdp_peer* peer = static_cast<freerdp_peer*>(connection.client_ptr);
			if (peer != nullptr) {
				client = (rdpShadowClient*)peer->context;
			}
		}
	}
	int ret = errcode_ok;
	if (client != nullptr && client->cliprdr->HdropPaste != nullptr) {
		ret = client->cliprdr->HdropPaste(client->cliprdr, path.c_str(), &progress, err_msg, max_bytes);
	}
	return ret;
}

bool RdpServerRose::can_hdrop_paste() const
{
	bool ret = false;
	rdpShadowClient* client = nullptr;
	{
		threading::lock lock(server_->connections_mutex_);
		std::map<int, std::unique_ptr<RdpConnection> >& id_to_connection = server_->id_to_connection_;
		for (std::map<int, std::unique_ptr<RdpConnection> >::const_iterator it = id_to_connection.begin(); it != id_to_connection.end(); ++ it) {
			RdpConnection& connection = *it->second.get();
			freerdp_peer* peer = static_cast<freerdp_peer*>(connection.client_ptr);
			if (peer != nullptr) {
				client = (rdpShadowClient*)peer->context;
			}
		}
	}
	if (client != nullptr && client->cliprdr->CanHdropPaste != nullptr) {
		ret = client->cliprdr->CanHdropPaste(client->cliprdr);
	}
	return ret;
}

void RdpServerRose::did_slice_quited(int timeout1)
{
	VALIDATE(server_.get() != nullptr, null_str);
	if (server_->connection_count() == 0) {
		SDL_Log("will stop rdpd_slice");
		slice_running_ = false;
		return;
	}

	// base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, base::Bind(&RdpServerRose::rdpd_slice, weak_ptr_factory_.GetWeakPtr(), timeout1));

	const base::TimeDelta timeout = base::TimeDelta::FromMilliseconds(20); // 20 ms.
	base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(FROM_HERE, base::Bind(&RdpServerRose::rdpd_slice, weak_ptr_factory_.GetWeakPtr(), timeout1), timeout);
}

void RdpServerRose::handle_pause_record_screen(RdpConnection& connection, bool desire_pause)
{
	bool current_paused = kosRecordScreenPaused();
	if (desire_pause && !current_paused) {
		kosPauseRecordScreen(desire_pause);
		SDL_Log("%u handle_pause_record_screen, pause capture screen", SDL_GetTicks());

	} else if (!desire_pause && current_paused) {
		SDL_Log("%u handle_pause_record_screen, continue capture screen", SDL_GetTicks());
		kosPauseRecordScreen(desire_pause);
	}
}

void RdpServerRose::rdpd_slice(int timeout)
{
	DCHECK_CALLED_ON_VALID_THREAD(server_->thread_checker_);
	
	// Although only max SUPPORTED_MAX_CLIENTS client is supported, but second client will not close until the CR is received.
	// between insert-rdp_connections and receipt of CR(Connection Request PDU), rdpd_slice may already be running, 
	// so there are (SUPPORTED_MAX_CLIENTS + 1) connection possible here.

	// if reject in RdpServer::HandleAcceptResult, should "server_->connection_count() <= SUPPORTED_MAX_CLIENTS"
	VALIDATE(server_->connection_count() <= SUPPORTED_MAX_CLIENTS + 1, null_str);

	tauto_destruct_executor destruct_executor(boost::bind(&RdpServerRose::did_slice_quited, this, timeout));

	RdpConnection* connection = server_->FindFirstHandshakedConnection();
	if (connection == nullptr) {
		// this connection has been destroyed or closing, do nothing.
		return;
	}
	VALIDATE(connection->handshaked(), null_str);

	freerdp_peer* peer = static_cast<freerdp_peer*>(connection->client_ptr);
	kosShadowSubsystem* subsystem = (kosShadowSubsystem*)freerdp_server_->subsystem;
	trecord_screen& record_screen = *subsystem->record_screen;
	if (!record_screen.thread_started() && can_xmit_screen_surface(freerdp_server_, peer, &gfxstatus_)) {
		rose_shadow_subsystem_start(freerdp_server_->subsystem);
		return;
	}

	rdpShadowClient* client = (rdpShadowClient*)peer->context;
	rdpContext* context = (rdpContext*)client;
	rdpShadowSurface* surface = freerdp_server_->surface;

	int images = 0;
	while (true) {
		surface->h264Length = 0;
		{
			threading::lock lock(record_screen.encoded_images_mutex());
			if (!record_screen.encoded_images.empty() && !connection->write_buf_is_alert() && can_xmit_screen_surface(freerdp_server_, peer, &gfxstatus_)) {
				const scoped_refptr<net::IOBufferWithSize>& image = record_screen.encoded_images.front();
				surface->h264Length = image->size();
				memcpy(surface->data, image->data(), surface->h264Length);
				// record_screen.encoded_images.erase(record_screen.encoded_images.begin());
				record_screen.encoded_images.pop();

				RECTANGLE_16 invalidRect;
				invalidRect.left = 0;
				invalidRect.top = 0;
				invalidRect.right = 1920;
				invalidRect.bottom = 1080;
				region16_union_rect(&(surface->invalidRegion), &(surface->invalidRegion), &invalidRect);
			}
			images = record_screen.encoded_images.size();
		}
		rose_did_update_peer_send(freerdp_server_, peer, &gfxstatus_, UpdateSubscriber_);
		if (surface->h264Length == 0) {
			break;
		}
	}

	const uint32_t now = SDL_GetTicks();
	HttpConnection::QueuedWriteIOBuffer* write_buf = connection->write_buf();
	if (connection->should_disconnect(now)) {
		SDL_Log("%u rdpd_slice(%i) cur: %3.1fM/alert: %3.1fM, qos: %u, write buffer is alert more time, think as disconnect", 
			now, connection->id(),
			1.0 * write_buf->total_size() / (1024 * 1024), 1.0 * connection->alert_buffer_threshold()  / (1024 * 1024),
			client->qoeFrameAcknowledges);
		// server_->PostClose(*connection);
		server_->Close(connection->id());
		return;
	}

	const uint32_t capture_thread_threshold = 60 * 1000; // 1 mimute
	if (!record_screen.thread_started() && now - connection->handshaked_ticks() >= capture_thread_threshold) {
		// Within capture_thread_threshold, handshaked connection must start the capture thread (which means entering activeed, etc.), 
		// otherwise an exception is considered, and force to disconnect.
		SDL_Log("%u rdpd_slice(%i) cur: %3.1fM/alert: %3.1fM, qos: %u, hasn't started capture thread over %u seconds, think as disconnect", 
			now, connection->id(),
			1.0 * write_buf->total_size() / (1024 * 1024), 1.0 * connection->alert_buffer_threshold()  / (1024 * 1024),
			client->qoeFrameAcknowledges, now - connection->handshaked_ticks());
		server_->Close(connection->id());
		return;
	}

	// const int alert_buffer_threshold = connection->alert_buffer_threshold();
	const int cur_write_buf_size = write_buf->total_size();
	uint32_t desire_disconnect_ticks = nposm;
	const int suppress_threshold = preferences::suppressthreshold();
	if (!client->suppressOutput) {
		if (connection->write_buf_is_alert()) {
			if (connection->shoule_disconnect_ticks() == 0 || client->qoeFrameAcknowledges != may_disconnect_write_buf_bytes_) {
				// if cur_write_buf_size < may_disconnect_write_buf_bytes_, mean has data to send, only sending is slow
				const int disconnect_threshold = 8000; // 8 second
				desire_disconnect_ticks = now + disconnect_threshold;
				may_disconnect_write_buf_bytes_ = client->qoeFrameAcknowledges;
				SDL_Log("%u, rdpd_slice, set disconnect_ticks to %u, cur: %3.1fM/%3.1fM, qos: %u", 
					now, desire_disconnect_ticks,
					1.0 * write_buf->total_size() / (1024 * 1024), 
					1.0 * connection->alert_buffer_threshold() /  (1024 * 1024),
					may_disconnect_write_buf_bytes_);
			}
		} else {
			// back to safe, cancel
			desire_disconnect_ticks = 0;
		}

	} else if (suppress_threshold != nposm && (int)(now - client->suppressOutputTicks) / 1000 >= suppress_threshold) {
		SDL_Log("%u rdpd_slice(%i) cur: %3.1fM/alert: %3.1fM, qos: %u, suppress %u(seconds) over %i, think as disconnect", 
			now, connection->id(),
			1.0 * write_buf->total_size() / (1024 * 1024), 1.0 * connection->alert_buffer_threshold()  / (1024 * 1024),
			client->qoeFrameAcknowledges, (now - client->suppressOutputTicks) / 1000, suppress_threshold);
		server_->Close(connection->id());
		return;

	} else {
		// if suppressOutput = true, I hasn't method to judge.
		desire_disconnect_ticks = 0;
	}
	if (desire_disconnect_ticks != nposm) {
		connection->set_shoule_disconnect_ticks(desire_disconnect_ticks);
	}

	// if (record_screen.thread_started()) {
		// pause/run snapshot only when thread is running.
		const int alert_images = 8;
		const int safe_images = 2;
		if (images >= alert_images) {
			handle_pause_record_screen(*connection, true);
		} else if (images <= safe_images) {
			handle_pause_record_screen(*connection, false);
		}
	// }

	// print debug log.
	if (startup_verbose_ticks_ == 0) {
		startup_verbose_ticks_ = now;
		last_verbose_ticks_ = startup_verbose_ticks_;
	}

	if (now - last_verbose_ticks_ >= 10000) {
		uint32_t total_second = (now - startup_verbose_ticks_) / 1000;
		uint32_t elapsed_second = (now - last_verbose_ticks_) / 1000;
		last_verbose_ticks_ = now;
		SDL_Log("rdpd_slice(%i) %s, %s, unsend %i, max: %3.1fK, cur: %3.1fM/%3.1fM, qos: %u, %s. last %u[s] %i frames, %3.1fM",
			connection->id(), format_elapse_hms2(total_second, false).c_str(), kosRecordScreenPaused()? "paused": "running",
			images, 1.0 * record_screen.max_one_frame_bytes / 1024,
			1.0 * write_buf->total_size() / (1024 * 1024), 
			1.0 * connection->alert_buffer_threshold() /  (1024 * 1024),
			client->qoeFrameAcknowledges, client->suppressOutput? "suppress": "send",
			elapsed_second, record_screen.last_capture_frames, 1.0 * record_screen.last_capture_bytes / (1024 * 1024));
		record_screen.last_capture_frames = 0;
		record_screen.last_capture_bytes = 0;
	}
}

void RdpServerRose::OnConnect(RdpConnection& connection)
{
	DCHECK_CALLED_ON_VALID_THREAD(server_->thread_checker_);

	freerdp_peer* client = freerdp_peer_new(fake_peer_socket_);
	UpdateSubscriber_ = rose_did_shadow_peer_connect(freerdp_server_, client, &gfxstatus_);
	client->rose_read_layer = did_rose_read_layer;
	client->rose_write_layer = did_rose_write_layer;
	client->rose_delegate = this;
	client->rose_connection = &connection;

	freerdp_server_->rose_delegate = this;

	connection.client_ptr = client;

	// Structures in freerdp is a bit messy and can't find a good variable to count how many client in real time.
	// temporarily use was_clients to store how many clients that it OnConnect called.
	client->was_clients = server_->connection_count();

	if (!slice_running_) {
		SDL_Log("will run rdpd_slice");
		slice_running_ = true;
		base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, base::Bind(&RdpServerRose::rdpd_slice, weak_ptr_factory_.GetWeakPtr(), check_slice_timeout_));
	}
}

void RdpServerRose::OnRdpRequest(RdpConnection& connection, const uint8_t* buf, int buf_len)
{
	DCHECK_CALLED_ON_VALID_THREAD(server_->thread_checker_);

	// RdpConnection::tdid_read_lock lock(*this, buf, buf_len);
	freerdp_peer* client = reinterpret_cast<freerdp_peer*>(connection.client_ptr);
	VALIDATE(client != nullptr, null_str);
	rdpRdp* rdp = client->context->rdp;

	rose_did_read(client);
	// return lock.consumed();
}

void RdpServerRose::OnClose(RdpConnection& connection)
{
	DCHECK_CALLED_ON_VALID_THREAD(server_->thread_checker_);

	freerdp_peer* client = static_cast<freerdp_peer*>(connection.client_ptr);
	SDL_Log("RdpServerRose::Close(%i)--- client: %p", connection.id(), client);
	if (client != nullptr) {
		rose_did_shadow_peer_disconnect(freerdp_server_, client, &gfxstatus_, UpdateSubscriber_);
		SDL_Log("RdpServerRose::Close(%i) pre rose_shadow_subsystem_stop", connection.id());
		rose_shadow_subsystem_stop(freerdp_server_->subsystem);
		connection.client_ptr = nullptr;
	}

	freerdp_server_->rose_delegate = nullptr;
	SDL_Log("------RdpServerRose::Close(%i) X", connection.id());
}

trdpd_manager::trdpd_manager()
	: tserver_(server_rdpd)
	, e_(false, false)
{}

void trdpd_manager::did_set_event()
{
	e_.Set();
}

void trdpd_manager::start_internal(uint32_t ipaddr)
{
	tauto_destruct_executor destruct_executor(boost::bind(&trdpd_manager::did_set_event, this));
	delegate_.reset(new RdpServerRose(*thread_.get()));
	delegate_->SetUp(ipaddr);
	delegate_->server_address().ToString();

	// net::HttpServer server(std::move(server_socket), &delegate);
	// delegate.set_server(&server);
}

void trdpd_manager::stop_internal()
{
	tauto_destruct_executor destruct_executor(boost::bind(&trdpd_manager::did_set_event, this));
	VALIDATE(delegate_.get() != nullptr, null_str);
	delegate_.reset();
}

void trdpd_manager::start(uint32_t ipaddr)
{
	CHECK(thread_.get() == nullptr);
	thread_.reset(new base::Thread("RdpdThread"));

	base::Thread::Options socket_thread_options;
	socket_thread_options.message_loop_type = base::MessageLoop::TYPE_IO;
	socket_thread_options.timer_slack = base::TIMER_SLACK_MAXIMUM;
	CHECK(thread_->StartWithOptions(socket_thread_options));

	thread_->task_runner()->PostTask(FROM_HERE, base::BindOnce(&trdpd_manager::start_internal, base::Unretained(this), ipaddr));
	e_.Wait(rtc::Event::kForever);
}

void trdpd_manager::stop()
{
	if (thread_.get() == nullptr) {
		VALIDATE(delegate_.get() == nullptr, null_str);
		return;
	}

	CHECK(delegate_.get() != nullptr);
	// stop_internal will reset delegate_.

	thread_->task_runner()->PostTask(FROM_HERE, base::BindOnce(&trdpd_manager::stop_internal, base::Unretained(this)));
	e_.Wait(rtc::Event::kForever);

	thread_.reset();
}

void trdpd_manager::clipboard_updated(const std::string& text)
{
	// this thread maybe not in main thread. maybe sync.
	if (delegate_.get() != nullptr) {
		delegate_->clipboard_updated(text);
	}
}

void trdpd_manager::hdrop_copied(const std::string& files)
{
	// this thread maybe not in main thread. maybe sync.
	if (delegate_.get() != nullptr) {
		delegate_->hdrop_copied(files);
	}
}

bool trdpd_manager::hdrop_paste(gui2::tprogress_& progress, const std::string& path, int* err_code, char* err_msg, int max_bytes)
{
	progress.set_align(gui2::tgrid::HORIZONTAL_ALIGN_LEFT);

	// this thread maybe not in main thread. maybe sync.
	*err_code = errcode_ok;
	if (delegate_.get() != nullptr) {
		*err_code = delegate_->hdrop_paste(progress, path, err_msg, max_bytes);
	}
	return *err_code == errcode_ok;
}

bool trdpd_manager::can_hdrop_paste() const
{
	if (delegate_.get() != nullptr) {
		return delegate_->can_hdrop_paste();
	}
	return false;
}

}  // namespace net
