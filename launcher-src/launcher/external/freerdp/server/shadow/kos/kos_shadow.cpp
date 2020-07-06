/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 *
 * Copyright 2011-2014 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
#include <windows.h>

#include <winpr/crt.h>
#include <winpr/synch.h>
#include <winpr/sysinfo.h>
*/
#include <freerdp/log.h>
#include <freerdp/codec/color.h>
#include <freerdp/codec/region.h>

#include "kos_shadow.h"
#include "SDL.h"
#include "SDL_log.h"
#include "filesystem.hpp"
#include <wml_exception.hpp>

#include <kosapi/sys.h>
#include "opencv2/imgproc.hpp"

// chromium
#include "base/bind.h"

// webrtc
#include "api/video/i420_buffer.h"

#include "libyuv/video_common.h"

#include "shadow_subsystem.h"

#define TAG SERVER_TAG("shadow.kos")

static BOOL kos_shadow_input_synchronize_event(rdpShadowSubsystem* subsystem,
                                               rdpShadowClient* client, UINT32 flags)
{
	WLog_WARN(TAG, "%s: TODO: Implement!", __FUNCTION__);
	return TRUE;
}

static BOOL kos_shadow_input_keyboard_event(rdpShadowSubsystem* subsystem, rdpShadowClient* client,
                                            UINT16 flags, UINT16 code)
{
	UINT rc;
	KosInput event;
	event.type = KOS_INPUT_KEYBOARD;
	event.u.ki.virtual_key = 0;
	event.u.ki.scan_code = code;
	event.u.ki.flags = KEYEVENTF_SCANCODE;
	// event.ki.dwExtraInfo = 0;
	event.u.ki.time = 0;

	if (flags & KBD_FLAGS_RELEASE)
		event.u.ki.flags |= KEYEVENTF_KEYUP;

	if (flags & KBD_FLAGS_EXTENDED)
		event.u.ki.flags |= KEYEVENTF_EXTENDEDKEY;

	rc = kosSendInput(1, &event);
	if (rc == 0) {
		return FALSE;
	}
	return TRUE;
}
/*
static BOOL kos_shadow_input_unicode_keyboard_event(rdpShadowSubsystem* subsystem,
                                                    rdpShadowClient* client, UINT16 flags,
                                                    UINT16 code)
{
	UINT rc;
	INPUT event;
	event.type = INPUT_KEYBOARD;
	event.ki.wVk = 0;
	event.ki.wScan = code;
	event.ki.dwFlags = KEYEVENTF_UNICODE;
	event.ki.dwExtraInfo = 0;
	event.ki.time = 0;

	if (flags & KBD_FLAGS_RELEASE)
		event.ki.dwFlags |= KEYEVENTF_KEYUP;

	rc = SendInput(1, &event, sizeof(INPUT));
	if (rc == 0)
		return FALSE;
	return TRUE;
}
*/
static BOOL kos_shadow_input_mouse_event(rdpShadowSubsystem* subsystem, rdpShadowClient* client,
                                         UINT16 flags, UINT16 x, UINT16 y)
{
	UINT rc = 1;
	KosInput event;
	// float width;
	// float height;
	ZeroMemory(&event, sizeof(KosInput));
	event.type = KOS_INPUT_MOUSE;

	if (flags & (PTR_FLAGS_WHEEL | PTR_FLAGS_HWHEEL))
	{
		if (flags & PTR_FLAGS_WHEEL)
			event.u.mi.flags = MOUSEEVENTF_WHEEL;
		else
			event.u.mi.flags = MOUSEEVENTF_HWHEEL;
		event.u.mi.mouse_data = flags & WheelRotationMask;

		if (flags & PTR_FLAGS_WHEEL_NEGATIVE)
			event.u.mi.mouse_data *= -1;

		rc = kosSendInput(1, &event);
/*
		// The build target is a system that did not support MOUSEEVENTF_HWHEEL
		// but it may run on newer systems supporting it.
		// Ignore the return value in these cases.
		//
#if (_WIN32_WINNT < 0x0600)
		if (flags & PTR_FLAGS_HWHEEL)
			rc = 1;
#endif
*/
	} else {
		// width = (float)GetSystemMetrics(SM_CXSCREEN);
		// height = (float)GetSystemMetrics(SM_CYSCREEN);
/*
		width = 1920;
		height = 1080;
		event.u.mi.dx = (int)((float)x * (65535.0f / width));
		event.u.mi.dy = (int)((float)y * (65535.0f / height));
*/
		event.u.mi.dx = x;
		event.u.mi.dy = y;
		event.u.mi.flags = MOUSEEVENTF_ABSOLUTE;

		if (flags & PTR_FLAGS_MOVE) {
			event.u.mi.flags |= MOUSEEVENTF_MOVE;
			rc = kosSendInput(1, &event);
			if (rc == 0)
				return FALSE;
		}

		event.u.mi.flags = MOUSEEVENTF_ABSOLUTE;

		if (flags & PTR_FLAGS_BUTTON1) {
			if (flags & PTR_FLAGS_DOWN)
				event.u.mi.flags |= MOUSEEVENTF_LEFTDOWN;
			else
				event.u.mi.flags |= MOUSEEVENTF_LEFTUP;

			rc = kosSendInput(1, &event);
		} else if (flags & PTR_FLAGS_BUTTON2) {
			if (flags & PTR_FLAGS_DOWN)
				event.u.mi.flags |= MOUSEEVENTF_RIGHTDOWN;
			else
				event.u.mi.flags |= MOUSEEVENTF_RIGHTUP;

			rc = kosSendInput(1, &event);

		} else if (flags & PTR_FLAGS_BUTTON3) {
			if (flags & PTR_FLAGS_DOWN)
				event.u.mi.flags |= MOUSEEVENTF_MIDDLEDOWN;
			else
				event.u.mi.flags |= MOUSEEVENTF_MIDDLEUP;

			rc = kosSendInput(1, &event);
		}
	}

	if (rc == 0)
		return FALSE;
	return TRUE;
}

static BOOL kos_shadow_input_extended_mouse_event(rdpShadowSubsystem* subsystem,
                                                  rdpShadowClient* client, UINT16 flags, UINT16 x,
                                                  UINT16 y)
{
	UINT rc = 1;
	KosInput event;
	// float width;
	// float height;
	ZeroMemory(&event, sizeof(KosInput));

	if ((flags & PTR_XFLAGS_BUTTON1) || (flags & PTR_XFLAGS_BUTTON2))
	{
		event.type = KOS_INPUT_MOUSE;

		if (flags & PTR_FLAGS_MOVE)
		{
			// width = (float)GetSystemMetrics(SM_CXSCREEN);
			// height = (float)GetSystemMetrics(SM_CYSCREEN);
/*
			width = 1920;
			height = 1080;
			event.u.mi.dx = (int)((float)x * (65535.0f / width));
			event.u.mi.dy = (int)((float)y * (65535.0f / height));
*/
			event.u.mi.dx = x;
			event.u.mi.dy = y;
			event.u.mi.flags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE;
			rc = kosSendInput(1, &event);
			if (rc == 0)
				return FALSE;
		}

		event.u.mi.dx = event.u.mi.dy = event.u.mi.flags = 0;

		if (flags & PTR_XFLAGS_DOWN)
			event.u.mi.flags |= MOUSEEVENTF_XDOWN;
		else
			event.u.mi.flags |= MOUSEEVENTF_XUP;

		if (flags & PTR_XFLAGS_BUTTON1)
			event.u.mi.mouse_data = XBUTTON1;
		else if (flags & PTR_XFLAGS_BUTTON2)
			event.u.mi.mouse_data = XBUTTON2;

		rc = kosSendInput(1, &event);
	}

	if (rc == 0)
		return FALSE;
	return TRUE;
}

static int kos_shadow_invalidate_region(kosShadowSubsystem* subsystem, int x, int y, int width,
                                        int height)
{
	rdpShadowServer* server;
	rdpShadowSurface* surface;
	RECTANGLE_16 invalidRect;
	server = subsystem->base.server;
	surface = server->surface;
	invalidRect.left = x;
	invalidRect.top = y;
	invalidRect.right = x + width;
	invalidRect.bottom = y + height;
	EnterCriticalSection(&(surface->lock));
	region16_union_rect(&(surface->invalidRegion), &(surface->invalidRegion), &invalidRect);
	LeaveCriticalSection(&(surface->lock));
	return 1;
}

tfile* file = nullptr;
void tscreen_encoder::app_encoded_image(const scoped_refptr<net::IOBufferWithSize>& image)
{
	// screen_.did_encoded_image(image);
	// if (file != nullptr && encoded_frames <= 2) {
	if (file != nullptr) {
		int size = image->size();
		posix_fwrite(file->fp, &size, sizeof(int));
		posix_fwrite(file->fp, image->data(), image->size());
	}
}

void trecord_screen::did_encoded_image(const scoped_refptr<net::IOBufferWithSize>& image)
{
	threading::lock lock(encoded_images_mutex_);
	encoded_images.push(image);
}

void trecord_screen::did_screen_captured(uint8_t* pixel_buf, int length, int width, int height)
{
	rdpShadowServer* server = subsystem_.base.server;
	rdpShadowSurface* surface = server->surface;

	if (ArrayList_Count(server->clients) < 1) {
		// this client maybe disconnecting...
		return;
	}

	if (captured_is_h264) {
		scoped_refptr<net::IOBufferWithSize> image = new net::IOBufferWithSize(length);
		memcpy(image->data(), pixel_buf, length);
		{
			threading::lock lock(encoded_images_mutex_);
			encoded_images.push(image);
		}
		if (length > max_one_frame_bytes) {
			max_one_frame_bytes = length;
		}
/*
		surface->h264Length = length;
		memcpy(surface->data, pixel_buf, surface->h264Length);
*/
	} else {
		VALIDATE(length == width * height * kGlBytesPerPixel, null_str);
		VALIDATE(encoder_.get() != nullptr, null_str);
		encoder_->encode_frame_fourcc(pixel_buf, length, width, height, libyuv::FOURCC_ABGR);
	}

	last_capture_frames ++;
	last_capture_bytes += length;
/*
	RECTANGLE_16 invalidRect;
	invalidRect.left = 0;
	invalidRect.top = 0;
	invalidRect.right = width;
	invalidRect.bottom = height;
	region16_union_rect(&(surface->invalidRegion), &(surface->invalidRegion), &invalidRect);

	ArrayList_Lock(server->clients);
	int count = ArrayList_Count(server->clients);
	shadow_subsystem_frame_update(&subsystem_.base);
	ArrayList_Unlock(server->clients);
	region16_clear(&(surface->invalidRegion));
*/
}

void did_gui2_screen_captured(uint8_t* pixel_buf, int length, int width, int height, uint32_t flags, void* user)
{
	VALIDATE(length > 0, null_str);
	trecord_screen* record = reinterpret_cast<trecord_screen*>(user);
	record->did_screen_captured(pixel_buf, length, width, height);
}

void trecord_screen::clear_session_variables()
{
	if (!encoded_images.empty()) {
		std::queue<scoped_refptr<net::IOBufferWithSize> > empty;
		std::swap(empty, encoded_images);
	}

    last_capture_frames = 0;
	last_capture_bytes = 0;
	max_one_frame_bytes = 0;
}

void trecord_screen::start_internal()
{
	// Until now, the h264-compressed frames have not been serialized to RecordScreenThread thread, 
	// and will result to fault. Currently only h264 = true is supported.
	VALIDATE(captured_is_h264, null_str);

	VALIDATE_NOT_MAIN_THREAD();
	VALIDATE(encoded_images.empty(), null_str);
	if (!captured_is_h264) {
		file = new tfile("c:/ddksample/test-1920x1080.h264", GENERIC_WRITE, CREATE_ALWAYS);
		encoder_.reset(new tscreen_encoder(*this));
	}
	kosRecordScreenLoop(captured_is_h264? 8000: 0, pixel_buf_, did_gui2_screen_captured, this);
	if (!captured_is_h264) {
		encoder_.reset();
		delete file;
	}
	file = nullptr;
}

void trecord_screen::start()
{
	CHECK(thread_.get() == nullptr);
	thread_.reset(new base::Thread("RecordScreenThread"));

	base::Thread::Options socket_thread_options;
	socket_thread_options.message_loop_type = base::MessageLoop::TYPE_IO;
	socket_thread_options.timer_slack = base::TIMER_SLACK_MAXIMUM;
	CHECK(thread_->StartWithOptions(socket_thread_options));

	thread_->task_runner()->PostTask(FROM_HERE, base::BindOnce(&trecord_screen::start_internal, base::Unretained(this)));
}

void trecord_screen::stop()
{
	// VALIDATE_IN_MAIN_THREAD();
	if (thread_.get() == nullptr) {
		return;
	}
	kosStopRecordScreen();
	// base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, base::MessageLoop::QuitWhenIdleClosure());
	// thread_->task_runner()->PostTask(FROM_HERE, base::MessageLoop::QuitWhenIdleClosure());
	SDL_Log("%u trecord_screen::stop---", SDL_GetTicks());
	thread_.reset();

	clear_session_variables();

	SDL_Log("%u ---trecord_screen::stop X", SDL_GetTicks());
}

static UINT32 kos_shadow_enum_monitors(MONITOR_DEF* monitors, UINT32 maxMonitors)
{
	int index;
	int desktopWidth = 1920;
	int desktopHeight = 1080;
	DWORD iDevNum = 0;
	int numMonitors = 0;
	MONITOR_DEF* monitor;

	{
		index = 0;
		numMonitors = 1;
		monitor = &monitors[index];
		monitor->left = 0;
		monitor->top = 0;
		monitor->right = desktopWidth;
		monitor->bottom = desktopHeight;
		monitor->flags = 1;
	}
	return numMonitors;
}

static int kos_shadow_subsystem_init(rdpShadowSubsystem* arg)
{
	kosShadowSubsystem* subsystem = (kosShadowSubsystem*)arg;
	// int status;
	MONITOR_DEF* virtualScreen;
	subsystem->base.numMonitors = kos_shadow_enum_monitors(subsystem->base.monitors, 16);
	virtualScreen = &(subsystem->base.virtualScreen);
	virtualScreen->left = 0;
	virtualScreen->top = 0;
	virtualScreen->right = 0; // subsystem->base.monitors[0].right
	virtualScreen->bottom = 0; // subsystem->base.monitors[0].bottom
	virtualScreen->flags = 1;
	return 1;
}

static int kos_shadow_subsystem_uninit(rdpShadowSubsystem* arg)
{
	kosShadowSubsystem* subsystem = (kosShadowSubsystem*)arg;

	if (!subsystem)
		return -1;

	// kos_shadow_dxgi_uninit(subsystem);
	return 1;
}

static int kos_shadow_subsystem_start(rdpShadowSubsystem* arg)
{
	kosShadowSubsystem* subsystem = (kosShadowSubsystem*)arg;

	if (!subsystem)
		return -1;

	// subsystem->record_screen->start();
	return 1;
}

int rose_shadow_subsystem_start(rdpShadowSubsystem* arg)
{
	SDL_Log("rose_shadow_subsystem_start---");
	kosShadowSubsystem* subsystem = (kosShadowSubsystem*)arg;
	if (!subsystem) {
		SDL_Log("---rose_shadow_subsystem_start X, subsystem is nullptr");
		return -1;
	}

	subsystem->record_screen->start();
	SDL_Log("---rose_shadow_subsystem_start X");
	return 1;
}

static int kos_shadow_subsystem_stop(rdpShadowSubsystem* arg)
{
	SDL_Log("kos_shadow_subsystem_stop---");
	kosShadowSubsystem* subsystem = (kosShadowSubsystem*)arg;

	if (!subsystem) {
		SDL_Log("---kos_shadow_subsystem_stop X, subsystem is nullptr");
		return -1;
	}
	subsystem->record_screen->stop();
	SDL_Log("---kos_shadow_subsystem_stop X");
	return 1;
}

int rose_shadow_subsystem_stop(rdpShadowSubsystem* arg)
{
	return kos_shadow_subsystem_stop(arg);
}

static void kos_shadow_subsystem_free(rdpShadowSubsystem* arg)
{
	kosShadowSubsystem* subsystem = (kosShadowSubsystem*)arg;

	if (!subsystem)
		return;

	kos_shadow_subsystem_uninit(arg);
	delete subsystem->record_screen;
	free(subsystem);
}

static rdpShadowSubsystem* kos_shadow_subsystem_new(void)
{
	kosShadowSubsystem* subsystem;
	subsystem = (kosShadowSubsystem*)calloc(1, sizeof(kosShadowSubsystem));

	if (!subsystem) {
		return NULL;
	}
	subsystem->record_screen = new trecord_screen(*subsystem);

	subsystem->base.SynchronizeEvent = kos_shadow_input_synchronize_event;
	subsystem->base.KeyboardEvent = kos_shadow_input_keyboard_event;
	// subsystem->base.UnicodeKeyboardEvent = kos_shadow_input_unicode_keyboard_event;
	subsystem->base.UnicodeKeyboardEvent = nullptr;
	subsystem->base.MouseEvent = kos_shadow_input_mouse_event;
	subsystem->base.ExtendedMouseEvent = kos_shadow_input_extended_mouse_event;
	return &subsystem->base;
}

int kos_ShadowSubsystemEntry(RDP_SHADOW_ENTRY_POINTS* pEntryPoints)
{
	pEntryPoints->New = kos_shadow_subsystem_new;
	pEntryPoints->Free = kos_shadow_subsystem_free;
	pEntryPoints->Init = kos_shadow_subsystem_init;
	pEntryPoints->Uninit = kos_shadow_subsystem_uninit;
	pEntryPoints->Start = kos_shadow_subsystem_start;
	pEntryPoints->Stop = kos_shadow_subsystem_stop;
	pEntryPoints->EnumMonitors = kos_shadow_enum_monitors;
	return 1;
}
