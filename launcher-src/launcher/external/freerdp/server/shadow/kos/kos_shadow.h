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

#ifndef FREERDP_SERVER_SHADOW_KOS_H
#define FREERDP_SERVER_SHADOW_KOS_H

#include <freerdp/assistance.h>

#include <freerdp/server/shadow.h>

/*
#include <winpr/crt.h>
#include <winpr/synch.h>
#include <winpr/thread.h>
#include <winpr/stream.h>
#include <winpr/collections.h>
*/
#include <rtc_client.hpp>

// webrtc
#include "rtc_base/event.h"
#include "base/threading/thread.h"

#include <kosapi/gui.h>

static const int kGlBytesPerPixel = 4;      // GL_RGBA
static const int kOutBytesPerPixel = 3;     // RGB only

struct kosShadowSubsystem;
class trecord_screen;

class tscreen_encoder: public twebrtc_encoder
{
public:
    tscreen_encoder(trecord_screen& screen)
        : twebrtc_encoder("H264", 8000)
        , screen_(screen)
    {}

private:
    void app_encoded_image(const scoped_refptr<net::IOBufferWithSize>& image) override;

private:
    trecord_screen& screen_;
};

class trecord_screen
{
public:
	trecord_screen(kosShadowSubsystem& subsystem)
        : subsystem_(subsystem)
        , max_encoded_threshold(3)
        , captured_is_h264(true)
        , last_capture_frames(0)
		, last_capture_bytes(0)
        , max_one_frame_bytes(0)
	{
		pixel_buf_ = new uint8_t[1920 * 1080 * kGlBytesPerPixel];
	}
	~trecord_screen()
	{
		delete[] pixel_buf_;
	}

	void start();
	void stop();
    bool thread_started() const { return thread_.get() != nullptr; }

    void did_screen_captured(uint8_t* pixel_buf, int length, int width, int height);
    void did_encoded_image(const scoped_refptr<net::IOBufferWithSize>& image);

    threading::mutex& encoded_images_mutex() { return encoded_images_mutex_; }

public:
	uint8_t* pixel_buf_;
    const int max_encoded_threshold;
    std::queue<scoped_refptr<net::IOBufferWithSize> > encoded_images;
    bool captured_is_h264;

    int last_capture_frames;
	int last_capture_bytes;
    int max_one_frame_bytes;

private:
	void start_internal();
    void clear_session_variables();

private:
    kosShadowSubsystem& subsystem_;
	std::unique_ptr<base::Thread> thread_;
    std::unique_ptr<tscreen_encoder> encoder_;
    threading::mutex encoded_images_mutex_;
};

struct kosShadowSubsystem
{
	rdpShadowSubsystem base;

	trecord_screen* record_screen;
};

#ifdef __cplusplus
extern "C"
{
#endif

int rose_shadow_subsystem_start(rdpShadowSubsystem* arg);
int rose_shadow_subsystem_stop(rdpShadowSubsystem* arg);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_SERVER_SHADOW_KOS_H */
