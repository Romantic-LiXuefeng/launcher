#define GETTEXT_DOMAIN "rose-lib"

#include "filesystem.hpp"
#include "serialization/string_utils.hpp"
#include "wml_exception.hpp"

#include <SDL.h>
#include <opencv2/imgproc/imgproc.hpp>

#include <boost/bind.hpp>
#include <numeric>
#include <iomanip>

#include <kosapi/gui.h>

#ifndef _WIN32
#error "This file is impletement of libkosapi.so on windows!"
#endif

static const int kGlBytesPerPixel = 4;      // GL_RGBA
static const int kOutBytesPerPixel = 3;     // RGB only
static bool gPause = false;

struct tfile_header {
	uint32_t packet_len;
	uint32_t width;
	uint32_t height;
	uint32_t stride;
	uint32_t format;
};

void increseRgbToRgba(const uint8_t* src, uint8_t* dst, unsigned int pixelCount)
{
    // Convert RGBA to RGB.
    //
    // Unaligned 32-bit accesses are allowed on ARM, so we could do this
    // with 32-bit copies advancing at different rates (taking care at the
    // end to not go one byte over).
    const uint8_t* readPtr = src;
    for (unsigned int i = 0; i < pixelCount; i++) {
        *dst++ = readPtr[0];
        *dst++ = readPtr[1];
        *dst++ = readPtr[2];
        *dst++ = 0xff;
		readPtr += 3;
    }
}

static bool request_quit_record_screen = false;
static int gui2_record_screen_loop_raw_frame(uint8_t* pixel_buf, fdid_gui2_screen_captured did, void* user)
{
	request_quit_record_screen = false;

	tfile file("c:/ddksample/demo.frames", GENERIC_READ, OPEN_EXISTING);
	int64_t fsize = posix_fsize(file.fp);
	VALIDATE(fsize > 0, null_str);
	posix_fseek(file.fp, 0);

	tfile_header header;
	int64_t pos = 0;
	while (pos < fsize && !request_quit_record_screen) {
		int read_bytes = posix_fread(file.fp, &header, sizeof(tfile_header));
		VALIDATE(read_bytes == sizeof(tfile_header), null_str);
		VALIDATE(header.width == 1920 && header.height == 1080, null_str);
		VALIDATE(header.stride == header.width * kOutBytesPerPixel, null_str);
		VALIDATE(header.packet_len == sizeof(header) + header.stride * header.height - sizeof(uint32_t), null_str);

		const int frame_len = header.stride * header.height;
		file.resize_data(frame_len);
		read_bytes = posix_fread(file.fp, file.data, frame_len);

		VALIDATE(read_bytes == frame_len, null_str);
		increseRgbToRgba((const uint8_t*)file.data, pixel_buf, header.width * header.height);
		did(pixel_buf, header.width * header.height * kGlBytesPerPixel, header.width, header.height, 0, user);
		pos += header.packet_len + sizeof(uint32_t);
		SDL_Delay(200);
		if (pos == fsize) {
			// loop again
			pos = 0;
			posix_fseek(file.fp, pos);
		}
	}
	VALIDATE(pos == fsize || request_quit_record_screen, null_str);
	SDL_Log("%u ---kosRecordScreenLoop XXX", SDL_GetTicks());
	return 0;
}

struct th264file_header {
	uint32_t packet_len;
};
static int gui2_record_screen_loop_h264(uint8_t* pixel_buf, fdid_gui2_screen_captured did, void* user)
{
	request_quit_record_screen = false;

	tfile file("c:/ddksample/test-1920x1080.h264", GENERIC_READ, OPEN_EXISTING);
	int64_t fsize = posix_fsize(file.fp);
	VALIDATE(fsize > 0, null_str);
	posix_fseek(file.fp, 0);

	const int width = 1920;
	const int height = 1080;
	th264file_header header;
	int64_t pos = 0;
	while (pos < fsize && !request_quit_record_screen) {
		if (gPause) {
			SDL_Delay(300);
			continue;
		}
		int read_bytes = posix_fread(file.fp, &header, sizeof(th264file_header));
		VALIDATE(read_bytes == sizeof(th264file_header), null_str);
		VALIDATE(header.packet_len > 0, null_str);

		const int frame_len = header.packet_len;
		// file.resize_data(frame_len);
		read_bytes = posix_fread(file.fp, pixel_buf, frame_len);

		VALIDATE(read_bytes == frame_len, null_str);
		did(pixel_buf, header.packet_len, width, height, 0, user);
		pos += sizeof(uint32_t) + header.packet_len;
		SDL_Delay(100);
		if (pos == fsize) {
			// loop again
			pos = 0;
			posix_fseek(file.fp, pos);
		}
	}
	VALIDATE(pos == fsize || request_quit_record_screen, null_str);
	gPause = false;
	SDL_Log("%u ---gui2_record_screen_loop_h264 XXX", SDL_GetTicks());
	return 0;
}

int kosRecordScreenLoop(uint32_t bitrate_kbps, uint8_t* pixel_buf, fdid_gui2_screen_captured did, void* user)
{
	if (bitrate_kbps > 0) {
		return gui2_record_screen_loop_h264(pixel_buf, did, user);
	} else {
		return gui2_record_screen_loop_raw_frame(pixel_buf, did, user);
	}
}

void kosStopRecordScreen()
{
	request_quit_record_screen = true;
}

void kosPauseRecordScreen(bool pause)
{
	gPause = pause;
}

bool kosRecordScreenPaused()
{
	return gPause;
}


