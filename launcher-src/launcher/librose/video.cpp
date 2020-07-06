/* $Id: video.cpp 46847 2010-10-01 01:43:16Z alink $ */
/*
   Copyright (C) 2003 - 2010 by David White <dave@whitevine.net>
   Part of the Battle for Wesnoth Project http://www.wesnoth.org/

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY.

   See the COPYING file for more details.
*/

/**
 *  @file
 *  Video-testprogram, standalone
 */
#define GETTEXT_DOMAIN "rose-lib"

#include "global.hpp"

#include "font.hpp"
#include "image.hpp"
#include "preferences.hpp"
#include "preferences_display.hpp"
#include "sdl_utils.hpp"
#include "video.hpp"
#include "gettext.hpp"
#include "base_instance.hpp"
#include <boost/foreach.hpp>
#include <vector>
#include <map>
#include <algorithm>

namespace {
	bool fullScreen = false;
	bool windows_use_opengl = true;
}

static unsigned int get_flags(unsigned int flags)
{
#if defined(__APPLE__) && TARGET_OS_IPHONE
	// flags |= SDL_WINDOW_BORDERLESS; // if want to hide status bar, se it.
#else
	if (!(flags & SDL_WINDOW_FULLSCREEN)) {
		flags |= SDL_WINDOW_RESIZABLE;
	}
#endif

	flags |= SDL_WINDOW_ALLOW_HIGHDPI;

#ifdef _WIN32
	if (windows_use_opengl) {
		flags |= SDL_WINDOW_OPENGL;
	}
#endif

	return flags;
}

namespace {
struct event {
	int x, y, w, h;
	bool in;
	event(const SDL_Rect& rect, bool i) : x(i ? rect.x : rect.x + rect.w), y(rect.y), w(rect.w), h(rect.h), in(i) { }
};
bool operator<(const event& a, const event& b) {
	if (a.x != b.x) return a.x < b.x;
	if (a.in != b.in) return a.in;
	if (a.y != b.y) return a.y < b.y;
	if (a.h != b.h) return a.h < b.h;
	if (a.w != b.w) return a.w < b.w;
	return false;
}
bool operator==(const event& a, const event& b) {
	return a.x == b.x && a.y == b.y && a.w == b.w && a.h == b.h && a.in == b.in;
}

struct segment {
	int x, count;
	segment() : x(0), count(0) { }
	segment(int x, int count) : x(x), count(count) { }
};

}

namespace {
Uint32 current_format = SDL_PIXELFORMAT_UNKNOWN;
SDL_Renderer* renderer = NULL;
SDL_Window* window = NULL;
texture frameTexture = NULL;
texture whiteTexture;
int frame_width = 0;
int frame_height = 0;
}

SDL_Renderer* get_renderer()
{
	return renderer;
}

texture& get_screen_texture()
{
	return frameTexture;
}

texture& get_white_texture()
{
	return whiteTexture;
}

int get_screen_width()
{
	return frame_width;
}

int get_screen_height()
{
	return frame_height;
}

SDL_Rect screen_area()
{
	return create_rect(0, 0, frame_width, frame_height);
}

static void clear_textures()
{
	image::flush_cache(true);
	if (frameTexture.get() == NULL) {
		return;
	}
	VALIDATE(frameTexture.unique() && whiteTexture.unique(), null_str);

	frameTexture = NULL;
	whiteTexture = NULL;
}

const SDL_PixelFormat& get_screen_format()
{
	return get_neutral_pixel_format();
}

CVideo::CVideo()
	: updatesLocked_(0)
{
	// on ios and android, disable screensaver will result to disable entering idle.
	// in order to control idle, advice to use SDL_HINT_IDLE_TIMER_DISABLED.
	SDL_SetHint(SDL_HINT_VIDEO_ALLOW_SCREENSAVER, "1");

	initSDL();
}

void CVideo::initSDL()
{
	const int res = SDL_InitSubSystem(SDL_INIT_VIDEO | SDL_INIT_NOPARACHUTE);
	if (res < 0) {
		throw CVideo::error();
	}
/*
	// now don't call it. why?
	// --on android, it will result popup soft-keyboard. I don't known reason.
	if (SDL_GetEventState(SDL_TEXTINPUT) != SDL_ENABLE) {
		// in SDL, ScreenKeyboard is soft keyboard.
		// to non-screenkeyboard(for exmaple windows), SDL_VideoInit(SDL_video.c) is call it by default
		SDL_EventState(SDL_TEXTINPUT, SDL_ENABLE);
	}
*/
}

CVideo::~CVideo()
{
	SDL_Log("CVideo::~CVideo(), 1");
	// since rendere will be destroy, texture associated it should be release.
	clear_textures();
	if (renderer) {
		SDL_DestroyRenderer(renderer);
	}
	// SDL_DestroyTexture/SDL_DestroyRenderer requrie EGLContext, and SDL_DestroyWindow will delete EGLContext
	// so call SDL_DestroyWindow after them.
	if (window) {
		SDL_DestroyWindow(window);
		window = NULL;
	}
	SDL_Quit();
	SDL_Log("CVideo::~CVideo(), 2");
}

bool CVideo::setMode(int w, int h, int flags)
{
	bool reset_zoom = frameTexture.get()? false: true;

	flags = get_flags(flags);

	if (current_format == SDL_PIXELFORMAT_UNKNOWN) {
		current_format = SDL_PIXELFORMAT_ARGB8888;
	}

	fullScreen = (flags & SDL_WINDOW_FULLSCREEN) != 0;
	instance->pre_create_renderer();
	// since rendere will be destroy, texture associated it should be release.
	clear_textures();
	if (renderer) {
		SDL_DestroyRenderer(renderer);
	}
	// SDL_DestroyTexture/SDL_DestroyRenderer requrie EGLContext, and SDL_DestroyWindow will delete EGLContext
	// so call SDL_DestroyWindow after them.
	if (window) {
		SDL_DestroyWindow(window);
		window = NULL;
	}

	int x = SDL_WINDOWPOS_UNDEFINED;
	int y = SDL_WINDOWPOS_UNDEFINED;

#if (defined(__APPLE__) && TARGET_OS_IPHONE)	
	x = y = 0;
#endif

	SDL_Log("setMode, (%i, %i, %i, %i)", x, y, w, h);

	window = SDL_CreateWindow(game_config::get_app_msgstr(null_str).c_str(), x, y, w, h, flags);

	SDL_SetHint(SDL_HINT_RENDER_SCALE_QUALITY, "linear");
#ifdef _WIN32
	if (windows_use_opengl) {
		SDL_SetHint(SDL_HINT_RENDER_DRIVER, "opengl");
		// SDL_SetHint(SDL_HINT_RENDER_DRIVER, "opengles2");
	}
#endif
	renderer = SDL_CreateRenderer(window, -1, 0);

#if (defined(__APPLE__) && TARGET_OS_IPHONE)
	{
		// Fix Bug!
		int w2, h2;
		SDL_GetWindowSize(window, &w2, &h2);
		SDL_Log("setMode, create size: %ix%i, requrie: %ix%i", w2, h2, w, h);

		SDL_SetWindowSize(window, w, h);
	}
#endif
	// for android os, status bar effect desired and actual size.
	SDL_GetWindowSize(window, &w, &h);

	frame_width = w;
	frame_height = h;
	frameTexture = SDL_CreateTexture(renderer, current_format, SDL_TEXTUREACCESS_TARGET, w, h);	
	if (frameTexture.get() == NULL) {
		return false;
	}
	SDL_SetRenderTarget(renderer, frameTexture.get());

	// white texture. use to brighten.
	surface surf = image::get_image("misc/white-background.png");
	whiteTexture = SDL_CreateTextureFromSurface(renderer, surf);

	SDL_SetTextureBlendMode(frameTexture.get(), SDL_BLENDMODE_NONE);
	image::set_pixel_format(get_neutral_pixel_format());
	game_config::svga = frame_width >= 800 * gui2::twidget::hdpi_scale && frame_height >= 600 * gui2::twidget::hdpi_scale;
	if (reset_zoom) {
		int zoom = preferences::zoom();
		image::set_zoom(zoom);
	}

	instance->post_create_renderer();

	return true;
}

int CVideo::getx() const
{
	return frame_width;
}

int CVideo::gety() const
{
	return frame_height;
}

SDL_Rect CVideo::bound() const
{
	SDL_Rect rc;
	int display = window? SDL_GetWindowDisplayIndex(window): 0;
	SDL_GetDisplayBounds(display, &rc);
	return rc;
}

void CVideo::sdl_set_window_size(int width, int height)
{
	SDL_SetWindowSize(window, width, height);
}

const SDL_PixelFormat& CVideo::getformat() const
{
	return get_neutral_pixel_format();
}

void CVideo::flip()
{
    // when enable background audio, will enter it during background.
    if (!instance->foreground()) {
        return;
    }

	texture null_tex;
	trender_target_lock lock(renderer, null_tex);
	SDL_RenderCopy(renderer, frameTexture.get(), NULL, NULL);
/*
	static texture grace_hopper;
	if (grace_hopper.get() == nullptr) {
		surface surf = image::get_image("misc/grace_hopper.png");
		grace_hopper = SDL_CreateTextureFromSurface(get_renderer(), surf);
		SDL_UpdateTexture(grace_hopper.get(), nullptr, surf->pixels, surf->pitch);
	}

	SDL_Rect dstrect {(frame_width - frame_height) / 2, -(frame_width - frame_height) / 2, frame_height, frame_width};
	SDL_RenderCopyEx(renderer, grace_hopper.get(), nullptr, &dstrect, 90, nullptr, SDL_FLIP_NONE);
*/
	SDL_RenderPresent(renderer);
}

void CVideo::lock_updates(bool value)
{
	if (value == true) {
		++ updatesLocked_;
	} else {
		-- updatesLocked_;
	}
}

bool CVideo::update_locked() const
{
	return updatesLocked_ > 0;
}

texture& CVideo::getTexture()
{
	return frameTexture;
}

SDL_Window* CVideo::getWindow()
{
	return window;
}

bool CVideo::isFullScreen() const { return fullScreen; }
