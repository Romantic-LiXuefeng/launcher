/* $Id$ */
/*
   Copyright (C) 2011 Sergey Popov <loonycyborg@gmail.com>
   Part of the Battle for Wesnoth Project http://www.wesnoth.org/

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY.

   See the COPYING file for more details.
*/

#define GETTEXT_DOMAIN "rose-lib"

#include "gui/dialogs/progress.hpp"

#include "gettext.hpp"
#include "gui/widgets/button.hpp"
#include "gui/widgets/label.hpp"
#include "gui/widgets/track.hpp"
#include "gui/widgets/settings.hpp"
#include "gui/widgets/window.hpp"

#include <boost/bind.hpp>

#include "font.hpp"

namespace gui2 {

REGISTER_DIALOG(rose, progress)

tprogress_* tprogress_::instance = nullptr;

tprogress::tprogress(const std::string& title, const std::string& message, const boost::function<bool (tprogress_&)>& did_first_drawn, int hidden_ms, const std::string& cancel_img, int best_width, int best_height, const boost::function<void (ttrack&, const SDL_Rect&, int, const std::string&)>& did_draw_bar)
	: title_(title)
	, message_(message)
	, start_ticks_(SDL_GetTicks())
	, did_first_drawn_(did_first_drawn)
	, hidden_ticks_(hidden_ms)
	, cancel_img_(cancel_img)
	, require_cancel_(false)
	, track_best_width_(best_width)
	, track_best_height_(best_height)
	, did_draw_bar_(did_draw_bar)
{
	VALIDATE(did_first_drawn_, null_str);

	VALIDATE(tprogress_::instance == nullptr, "only allows a maximum of one tprogress");
	tprogress_::instance = this;
}

tprogress::~tprogress()
{
	VALIDATE(!timer_.valid(), null_str);
	tprogress_::instance = nullptr;
}

void tprogress::pre_show()
{
	if (!title_.empty()) {
		tlabel* label = find_widget<tlabel>(window_, "title", false, false);
		label->set_label(title_);
	} else {
		window_->set_margin(0, 0, 0, 0);
		window_->set_border(null_str);
	}

	const int initial_percentage = hidden_ticks_ == 0? PROGRESS_MIN_PERCENTAGE: PROGRESS_MAX_PERCENTAGE;
	progress_.reset(new tprogress_bar(*window_, find_widget<twidget>(window_, "_progress", false), message_, initial_percentage, did_draw_bar_));
	progress_->track().set_best_size_1th(track_best_width_, progress_->track().get_width_is_max(), track_best_height_, progress_->track().get_height_is_max());

	tbutton* button = find_widget<tbutton>(window_, "_cancel", false, false);
	if (cancel_img_.empty()) {
		button->set_visible(twidget::INVISIBLE);
	} else {
		button->set_label(cancel_img_);
	}

	connect_signal_mouse_left_click(
		*button
		, boost::bind(
		&tprogress::click_cancel
		, this));

	if (hidden_ticks_ != 0) {
		window_->set_visible(twidget::INVISIBLE);
	}
}

void tprogress::post_show()
{
}

void tprogress::app_first_drawn()
{
	bool ret = did_first_drawn_(*this);
	VALIDATE(!window_->is_closing(), null_str);

	if (ret) {
		VALIDATE(!require_cancel_, null_str);
		window_->set_retval(twindow::OK);
	} else {
		window_->set_retval(twindow::CANCEL);
	}
}

void tprogress::timer_handler(bool render_track)
{
	if (window_->get_visible() != twidget::VISIBLE && SDL_GetTicks() - start_ticks_ >= hidden_ticks_) {
		window_->set_visible(twidget::VISIBLE);
		hidden_ticks_ = UINT32_MAX;
	}

	if (render_track && window_->get_visible() == twidget::VISIBLE) {
		progress_->track().timer_handler();
	}
}

void tprogress::set_percentage(const int percentage)
{
	VALIDATE(percentage >= PROGRESS_MIN_PERCENTAGE && percentage <= PROGRESS_MAX_PERCENTAGE, null_str);

	bool changed = progress_->set_percentage(percentage);
	if (changed) {
		timer_handler(false);
		window_->show_slice();
	}
}

void tprogress::set_message(const std::string& message)
{
	bool changed = progress_->set_message(message);
	if (changed) {
		timer_handler(false);
		window_->show_slice();
	}
}

void tprogress::set_align(int align)
{
	progress_->set_align(align);
}

void tprogress::cancel_task()
{
	VALIDATE(!require_cancel_, null_str);
	require_cancel_ = true;
}

void tprogress::show_slice()
{ 
	timer_handler(true);
	window_->show_slice(); 
}

bool tprogress::is_visible() const
{
	return window_->get_visible() == twidget::VISIBLE;
}

void tprogress::click_cancel()
{
	if (!require_cancel_) {
		cancel_task();
	}
}

bool run_with_progress_dlg(const std::string& title, const std::string& message, const boost::function<bool (tprogress_&)>& did_first_drawn, int hidden_ms, const std::string& cancel_img, const SDL_Rect& rect, const boost::function<void (ttrack&, const SDL_Rect&, int, const std::string&)>& did_draw_bar)
{
	gui2::tprogress dlg(title, message, did_first_drawn, hidden_ms, cancel_img, rect.w, rect.h, did_draw_bar);
	dlg.show(rect.x, rect.y);

	return dlg.get_retval() == twindow::OK;
}

//
// tprogress_widget
//
tprogress_widget::tprogress_widget(twindow& window, bool clear_event, const std::string& message, const boost::function<bool (tprogress_&)>& did_first_drawn, int hidden_ms, const SDL_Rect& rect, const boost::function<void (ttrack&, const SDL_Rect&, int, const std::string&)>& did_draw_bar)
	: window_(window)
	, float_track_(window.float_track())
	, message_(message)
	, start_ticks_(SDL_GetTicks())
	, did_first_drawn_(did_first_drawn)
	, hidden_ticks_(hidden_ms)
	, clear_event_(clear_event)
	, track_rect_(rect)
	, did_draw_bar_(did_draw_bar)
{
	VALIDATE(did_first_drawn_, null_str);

	VALIDATE(!float_track_.is_visible(), null_str);
	VALIDATE(tprogress_::instance == nullptr, "only allows a maximum of one tprogress");
	tprogress_::instance = this;

	pre_show();
}

tprogress_widget::~tprogress_widget()
{
	float_track_.set_visible(false);
	tprogress_::instance = nullptr;
}

void tprogress_widget::pre_show()
{
	const int initial_percentage = hidden_ticks_ == 0? PROGRESS_MIN_PERCENTAGE: PROGRESS_MAX_PERCENTAGE;
	progress_.reset(new tprogress_bar(window_, *float_track_.widget.get(), message_, initial_percentage, did_draw_bar_));

	ttrack& track = progress_->track();
	float_track_.set_ref_widget(&window_, tpoint(track_rect_.x, track_rect_.y));
	track.set_layout_size(tpoint(track_rect_.w, track_rect_.h));
	// if set need_layut to true, old dirty background may appear after be invisible.
	// reference to "canvas = widget.get_canvas_tex();" in twindow::draw_float_widgets().
	float_track_.need_layout = true;

	if (hidden_ticks_ != 0) {
		float_track_.set_visible(false);
	} else {
		set_visible();
	}
}

void tprogress_widget::timer_handler(bool render_track)
{
	if (!float_track_.is_visible() && SDL_GetTicks() - start_ticks_ >= hidden_ticks_) {
		set_visible();
		hidden_ticks_ = UINT32_MAX;
	}

	if (render_track && float_track_.is_visible()) {
		progress_->track().timer_handler();
	}
}

void tprogress_widget::set_percentage(const int percentage)
{
	VALIDATE(percentage >= 0 && percentage <= 100, null_str);

	bool changed = progress_->set_percentage(percentage);
	if (changed) {
		timer_handler(false);
		absolute_draw_float_widgets();
	}
}

void tprogress_widget::set_message(const std::string& message)
{
	bool changed = progress_->set_message(message);
	if (changed) {
		timer_handler(false);
		absolute_draw_float_widgets();
	}
}

void tprogress_widget::set_align(int align)
{
	progress_->set_align(align);
}

void tprogress_widget::show_slice()
{
	timer_handler(true);
	if (true) {
		// Must not call window_.show_slice()! it will process event, for example mouse.
		// why? 1)click result run progress_widget. 
		// 2)click it again, will result run progress_widget agin, but first is running. throw exception.
		// ==>Base rule: during run_with_progress_xxx, must not process any event.
		if (clear_event_) {
			SDL_Event temp_event;
			while (SDL_PollEvent(&temp_event)) {}
		}

		// why not useab solute_draw()?
		// --twindow::draw will call ttrack::did_draw_, did_draw_ may run_with_progress_widget or user's app logic,
		//   and result dead-loop or exception.
		absolute_draw_float_widgets();

		// Add a delay so we don't keep spinning if there's no event.
		SDL_Delay(10);

	} else {
		window_.show_slice();
	}
}

bool tprogress_widget::is_visible() const
{
	return float_track_.is_visible();
}

void tprogress_widget::set_visible()
{
	VALIDATE(!float_track_.is_visible(), null_str);
	float_track_.set_visible(true);
	absolute_draw_float_widgets();
}

bool run_with_progress_widget(bool clear_event, const std::string& message, const boost::function<bool (tprogress_&)>& did_first_drawn, int hidden_ms, const SDL_Rect& _rect, const boost::function<void (ttrack&, const SDL_Rect&, int, const std::string&)>& did_draw_bar)
{
	std::vector<twindow*> connected = gui2::connectd_window();
	if (connected.empty()) {
		return run_with_progress_dlg(null_str, message, did_first_drawn, hidden_ms, null_str, _rect, did_draw_bar);
	}

	twindow& window = *connected.back();

	const int default_width = gui2::settings::screen_width * 80 / 100; // 80%
	const int default_height = 48 * twidget::hdpi_scale;
	SDL_Rect rect = _rect;
	if (rect.w == nposm) {
		rect.w = default_width;
	}
	if (rect.h == nposm) {
		rect.h = default_height;
	}
	if (rect.x == nposm) {
		rect.x = (gui2::settings::screen_width - rect.w) / 2;
	}
	if (rect.y == nposm) {
		rect.y = (gui2::settings::screen_height - rect.h) / 2;
	}

	gui2::tprogress_widget dlg(window, clear_event, message, did_first_drawn, hidden_ms, rect, did_draw_bar);
	return did_first_drawn(dlg);
}

} // namespace gui2

