/* $Id$ */
/*
   Copyright (C) 2011 by Sergey Popov <loonycyborg@gmail.com>
   Part of the Battle for Wesnoth Project http://www.wesnoth.org/

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY.

   See the COPYING file for more details.
*/

#ifndef GUI_DIALOGS_PROGRESS_HPP_INCLUDED
#define GUI_DIALOGS_PROGRESS_HPP_INCLUDED

#include "gui/dialogs/dialog.hpp"
#include "gui/widgets/progress_bar.hpp"

namespace gui2 {

class tbutton;

/**
 * Dialog that tracks network transmissions
 *
 * It shows upload/download progress and allows the user
 * to cancel the transmission.
 */
class tprogress : public tdialog, public tprogress_
{
public:
	tprogress(const std::string& title, const std::string& message, const boost::function<bool (tprogress_&)>& did_first_drawn, int hidden_ms, const std::string& cancel_img, int best_width, int best_height, const boost::function<void (ttrack&, const SDL_Rect&, int, const std::string&)>& did_draw_bar);
	~tprogress();

	void set_percentage(const int percentage) override;
	void set_message(const std::string& message) override;
	void set_align(int align) override;
	void cancel_task() override;
	bool task_cancelled() const override { return require_cancel_; }
	void show_slice() override;
	bool is_visible() const override;
	bool is_new_window() const override { return true; }

protected:
	/** Inherited from tdialog. */
	void pre_show() override;

	/** Inherited from tdialog. */
	void post_show() override;

	/** Inherited from tdialog, implemented by REGISTER_DIALOG. */
	virtual const std::string& window_id() const;

	void click_cancel();

private:
	void app_first_drawn() override;
	void timer_handler(bool render_track);

private:
	// The title for the dialog.
	const std::string title_;
	const std::string message_;
	const boost::function<bool (tprogress_&)> did_first_drawn_;
	Uint32 hidden_ticks_;
	const std::string cancel_img_;
	const boost::function<void (ttrack&, const SDL_Rect&, int, const std::string&)> did_draw_bar_;

	std::unique_ptr<tprogress_bar> progress_;
	
	Uint32 start_ticks_;
	bool require_cancel_;
	const int track_best_width_;
	const int track_best_height_;
};


class tprogress_widget: public tprogress_
{
public:
	tprogress_widget(twindow& window, bool clear_event, const std::string& message, const boost::function<bool (tprogress_&)>& did_first_drawn, int hidden_ms, const SDL_Rect& rect, const boost::function<void (ttrack&, const SDL_Rect&, int, const std::string&)>& did_draw_bar);
	~tprogress_widget();

	void set_percentage(const int percentage) override;
	void set_message(const std::string& message) override;
	void set_align(int align) override;
	void cancel_task() override {}
	bool task_cancelled() const override { return false; }
	void show_slice() override;
	bool is_visible() const override;
	bool is_new_window() const override { return false; }

private:
	void pre_show();
	void set_visible();

private:
	void timer_handler(bool render_track);

private:
	twindow& window_;
	tfloat_widget& float_track_;
	const std::string message_;
	const boost::function<bool (tprogress_&)> did_first_drawn_;
	uint32_t hidden_ticks_;
	bool clear_event_;
	const boost::function<void (ttrack&, const SDL_Rect&, int, const std::string&)> did_draw_bar_;

	std::unique_ptr<tprogress_bar> progress_;
	
	Uint32 start_ticks_;
	const SDL_Rect track_rect_;
};

} // namespace gui2

#endif

