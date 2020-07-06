/* $Id: campaign_difficulty.cpp 49602 2011-05-22 17:56:13Z mordante $ */
/*
   Copyright (C) 2010 - 2011 by Ignacio Riquelme Morelle <shadowm2006@gmail.com>
   Part of the Battle for Wesnoth Project http://www.wesnoth.org/

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY.

   See the COPYING file for more details.
*/

#define GETTEXT_DOMAIN "launcher-lib"

#include "gui/dialogs/explorer.hpp"

#include "formula_string_utils.hpp"
#include "gettext.hpp"
#include "filesystem.hpp"
#include "rose_config.hpp"
// #include "game_config.hpp"

#include "gui/dialogs/helper.hpp"
#include "gui/widgets/settings.hpp"
#include "gui/widgets/window.hpp"
#include "gui/widgets/label.hpp"
#include "gui/widgets/button.hpp"
#include "gui/widgets/toggle_button.hpp"
#include "gui/widgets/toggle_panel.hpp"
#include "gui/widgets/listbox.hpp"
#include "gui/widgets/report.hpp"
#include "gui/widgets/text_box.hpp"
#include "gui/dialogs/combo_box.hpp"
#include "gui/dialogs/message.hpp"
#include "gui/dialogs/menu.hpp"
#include "gui/dialogs/edit_box.hpp"

// std::tolower
#include <cctype>

namespace gui2 {

REGISTER_DIALOG(launcher, explorer)

const char texplorer::path_delim = '/';
const std::string texplorer::path_delim_str = "/";

texplorer::tfile2::tfile2(const std::string& name)
	: name(name)
	, method(texplorer::METHOD_ALPHA)
{
	lower = utils::lowercase(name);
}
bool texplorer::tfile2::operator<(const texplorer::tfile2& that) const 
{
	return lower < that.lower; 
}


texplorer::texplorer(net::trdpd_manager& rdpd_mgr, const std::string& initial, const tentry& extra, bool only_extra_entry)
	: tstatusbar(rdpd_mgr)
	, initial_(initial)
	, extra_(extra)
	, only_extra_entry_(only_extra_entry)
	, navigate_(nullptr)
	, goto_higher_(nullptr)
	, file_list_(nullptr)
	, filename_(nullptr)
	, summary_(nullptr)
	, current_dir_(get_path(initial))
	, auto_select_(false)
{
	set_timer_interval(1000);

	if (extra_.valid()) {
		extra_.path = get_path(extra_.path);
		VALIDATE(SDL_IsDirectory(extra_.path.c_str()), null_str);
	}
	if (only_extra_entry_) {
		VALIDATE(extra_.valid(), null_str);
	}
	if (!is_directory(current_dir_)) {
		if (!only_extra_entry_) {
			current_dir_ = get_path(game_config::preferences_dir);
		} else {
			current_dir_ = extra_.path;
		}
	}
}

void texplorer::pre_show()
{
	window_->set_label("misc/white-background.png");

	tstatusbar::pre_show(*window_, find_widget<tpanel>(window_, "statusbar_panel", false).grid());

	find_widget<tbutton>(window_, "cancel", false).set_icon("misc/back.png");

	tbutton* button = find_widget<tbutton>(window_, "multiselect", false, true);
	button->set_icon("misc/multiselect.png");
	connect_signal_mouse_left_click(
			  *button
			, boost::bind(
				&texplorer::click_multiselect
				, this
				, boost::ref(*button)));

	button = find_widget<tbutton>(window_, "edit", false, true);
	button->set_icon("misc/edit.png");
	connect_signal_mouse_left_click(
			  *button
			, boost::bind(
				&texplorer::click_edit
				, this
				, boost::ref(*button)));

	button = find_widget<tbutton>(window_, "new_floder", false, true);
	button->set_icon("misc/new-folder.png");
	connect_signal_mouse_left_click(
			  *button
			, boost::bind(
				&texplorer::click_new_folder
				, this
				, boost::ref(*button)));

	filename_ = find_widget<ttext_box>(window_, "filename", false, true);
	summary_  = find_widget<tlabel>(window_, "summary", false, true);

	goto_higher_ = find_widget<tbutton>(window_, "goto-higher", false, true);
	connect_signal_mouse_left_click(
			  *goto_higher_
			, boost::bind(
				&texplorer::goto_higher
				, this));

	find_widget<tpanel>(window_, "navigate_panel", false, true)->set_border("textbox");

	navigate_ = find_widget<treport>(window_, "navigate", false, true);
	navigate_->set_did_item_click(boost::bind(&texplorer::click_navigate, this, boost::ref(*window_), _2));


	filename_->set_active(false);
	filename_->set_did_text_changed(boost::bind(&texplorer::text_changed_callback, this, _1));

	tlistbox& list = find_widget<tlistbox>(window_, "default", false);
	// if (!game_config::mobile) {
		list.set_did_row_double_click(boost::bind(&texplorer::did_item_double_click, this, _1, _2));
	// }
	list.set_did_row_changed(boost::bind(&texplorer::did_item_selected, this, _1, _2));
	window_->keyboard_capture(&list);
	file_list_ = &list;

	init_entry(*window_);
}

void texplorer::post_show()
{
}

std::string texplorer::calculate_result() const
{
	const std::string& label = filename_->label();
	if (current_dir_ != path_delim_str) {
		return current_dir_ + path_delim + label;
	} else {
		return current_dir_ + label;
	}
}

void texplorer::init_entry(twindow& window)
{
	if (!only_extra_entry_) {
		entries_.push_back(tentry(game_config::preferences_dir, _("UserData"), "misc/documents.png"));
		if (game_config::os == os_windows) {
			entries_.push_back(tentry("c:", _("C:"), "misc/disk.png"));
		} else {
			entries_.push_back(tentry("/", _("Device"), "misc/disk.png"));
		}
		if (game_config::os != os_android) {
			entries_.push_back(tentry(game_config::path, _("Sandbox"), "misc/dir-res.png"));
		}
	}
	if (extra_.valid()) {
		entries_.push_back(extra_);
	}
	VALIDATE(!entries_.empty(), null_str);

	tlistbox& root = find_widget<tlistbox>(&window, "root", false);
	root.enable_select(false);

	std::map<std::string, std::string> data;
	for (std::vector<tentry>::const_iterator it = entries_.begin(); it != entries_.end(); ++ it) {
		const tentry& entry = *it;
		data.clear();
		data.insert(std::make_pair("label", entry.label));
		ttoggle_panel& row = root.insert_row(data);
		row.set_child_icon("label", entry.icon);
	}
	root.set_did_row_changed(boost::bind(&texplorer::did_root_changed, this, _1, _2));

	did_root_changed(root, root.row_panel(0));
}

void texplorer::reload_navigate()
{
	VALIDATE(!current_dir_.empty(), null_str);

	std::vector<std::string> ids;

	if (current_dir_ != path_delim_str) {
		ids = utils::split(current_dir_, path_delim);

		if (current_dir_.at(0) == path_delim) {
			// it is prefix by '/'.
			ids.insert(ids.begin(), path_delim_str);
		}

	} else {
		ids.push_back(path_delim_str);
	}

	int childs = navigate_->items();
	while (childs > (int)ids.size()) {
		// require reverse erase.
		navigate_->erase_item(nposm);
		childs = navigate_->items();
	}
	
	cookie_paths_.clear();

	int n = 0;
	for (std::vector<std::string>::const_iterator it = ids.begin(); it != ids.end(); ++ it, n ++) {
		const std::string& label = *it;
		if (n < childs) {
			gui2::tbutton* widget = dynamic_cast<tbutton*>(&navigate_->item(n));
			VALIDATE(widget->label() == label, null_str);

		} else {
			// password_char_(UCS2_to_UTF8(0x25b6)), 0x25ba
			navigate_->insert_item(null_str, label);
		}
		if (!cookie_paths_.empty()) {
			if (cookie_paths_.back() != path_delim_str) {
				cookie_paths_.push_back(cookie_paths_.back() + path_delim_str + label);
			} else {
				cookie_paths_.push_back(cookie_paths_.back() + label);
			}
		} else {
			cookie_paths_.push_back(label);
		}
	}

	goto_higher_->set_active(ids.size() >= 2);
}

void texplorer::click_navigate(twindow& window, tbutton& widget)
{
	if (only_extra_entry_ && cookie_paths_[widget.at()].size() < extra_.path.size()) {
		return;
	}
	current_dir_ = cookie_paths_[widget.at()];
	update_file_lists();

	reload_navigate();
}

void texplorer::did_root_changed(tlistbox& list, ttoggle_panel& widget)
{
	// reset navigate
	navigate_->clear();

	current_dir_ = entries_[widget.at()].path;
	update_file_lists();

	reload_navigate();
}

static const std::string& get_browse_icon(bool dir)
{
	static const std::string dir_icon = "misc/folder.png";
	static const std::string file_icon = "misc/file.png";
	return dir? dir_icon: file_icon;
}

void texplorer::add_row(twindow& window, tlistbox& list, const std::string& name, bool dir)
{
	std::map<std::string, std::string> list_item_item;

	list_item_item.insert(std::make_pair("name", name));

	list_item_item.insert(std::make_pair("date", "---"));

	list_item_item.insert(std::make_pair("size", dir? null_str: "---"));

	ttoggle_panel& row = list.insert_row(list_item_item);
	row.set_child_icon("name", get_browse_icon(dir));

	if (dir) {
		row.connect_signal<event::LONGPRESS>(
			boost::bind(
				&texplorer::signal_handler_longpress_item
				, this
				, _4, _5, boost::ref(row))
				, event::tdispatcher::back_child);
		row.connect_signal<event::LONGPRESS>(
			boost::bind(
				&texplorer::signal_handler_longpress_item
				, this
				, _4, _5, boost::ref(row))
				, event::tdispatcher::back_post_child);
	}
}

void texplorer::click_directory(ttoggle_panel& row)
{
	std::vector<gui2::tmenu::titem> items;
	std::string message;

	enum {select};
	
	items.push_back(gui2::tmenu::titem(_("Select"), select, "misc/select.png"));

	int selected;
	{
		int x, y;
		SDL_GetMouseState(&x, &y);
		gui2::tmenu dlg(items, nposm);
		dlg.show(x, y + 16 * twidget::hdpi_scale);
		int retval = dlg.get_retval();
		if (dlg.get_retval() != gui2::twindow::OK) {
			return;
		}
		selected = dlg.selected_val();
	}
	if (selected == select) {
		tlistbox* list = find_widget<tlistbox>(window_, "default", false, true);
		tauto_select_lock lock(*this);
		list->select_row(row.at());
	}
}

void texplorer::signal_handler_longpress_item(bool& halt, const tpoint& coordinate, ttoggle_panel& row)
{
	halt = true;

	// network maybe disconnect except.
	rtc::Thread::Current()->Post(RTC_FROM_HERE, this, texplorer::MSG_POPUP_DIRECTORY, reinterpret_cast<rtc::MessageData*>(&row));
}

void texplorer::app_OnMessage(rtc::Message* msg)
{
	ttoggle_panel* row = nullptr;
	switch (msg->message_id) {
	case MSG_POPUP_DIRECTORY:
		row = reinterpret_cast<ttoggle_panel*>(msg->pdata);
		click_directory(*row);
		break;

	case MSG_OPEN_DIRECTORY:
		row = reinterpret_cast<ttoggle_panel*>(msg->pdata);
		open(*window_, row->at());
		break;
	}
}

void texplorer::reload_file_table(int cursel)
{
	tlistbox* list = find_widget<tlistbox>(window_, "default", false, true);
	list->clear();

	int size = int(dirs_in_current_dir_.size() + files_in_current_dir_.size());
	for (std::set<tfile2>::const_iterator it = dirs_in_current_dir_.begin(); it != dirs_in_current_dir_.end(); ++ it) {
		const tfile2& file = *it;
		add_row(*window_, *list, file.name, true);

	}
	for (std::set<tfile2>::const_iterator it = files_in_current_dir_.begin(); it != files_in_current_dir_.end(); ++ it) {
		const tfile2& file = *it;
		add_row(*window_, *list, file.name, false);
	}
	if (size) {
		if (cursel >= size) {
			cursel = size - 1;
		}
		// tauto_select_lock lock(*this);
		// list->select_row(cursel);
	}
	set_filename(null_str);
	set_summary_label();
}

void texplorer::update_file_lists()
{
	canel_multiselect();
	files_in_current_dir_.clear();
	dirs_in_current_dir_.clear();

	std::vector<std::string> files, dirs;
	get_files_in_dir(current_dir_, &files, &dirs);

	// files and dirs of get_files_in_dir returned are unicode16 format
	for (std::vector<std::string>::const_iterator it = files.begin(); it != files.end(); ++ it) {
		const std::string& str = *it;
		files_in_current_dir_.insert(tfile2(str));
	}
	for (std::vector<std::string>::const_iterator it = dirs.begin(); it != dirs.end(); ++ it) {
		const std::string& str = *it;
		dirs_in_current_dir_.insert(tfile2(str));
	}

	reload_file_table(0);
}

void texplorer::open(twindow& window, const int at)
{
	std::set<tfile2>::const_iterator it = dirs_in_current_dir_.begin();
	std::advance(it, at);

	if (current_dir_ != path_delim_str) {
		current_dir_ = current_dir_ + path_delim + it->name;
	} else {
		current_dir_ = current_dir_ + it->name;
	}
	update_file_lists();

	reload_navigate();
}

void texplorer::goto_higher()
{
	if (only_extra_entry_ && current_dir_ == extra_.path) {
		return;
	}

	VALIDATE(cookie_paths_.size() >= 2, null_str);
	SDL_Log("goto_higher, cookie_paths_.back: %s, current_dir_: %s", cookie_paths_.back().c_str(), current_dir_.c_str());

	VALIDATE(cookie_paths_.back() == current_dir_, null_str);

	current_dir_ = cookie_paths_[cookie_paths_.size() - 2];
	update_file_lists();

	reload_navigate();
}

std::string texplorer::get_path(const std::string& file_or_dir) const 
{
	std::string res_path = utils::normalize_path(file_or_dir);

	// get rid of all path_delim at end.
	size_t s = res_path.size();
	while (s > 1 && res_path.at(s - 1) == path_delim) {
		res_path.erase(s - 1);
		s = res_path.size();
	}

	if (!::is_directory(res_path)) {
		size_t index = file_or_dir.find_last_of(path_delim);
		if (index != std::string::npos) {
			res_path = res_path.substr(0, index);
		}
	}
	return res_path;
}

void texplorer::did_item_selected(tlistbox& list, ttoggle_panel& widget)
{
	bool dir = false;

	std::set<tfile2>::const_iterator it;
	int row = widget.at();
	if (row < (int)dirs_in_current_dir_.size()) {
		dir = true;
		it = dirs_in_current_dir_.begin();
/*
		if (game_config::mobile && !auto_select_) {
			rtc::Thread::Current()->Post(RTC_FROM_HERE, this, texplorer::MSG_OPEN_DIRECTORY, reinterpret_cast<rtc::MessageData*>(&widget));
			return;
		}
*/
	} else {
		it = files_in_current_dir_.begin();
		row -= dirs_in_current_dir_.size();
	}
	std::advance(it, row);

	set_filename(it->name);
}

std::string texplorer::selected_full_name(int* type_ptr)
{
	ttoggle_panel* cursel = file_list_->cursel();
	VALIDATE(cursel != nullptr, null_str);

	bool dir = false;

	std::set<tfile2>::const_iterator it;
	int row = cursel->at();
	if (row < (int)dirs_in_current_dir_.size()) {
		dir = true;
		it = dirs_in_current_dir_.begin();

	} else {
		it = files_in_current_dir_.begin();
		row -= dirs_in_current_dir_.size();
	}
	std::advance(it, row);

	const std::string ret = current_dir_ + path_delim + it->name;
	if (type_ptr) {
		*type_ptr = dir? TYPE_DIR: TYPE_FILE;
	}
	return ret;
}

std::vector<std::string> texplorer::selected_full_multinames()
{
	VALIDATE(file_list_->multiselect(), null_str);
	const std::set<int>& rows = file_list_->multiselected_rows();
	VALIDATE(!rows.empty(), null_str);

	std::vector<std::string> ret;
	for (std::set<int>::const_iterator it = rows.begin(); it != rows.end(); ++ it) {
		int row_at = *it;
		// ttoggle_panel& row = file_list_->row_panel(row_at);
		bool dir = false;
		std::set<tfile2>::const_iterator it2;
		if (row_at < (int)dirs_in_current_dir_.size()) {
			dir = true;
			it2 = dirs_in_current_dir_.begin();

		} else {
			it2 = files_in_current_dir_.begin();
			row_at -= dirs_in_current_dir_.size();
		}
		std::advance(it2, row_at);
		ret.push_back(current_dir_ + path_delim + it2->name);
	}
	return ret;
}

void texplorer::did_item_double_click(tlistbox& list, ttoggle_panel& widget)
{
	int row = widget.at();
	if (row >= (int)dirs_in_current_dir_.size()) {
		return;
	}

	open(*window_, row);
}

void texplorer::text_changed_callback(ttext_box& widget)
{
	const std::string& label = widget.label();
	bool active = !label.empty();
	if (active) {
		const std::string path = calculate_result();
		if (SDL_IsFile(path.c_str())) {
			active = false;

		} else if (SDL_IsDirectory(path.c_str())) {
			active = false;
		}
		if (active && did_result_changed_) {
			active = did_result_changed_(calculate_result(), label);
		}
	}
}

void texplorer::set_filename(const std::string& label)
{
	filename_->set_label(label);
}

void texplorer::set_summary_label()
{
	utils::string_map symbols;
	symbols["items"] = str_cast(files_in_current_dir_.size() + dirs_in_current_dir_.size());

	summary_->set_label(vgettext2("$items items", symbols));
}

void texplorer::click_multiselect(tbutton& widget)
{
	click_multiselect_internal(widget);
}

void texplorer::click_multiselect_internal(tbutton& widget)
{	
	bool cur_multiselect = file_list_->multiselect();
	if (cur_multiselect) {
		// will cancel multiselect
		file_list_->enable_multiselect(false);
		file_list_->enable_select(true);

	} else {
		// will execult multiselect
		file_list_->enable_select(false);
		file_list_->enable_multiselect(true);
	}

	widget.set_icon(file_list_->multiselect()? "misc/multiselect-selected.png": "misc/multiselect.png");
}

bool texplorer::verify_edit_item(const std::string& label, const std::string& def, int type) const
{
	if (label.empty()) {
		return false;
	}
	if (label == def) {
		return false;
	}
	if (type == edittype_newfolder) {
		if (!utils::isvalid_filename(label)) {
			return false;
		}
		const tfile2 file2(label);
		if (dirs_in_current_dir_.count(file2) != 0) {
			return false;
		}
		if (files_in_current_dir_.count(file2) != 0) {
			return false;
		}
	}
	return true;
}

void texplorer::handle_edit_item(int type)
{
	VALIDATE(type >= 0 && type < edittype_count, null_str);
	utils::string_map symbols;
	std::string title;
	std::string prefix;
	std::string placeholder;
	std::string def;
	std::string remark;
	std::string reset;
	size_t max_chars = 0;
	std::string result;
	int cancel_seconds = 0; // always show
	{
		// tpaper_keyboard_focus_lock keyboard_focus_lock(*this);
		if (type == edittype_newfolder) {
			title = _("Input floder name");
			placeholder = null_str;
			def = null_str;
			max_chars = 20;

		} else {
			VALIDATE(false, null_str);
		}
		VALIDATE(max_chars > 0, null_str);
		gui2::tedit_box_param param(title, prefix, placeholder, def, remark, reset, _("OK"), max_chars, gui2::tedit_box_param::show_cancel + cancel_seconds);
		param.did_text_changed = boost::bind(&texplorer::verify_edit_item, this, _1, def, type);
		{
			gui2::tedit_box dlg(param);
			dlg.show(nposm, window_->get_height() / 4);
			if (dlg.get_retval() != twindow::OK) {
				return;
			}
		}
		result = param.result;
	}

	if (type == edittype_newfolder) {
		const std::string dir = current_dir_ + path_delim + result;
		SDL_bool ret = SDL_MakeDirectory(dir.c_str());
		if (!ret) {
			symbols["folder"] = result;
			gui2::show_message(null_str, vgettext2("Create $folder fail", symbols));
		}
		update_file_lists();

	} else {
		VALIDATE(false, null_str);
	}
}

void texplorer::click_new_folder(tbutton& widget)
{
	handle_edit_item(edittype_newfolder);
}

void texplorer::canel_multiselect()
{
	if (file_list_->multiselect()) {
		click_multiselect_internal(*find_widget<tbutton>(window_, "multiselect", false, true));
	}
}

void texplorer::click_edit(tbutton& widget)
{
	bool has_handshaked_connection = false;
	if (rdpd_mgr_.started()) {
		net::RdpServer& server = rdpd_mgr_.rdp_server();
		has_handshaked_connection = server.FindFirstHandshakedConnection() != nullptr;
	}
	if (!has_handshaked_connection) {
		gui2::show_message(null_str, _("No client, cannot copy or paste"));
		return;
	}

	enum {copy, cut, paste};

	std::vector<gui2::tmenu::titem> items;
	
	if (file_list_->cursel() != nullptr || !file_list_->multiselected_rows().empty()) {
		items.push_back(gui2::tmenu::titem(_("Copy"), copy));
		// items.push_back(gui2::tmenu::titem(_("Cut"), cut));
	}
	if (rdpd_mgr_.can_hdrop_paste()) {
		// paste
		items.push_back(gui2::tmenu::titem(_("Paste"), paste));
	}

	if (items.empty()) {
		gui2::show_message(null_str, _("Copy require select item. Paste require client copy item"));
		return;
	}

	int selected;
	{
		gui2::tmenu dlg(items, nposm);
		dlg.show(widget.get_x(), widget.get_y() + widget.get_height() + 16 * twidget::hdpi_scale);
		int retval = dlg.get_retval();
		if (dlg.get_retval() != gui2::twindow::OK) {
			return;
		}
		// absolute_draw();
		selected = dlg.selected_val();
	}

	if (selected == copy) {
		std::vector<std::string> files;
		if (file_list_->cursel() != nullptr) {
			files.push_back(selected_full_name(nullptr));
		} else {
			files = selected_full_multinames();
		}
		std::string files_str = utils::join_with_null(files);
		rdpd_mgr_.hdrop_copied(files_str);

	} else if (selected == paste) {
		// gui2::run_with_progress_widget(false, _("Paste"), boost::bind(&net::trdpd_manager::hdrop_paste, &rdpd_mgr_, _1, current_dir_), 0);
		int err_code = errcode_ok;
		char err_msg[512];
		utils::string_map symbols;

		symbols["app"] = "Launcher";
		const std::string title = vgettext2("When pasting, please Must not switch $app to background, otherwise will cause $app to exit illegally", symbols);
		gui2::run_with_progress_dlg(title, _("Paste"), boost::bind(&net::trdpd_manager::hdrop_paste, &rdpd_mgr_, _1, current_dir_, &err_code, err_msg, sizeof(err_msg)), 0, "misc/remove.png");
		if (err_code == errcode_file) {
			symbols["file"] = err_msg;
			gui2::show_message(null_str, vgettext2("Paste $file fail, Cancel paste", symbols));

		} else if (err_code == errcode_directory) {
			symbols["directory"] = err_msg;
			gui2::show_message(null_str, vgettext2("Create $directory fail, Cancel paste", symbols));

		} else if (err_code == errcode_format) {
			gui2::show_message(null_str, vgettext2("Get remote format fail, Cancel paste", symbols));

		} else if (err_code == errcode_clipboardupdate) {
			symbols["file"] = err_msg;
			gui2::show_message(null_str, vgettext2("Paste $file fail, remote clipboard's content was changed. Cancel paste", symbols));

		} else if (err_code == errcode_cancel) {
		}
		update_file_lists();

	} else if (selected == cut) {
		// cut_selection();
	}
}

void texplorer::app_timer_handler(uint32_t now)
{
	refresh_statusbar_grid();
}

}
