/* $Id: handler.hpp 54167 2012-05-13 13:33:24Z mordante $ */
/*
   Copyright (C) 2009 - 2012 by Mark de Wever <koraq@xs4all.nl>
   Part of the Battle for Wesnoth Project http://www.wesnoth.org/

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY.

   See the COPYING file for more details.
*/

#ifndef GUI_WIDGETS_AUXILIARY_EVENT_HANDLER_HPP_INCLUDED
#define GUI_WIDGETS_AUXILIARY_EVENT_HANDLER_HPP_INCLUDED

#define BOOST_MPL_CFG_NO_PREPROCESSED_HEADERS
#define BOOST_MPL_LIMIT_SET_SIZE 30

#include <boost/mpl/set.hpp>

#include <iosfwd>
#include <vector>

namespace gui2 {

class twindow;

namespace event {

class tdispatcher;

class tmanager
{
public:
	tmanager();
	~tmanager();
};

/**
 * The event send to the dispatcher.
 *
 * Events prefixed by SDL are (semi)-real SDL events. The handler does some
 * minor decoding like splitting the button down event to the proper event but
 * nothing more. Events without an SDL prefix are generated by another signal
 * eg the windows signal handler for SDL_MOUSE_MOTION can generate a
 * MOUSE_ENTER, MOUSE_MOTION and MOUSE_LEAVE event and send that to it's
 * children.
 *
 * @note When adding a new entry to the enum also add a unit test.
 */
enum tevent {
	MOUSE_ENTER                 /**< A mouse enter event for a widget. */
	, MOUSE_MOTION                /**< A mouse motion event for a widget. */
	, MOUSE_LEAVE                 /**< A mouse leave event for a widget. */

	, LEFT_BUTTON_DOWN            /**<
	                               * A left mouse button down event for a wiget.
	                               */
	, LEFT_BUTTON_UP              /**<
	                               * A left mouse button up event for a wiget.
	                               */
	, LEFT_BUTTON_CLICK           /**<
	                               * A left mouse button click event for a
	                               * wiget.
	                               */
	, LEFT_BUTTON_DOUBLE_CLICK    /**<
	                               * A left mouse button double click event for
	                               * a wiget.
	                               */
	, MIDDLE_BUTTON_DOWN          /**< See LEFT_BUTTON_DOWN. */
	, MIDDLE_BUTTON_UP            /**< See LEFT_BUTTON_UP. */
	, MIDDLE_BUTTON_CLICK         /**< See LEFT_BUTTON_CLICK. */
	, MIDDLE_BUTTON_DOUBLE_CLICK  /**< See LEFT_BUTTON_DOUBLE_CLICK. */

	, RIGHT_BUTTON_DOWN           /**< See LEFT_BUTTON_DOWN. */
	, RIGHT_BUTTON_UP             /**< See LEFT_BUTTON_UP. */
	, RIGHT_BUTTON_CLICK          /**< See LEFT_BUTTON_CLICK. */
	, RIGHT_BUTTON_DOUBLE_CLICK   /**< See LEFT_BUTTON_DOUBLE_CLICK. */

	, LONGPRESS

	, WHEEL_LEFT              /**< A SDL wheel left event. */
	, WHEEL_RIGHT             /**< A SDL wheel right event. */
	, WHEEL_UP                /**< A SDL wheel up event. */
	, WHEEL_DOWN              /**< A SDL wheel down event. */

	, SDL_KEY_DOWN                /**< A SDL key down event. */
	, SDL_TEXT_INPUT              /**< A SDL text input event. */

	, NOTIFY_REMOVAL              /**<
	                               * Send by a widget to notify others it's
	                               * being destroyed.
	                               */
	, NOTIFY_MODIFIED             /**<
	                               * Send by a widget to notify others its
	                               * contents or state are modified.
	                               *
	                               * What modified means is documented per
	                               * widget. If not documented the modified
	                               * means nothing.
	                               */

	, RECEIVE_KEYBOARD_FOCUS      /**< Widget gets keyboard focus. */
	, LOSE_KEYBOARD_FOCUS         /**< Widget loses keyboard focus. */
	, SHOW_TOOLTIP                /**<
	                               * Request the widget to show its hover
	                               * tooltip.
	                               */
	, NOTIFY_REMOVE_TOOLTIP       /**<
	                               * Request the widget to show its hover
	                               * tooltip.
	                               */

	, MESSAGE_SHOW_TOOLTIP        /**<
	                               * Request for somebody to show the tooltip
	                               * based on the data send.
	                               */
	, OUT_OF_CHAIN
};

/**
 * Helper for catching use error of tdispatcher::connect_signal.
 *
 * This helper is needed as a user can't supply the wrong kind of callback
 * functions to tdispatcher::connect_signal. If a wrong callback would be send
 * it will never get called.
 *
 * This version is for callbacks without extra parameters.
 * NOTE some mouse functions like MOUSE_ENTER don't send the mouse coordinates
 * to the callback function so they are also in this catagory.
 */
typedef
		boost::mpl::set<
			boost::mpl::int_<LEFT_BUTTON_CLICK>
			, boost::mpl::int_<LEFT_BUTTON_DOUBLE_CLICK>
			, boost::mpl::int_<MIDDLE_BUTTON_CLICK>
			, boost::mpl::int_<MIDDLE_BUTTON_DOUBLE_CLICK>
			, boost::mpl::int_<RIGHT_BUTTON_CLICK>
			, boost::mpl::int_<RIGHT_BUTTON_DOUBLE_CLICK>
			, boost::mpl::int_<LOSE_KEYBOARD_FOCUS>
			, boost::mpl::int_<OUT_OF_CHAIN>
		>
		tset_event;

/**
 * Helper for catching use error of tdispatcher::connect_signal.
 *
 * This version is for callbacks with a coordinate as extra parameter.
 */
typedef
		boost::mpl::set<
			  boost::mpl::int_<MOUSE_ENTER>
			, boost::mpl::int_<MOUSE_MOTION>
			, boost::mpl::int_<MOUSE_LEAVE>
			, boost::mpl::int_<LEFT_BUTTON_DOWN>
			, boost::mpl::int_<LEFT_BUTTON_UP>
			, boost::mpl::int_<MIDDLE_BUTTON_DOWN>
			, boost::mpl::int_<MIDDLE_BUTTON_UP>
			, boost::mpl::int_<RIGHT_BUTTON_DOWN>
			, boost::mpl::int_<RIGHT_BUTTON_UP>
			, boost::mpl::int_<LONGPRESS>
			, boost::mpl::int_<SHOW_TOOLTIP>
			, boost::mpl::int_<WHEEL_UP>
			, boost::mpl::int_<WHEEL_DOWN>
			, boost::mpl::int_<WHEEL_LEFT>
			, boost::mpl::int_<WHEEL_RIGHT>
		>
		tset_event_mouse;

/**
 * Helper for catching use error of tdispatcher::connect_signal.
 *
 * This version is for callbacks with the keyboard values (these haven't been
 * determined yet).
 */
typedef
		boost::mpl::set<
			boost::mpl::int_<SDL_KEY_DOWN>
		>
		tset_event_keyboard;

/**
 * Helper for catching use error of tdispatcher::connect_signal.
 *
 * This version is for callbacks with the textinput values (these haven't been
 * determined yet).
 */
typedef
		boost::mpl::set<
			boost::mpl::int_<SDL_TEXT_INPUT>
		>
		tset_event_textinput;

/**
 * Helper for catching use error of tdispatcher::connect_signal.
 *
 * This version is for callbacks with a sender aka notification messages. Like the
 * onces in tset_event it has no extra parameters, but this version is only
 * send to the target and not using the pre and post queue.
 */
typedef
		boost::mpl::set<
			  boost::mpl::int_<NOTIFY_REMOVAL>
			, boost::mpl::int_<NOTIFY_MODIFIED>
			, boost::mpl::int_<RECEIVE_KEYBOARD_FOCUS>
			, boost::mpl::int_<NOTIFY_REMOVE_TOOLTIP>
		>
		tset_event_notification;

/**
 * Helper for catching use error of tdispatcher::connect_signal.
 *
 * This version is for callbacks with a sender aka notification messages.
 * Unlike the notifications this message is send through the chain. The event
 * is send from a widget all the way up to the window, who always is the
 * receiver of the message (unless somebody grabbed it before).
 */
typedef
		boost::mpl::set<
			  boost::mpl::int_<MESSAGE_SHOW_TOOLTIP>
		>
		tset_event_message;

/**
 * Connects a dispatcher to the event handler.
 *
 * @param dispatcher              The dispatcher to connect.
 */
void connect_dispatcher(twindow* dispatcher);

/**
 * Disconnects a dispatcher to the event handler.
 *
 * @param dispatcher              The dispatcher to disconnect.
 */
void disconnect_dispatcher(twindow* dispatcher);


} // namespace event

void absolute_draw();
void absolute_draw_float_widgets();
std::vector<twindow*> connectd_window();
void resize_screen(const int width, const int height, bool top_half);
void pump_timers();

/**
 * Is a dialog open?
 *
 * @note added as backwards compatibility for gui::is_in_dialog.
 */
bool is_in_dialog();

} // namespace gui2

#endif

