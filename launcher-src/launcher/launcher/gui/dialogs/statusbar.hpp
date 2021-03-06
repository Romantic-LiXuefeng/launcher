#ifndef GUI_DIALOGS_STATUSBAR_HPP_INCLUDED
#define GUI_DIALOGS_STATUSBAR_HPP_INCLUDED

#include "rdp_server_rose.h"
#include "gui/dialogs/dialog.hpp"
#include "gui/widgets/timer.hpp"

namespace gui2 {

class tlabel;
class timage;
class tgrid;

class tstatusbar
{
public:
	// enum {MSG_UPDATE_APP = tdialog::POST_MSG_MIN_APP, POST_MSG_BASECLASS};

	explicit tstatusbar(net::trdpd_manager& rdpd_mgr);

	void pre_show(twindow& window, tgrid& statusbar_widget);

protected:
	void refresh_statusbar_grid();

protected:
	net::trdpd_manager& rdpd_mgr_;

	tgrid* statusbar_widget_;
	timage* client_widget_;
	tlabel* client_ip_widget_;
	tlabel* time_widget_;

private:
	twindow* window_priv_;
};

} // namespace gui2

#endif

