#ifndef GUI_DIALOGS_HOME_HPP_INCLUDED
#define GUI_DIALOGS_HOME_HPP_INCLUDED

#include "gui/dialogs/statusbar.hpp"
#include "gui/dialogs/dialog.hpp"

namespace gui2 {

class tbutton;

class thome: public tdialog, public tstatusbar
{
public:
	enum tresult {EXPLORER = 1};

	explicit thome(net::trdpd_manager& rdpd_mgr);

private:
	/** Inherited from tdialog. */
	void pre_show() override;

	/** Inherited from tdialog. */
	void post_show() override;

	/** Inherited from tdialog, implemented by REGISTER_DIALOG. */
	virtual const std::string& window_id() const;

	void app_timer_handler(uint32_t now) override;

	void click_aismart();
	void click_explorer();
	void click_suppress_threshold(tbutton& widget);

private:
	uint32_t start_ticks_;
};

} // namespace gui2

#endif

