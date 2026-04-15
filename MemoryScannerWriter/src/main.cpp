#include <wx/wx.h>
#include "gui/MainFrame.h"

class App : public wxApp {
public:
    bool OnInit() override {
        MainFrame* frame = new MainFrame("Memory Scanner & Writer");
        frame->Show(true);
        return true;
    }
};

wxIMPLEMENT_APP(App);
