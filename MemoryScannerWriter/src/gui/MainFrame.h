#pragma once
#include <wx/wx.h>
#include <wx/choice.h>
#include <wx/textctrl.h>
#include <wx/listctrl.h>
#include <wx/button.h>
#include <wx/combobox.h>
#include "../engine/ProcessManager.h"
#include "../engine/MemoryEngine.h"
#include "../models/ScanResult.h"

class MainFrame : public wxFrame {
public:
    MainFrame(const wxString& title);
    ~MainFrame();

private:
    void createControls();
    void populateProcessList();
    void onRefreshProcesses(wxCommandEvent& event);
    void onProcessSelected(wxCommandEvent& event);
    void onScan(wxCommandEvent& event);
    void onResetScan(wxCommandEvent& event);
    void onWriteValue(wxCommandEvent& event);
    void updateResultsList();
    DataType getSelectedDataType();
    ScanFilter getSelectedFilter();
    
    wxComboBox* m_processCombo;
    wxButton* m_refreshBtn;
    wxTextCtrl* m_searchValue;
    wxComboBox* m_dataType;
    wxComboBox* m_scanFilter;
    wxButton* m_scanBtn;
    wxButton* m_resetBtn;
    wxListView* m_resultsList;
    wxTextCtrl* m_writeValue;
    wxButton* m_writeBtn;
    wxStaticText* m_statusText;
    
    ProcessManager m_processManager;
    MemoryEngine* m_memoryEngine;
    std::vector<ScanResult> m_results;
    bool m_initialScanDone;
    
    wxDECLARE_EVENT_TABLE();
};
