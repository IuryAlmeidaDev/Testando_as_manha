#pragma once
#include <wx/wx.h>
#include <wx/choice.h>
#include <wx/textctrl.h>
#include <wx/listctrl.h>
#include <wx/button.h>
#include <wx/combobox.h>
#include <wx/notebook.h>
#include <wx/gauge.h>
#include <wx/panel.h>
#include <wx/frame.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/checkbox.h>
#include <wx/spinctrl.h>
#include "../engine/ProcessManager.h"
#include "../engine/MemoryEngine.h"
#include "../models/ScanResult.h"

class MainFrame : public wxFrame {
public:
    MainFrame(const wxString& title);
    ~MainFrame();

private:
    void createScannerTab(wxPanel* parent);
    void createPointerTab(wxPanel* parent);
    void createDumpTab(wxPanel* parent);
    void createToolsTab(wxPanel* parent);
    void createSettingsTab(wxPanel* parent);
    
    void populateProcessList();
    void updateResultsList();
    void updatePointerResultsList();
    void updateLog(const std::string& message);
    
    void onRefreshProcesses(wxCommandEvent& event);
    void onProcessSelected(wxCommandEvent& event);
    void onFirstScan(wxCommandEvent& event);
    void onNextScan(wxCommandEvent& event);
    void onResetScan(wxCommandEvent& event);
    void onStopScan(wxCommandEvent& event);
    void onAOBScan(wxCommandEvent& event);
    void onPointerScan(wxCommandEvent& event);
    void onDumpMemory(wxCommandEvent& event);
    void onInjectDLL(wxCommandEvent& event);
    void onSaveResults(wxCommandEvent& event);
    void onLoadResults(wxCommandEvent& event);
    void onCopyAddress(wxCommandEvent& event);
    void onWriteValue(wxCommandEvent& event);
    void onPrecisionChanged(wxSpinEvent& event);
    void onHotkey(wxKeyEvent& event);
    
    void onModuleWhitelistAdd(wxCommandEvent& event);
    void onModuleBlacklistAdd(wxCommandEvent& event);
    void onModuleFilterClear(wxCommandEvent& event);
    
    void updateProgress(int percent);
    
    DataType getSelectedDataType();
    ScanFilter getSelectedFilter();
    
    wxNotebook* m_notebook;
    
    wxComboBox* m_processCombo;
    wxButton* m_refreshBtn;
    wxTextCtrl* m_searchValue;
    wxComboBox* m_dataType;
    wxComboBox* m_scanFilter;
    wxButton* m_scanBtn;
    wxButton* m_nextScanBtn;
    wxButton* m_resetBtn;
    wxButton* m_stopBtn;
    wxButton* m_aobScanBtn;
    wxListView* m_resultsList;
    wxTextCtrl* m_writeValue;
    wxButton* m_writeBtn;
    wxButton* m_copyAddrBtn;
    wxButton* m_saveResultsBtn;
    wxButton* m_loadResultsBtn;
    wxStaticText* m_statusText;
    wxGauge* m_progressGauge;
    wxStaticText* m_resultCountText;
    
    wxTextCtrl* m_pointerAddress;
    wxSpinCtrl* m_pointerMaxLevel;
    wxSpinCtrl* m_pointerMaxResults;
    wxButton* m_pointerScanBtn;
    wxListView* m_pointerResultsList;
    
    wxTextCtrl* m_dumpAddress;
    wxTextCtrl* m_dumpSize;
    wxTextCtrl* m_dumpPath;
    wxButton* m_dumpBtn;
    
    wxTextCtrl* m_dllPath;
    wxButton* m_injectDllBtn;
    
    wxListBox* m_whitelistBox;
    wxListBox* m_blacklistBox;
    wxTextCtrl* m_moduleFilterInput;
    
    wxSpinCtrl* m_floatPrecision;
    
    wxTextCtrl* m_logBox;
    
    ProcessManager m_processManager;
    MemoryEngine* m_memoryEngine;
    std::vector<ScanResult> m_results;
    bool m_initialScanDone;
    bool m_aobMode;
    
    wxDECLARE_EVENT_TABLE();
};
