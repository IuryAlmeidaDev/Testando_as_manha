#include "MainFrame.h"
#include <wx/event.h>
#include <sstream>

wxBEGIN_EVENT_TABLE(MainFrame, wxFrame)
    EVT_BUTTON(1001, MainFrame::onRefreshProcesses)
    EVT_COMBOBOX(1002, MainFrame::onProcessSelected)
    EVT_BUTTON(1003, MainFrame::onScan)
    EVT_BUTTON(1004, MainFrame::onResetScan)
    EVT_BUTTON(1005, MainFrame::onWriteValue)
wxEND_EVENT_TABLE()

MainFrame::MainFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(800, 600)),
      m_memoryEngine(nullptr), m_initialScanDone(false) {
    
    SetMinSize(wxSize(700, 500));
    createControls();
    populateProcessList();
}

MainFrame::~MainFrame() {
    delete m_memoryEngine;
}

void MainFrame::createControls() {
    wxPanel* panel = new wxPanel(this, wxID_ANY);
    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
    
    wxBoxSizer* procSizer = new wxBoxSizer(wxHORIZONTAL);
    procSizer->Add(new wxStaticText(panel, wxID_ANY, "Process:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_processCombo = new wxComboBox(panel, 1002, "", wxDefaultPosition, wxSize(350, -1));
    m_refreshBtn = new wxButton(panel, 1001, "Refresh");
    procSizer->Add(m_processCombo, 0, wxRIGHT, 5);
    procSizer->Add(m_refreshBtn, 0);
    mainSizer->Add(procSizer, 0, wxEXPAND | wxALL, 10);
    
    wxBoxSizer* searchSizer = new wxBoxSizer(wxHORIZONTAL);
    searchSizer->Add(new wxStaticText(panel, wxID_ANY, "Value:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_searchValue = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(150, -1));
    
    wxArrayString types;
    types.Add("int8");
    types.Add("int16");
    types.Add("int32");
    types.Add("int64");
    types.Add("float");
    types.Add("double");
    types.Add("byte");
    types.Add("string");
    m_dataType = new wxComboBox(panel, wxID_ANY, "int32", wxDefaultPosition, wxSize(100, -1), types);
    m_dataType->SetSelection(2);
    
    wxArrayString filters;
    filters.Add("Exact");
    filters.Add("Increased");
    filters.Add("Decreased");
    filters.Add("Unchanged");
    m_scanFilter = new wxComboBox(panel, wxID_ANY, "Exact", wxDefaultPosition, wxSize(100, -1), filters);
    
    m_scanBtn = new wxButton(panel, 1003, "First Scan");
    m_resetBtn = new wxButton(panel, 1004, "Reset");
    
    searchSizer->Add(m_searchValue, 0, wxRIGHT, 5);
    searchSizer->Add(new wxStaticText(panel, wxID_ANY, "Type:"), 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT, 5);
    searchSizer->Add(m_dataType, 0, wxRIGHT, 5);
    searchSizer->Add(new wxStaticText(panel, wxID_ANY, "Filter:"), 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT, 5);
    searchSizer->Add(m_scanFilter, 0, wxRIGHT, 5);
    searchSizer->Add(m_scanBtn, 0, wxRIGHT, 5);
    searchSizer->Add(m_resetBtn, 0);
    mainSizer->Add(searchSizer, 0, wxEXPAND | wxALL, 10);
    
    m_resultsList = new wxListView(panel, wxID_ANY, wxDefaultPosition, wxDefaultSize, 
        wxLC_REPORT | wxLC_SINGLE_SEL);
    m_resultsList->InsertColumn(0, "Address", 0, 150);
    m_resultsList->InsertColumn(1, "Value", 0, 200);
    m_resultsList->InsertColumn(2, "Type", 0, 100);
    mainSizer->Add(m_resultsList, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);
    
    wxBoxSizer* writeSizer = new wxBoxSizer(wxHORIZONTAL);
    writeSizer->Add(new wxStaticText(panel, wxID_ANY, "New Value:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_writeValue = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(150, -1));
    m_writeBtn = new wxButton(panel, 1005, "Write to Selected");
    writeSizer->Add(m_writeValue, 0, wxRIGHT, 5);
    writeSizer->Add(m_writeBtn, 0);
    mainSizer->Add(writeSizer, 0, wxEXPAND | wxALL, 10);
    
    m_statusText = new wxStaticText(panel, wxID_ANY, "Select a process to begin");
    mainSizer->Add(m_statusText, 0, wxEXPAND | wxALL, 10);
    
    panel->SetSizer(mainSizer);
}

void MainFrame::populateProcessList() {
    m_processCombo->Clear();
    auto processes = m_processManager.getProcessList();
    
    for (const auto& proc : processes) {
        std::ostringstream oss;
        oss << proc.pid << " - " << proc.name << " (" << (proc.is64Bit ? "x64" : "x86") << ")";
        m_processCombo->Append(oss.str());
    }
}

void MainFrame::onRefreshProcesses(wxCommandEvent& event) {
    populateProcessList();
    m_statusText->SetLabel("Process list refreshed");
}

void MainFrame::onProcessSelected(wxCommandEvent& event) {
    int selection = m_processCombo->GetSelection();
    if (selection == wxNOT_FOUND) return;
    
    auto processes = m_processManager.getProcessList();
    if (selection >= (int)processes.size()) return;
    
    DWORD pid = processes[selection].pid;
    
    if (m_processManager.openProcess(pid)) {
        delete m_memoryEngine;
        m_memoryEngine = new MemoryEngine(m_processManager.getHandle(), m_processManager.is64Bit());
        m_initialScanDone = false;
        m_results.clear();
        m_resultsList->DeleteAllItems();
        m_scanBtn->SetLabel("First Scan");
        m_statusText->SetLabel("Process opened: " + processes[selection].name);
    } else {
        m_statusText->SetLabel("Failed to open process. Try running as administrator.");
    }
}

DataType MainFrame::getSelectedDataType() {
    switch (m_dataType->GetSelection()) {
        case 0: return DataType::INT8;
        case 1: return DataType::INT16;
        case 2: return DataType::INT32;
        case 3: return DataType::INT64;
        case 4: return DataType::FLOAT;
        case 5: return DataType::DOUBLE;
        case 6: return DataType::BYTE;
        case 7: return DataType::STRING;
        default: return DataType::INT32;
    }
}

ScanFilter MainFrame::getSelectedFilter() {
    switch (m_scanFilter->GetSelection()) {
        case 0: return ScanFilter::EXACT;
        case 1: return ScanFilter::INCREASED;
        case 2: return ScanFilter::DECREASED;
        case 3: return ScanFilter::UNCHANGED;
        default: return ScanFilter::EXACT;
    }
}

void MainFrame::onScan(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        m_statusText->SetLabel("Please select a process first");
        return;
    }
    
    wxString value = m_searchValue->GetValue();
    if (value.IsEmpty()) {
        m_statusText->SetLabel("Please enter a value to search");
        return;
    }
    
    DataType type = getSelectedDataType();
    
    if (!m_initialScanDone) {
        m_results = m_memoryEngine->initialScan(type, value.ToStdString());
        m_initialScanDone = true;
        m_scanBtn->SetLabel("Next Scan");
    } else {
        ScanFilter filter = getSelectedFilter();
        m_results = m_memoryEngine->nextScan(filter, value.ToStdString());
    }
    
    updateResultsList();
}

void MainFrame::onResetScan(wxCommandEvent& event) {
    if (m_memoryEngine) {
        m_memoryEngine->clearResults();
    }
    m_initialScanDone = false;
    m_results.clear();
    m_resultsList->DeleteAllItems();
    m_scanBtn->SetLabel("First Scan");
    m_statusText->SetLabel("Scan reset");
}

void MainFrame::onWriteValue(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        m_statusText->SetLabel("No process selected");
        return;
    }
    
    int selected = m_resultsList->GetFirstSelected();
    if (selected == -1) {
        m_statusText->SetLabel("Please select an address from results");
        return;
    }
    
    wxString value = m_writeValue->GetValue();
    if (value.IsEmpty()) {
        m_statusText->SetLabel("Please enter a value to write");
        return;
    }
    
    if (selected >= (int)m_results.size()) {
        return;
    }
    
    auto& result = m_results[selected];
    if (m_memoryEngine->writeMemory(result.address, result.type, value.ToStdString())) {
        std::ostringstream oss;
        oss << "Written " << value.ToStdString() << " to 0x" << std::hex << result.address;
        m_statusText->SetLabel(oss.str());
        
        wxCommandEvent e;
        onScan(e);
    } else {
        m_statusText->SetLabel("Failed to write memory. Try running as administrator.");
    }
}

void MainFrame::updateResultsList() {
    m_resultsList->DeleteAllItems();
    
    for (size_t i = 0; i < m_results.size(); i++) {
        const auto& result = m_results[i];
        std::ostringstream addr;
        addr << "0x" << std::hex << result.address;
        
        m_resultsList->InsertItem(i, addr.str());
        m_resultsList->SetItem(i, 1, result.getValueString());
        m_resultsList->SetItem(i, 2, result.getTypeString());
    }
    
    std::ostringstream status;
    status << "Found " << m_results.size() << " addresses";
    m_statusText->SetLabel(status.str());
}
