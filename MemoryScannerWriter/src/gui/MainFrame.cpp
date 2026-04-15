#include "MainFrame.h"
#include <wx/event.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <wx/filedlg.h>
#include <wx/msgdlg.h>

wxBEGIN_EVENT_TABLE(MainFrame, wxFrame)
    EVT_COMBOBOX(1001, MainFrame::onProcessSelected)
    EVT_BUTTON(1002, MainFrame::onRefreshProcesses)
    EVT_BUTTON(1003, MainFrame::onFirstScan)
    EVT_BUTTON(1004, MainFrame::onNextScan)
    EVT_BUTTON(1005, MainFrame::onResetScan)
    EVT_BUTTON(1006, MainFrame::onStopScan)
    EVT_BUTTON(1007, MainFrame::onAOBScan)
    EVT_BUTTON(1008, MainFrame::onPointerScan)
    EVT_BUTTON(1009, MainFrame::onDumpMemory)
    EVT_BUTTON(1010, MainFrame::onInjectDLL)
    EVT_BUTTON(1011, MainFrame::onSaveResults)
    EVT_BUTTON(1012, MainFrame::onLoadResults)
    EVT_BUTTON(1013, MainFrame::onCopyAddress)
    EVT_BUTTON(1014, MainFrame::onWriteValue)
    EVT_SPINCTRL(1015, MainFrame::onPrecisionChanged)
    EVT_BUTTON(1016, MainFrame::onModuleWhitelistAdd)
    EVT_BUTTON(1017, MainFrame::onModuleBlacklistAdd)
    EVT_BUTTON(1018, MainFrame::onModuleFilterClear)
wxEND_EVENT_TABLE()

MainFrame::MainFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(1000, 700)),
      m_memoryEngine(nullptr), m_initialScanDone(false), m_aobMode(false) {
    
    SetMinSize(wxSize(900, 600));
    
    wxPanel* mainPanel = new wxPanel(this, wxID_ANY);
    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
    
    m_notebook = new wxNotebook(mainPanel, wxID_ANY);
    
    wxPanel* scannerPanel = new wxPanel(m_notebook, wxID_ANY);
    createScannerTab(scannerPanel);
    m_notebook->AddPage(scannerPanel, "Scanner");
    
    wxPanel* pointerPanel = new wxPanel(m_notebook, wxID_ANY);
    createPointerTab(pointerPanel);
    m_notebook->AddPage(pointerPanel, "Pointer Scan");
    
    wxPanel* dumpPanel = new wxPanel(m_notebook, wxID_ANY);
    createDumpTab(dumpPanel);
    m_notebook->AddPage(dumpPanel, "Memory Dump");
    
    wxPanel* toolsPanel = new wxPanel(m_notebook, wxID_ANY);
    createToolsTab(toolsPanel);
    m_notebook->AddPage(toolsPanel, "Tools");
    
    wxPanel* settingsPanel = new wxPanel(m_notebook, wxID_ANY);
    createSettingsTab(settingsPanel);
    m_notebook->AddPage(settingsPanel, "Settings");
    
    mainSizer->Add(m_notebook, 1, wxEXPAND | wxALL, 5);
    
    m_logBox = new wxTextCtrl(mainPanel, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 80), 
        wxTE_MULTILINE | wxTE_READONLY | wxTE_WORDWRAP);
    mainSizer->Add(m_logBox, 0, wxEXPAND | wxALL, 5);
    
    m_statusText = new wxStaticText(mainPanel, wxID_ANY, "Select a process to begin");
    mainSizer->Add(m_statusText, 0, wxEXPAND | wxALL, 5);
    
    mainPanel->SetSizer(mainSizer);
    
    populateProcessList();
    
    SetAcceleratorTable(wxAcceleratorTable());
}

MainFrame::~MainFrame() {
    delete m_memoryEngine;
}

void MainFrame::createScannerTab(wxPanel* parent) {
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    
    wxBoxSizer* procSizer = new wxBoxSizer(wxHORIZONTAL);
    procSizer->Add(new wxStaticText(parent, wxID_ANY, "Process:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_processCombo = new wxComboBox(parent, 1001, "", wxDefaultPosition, wxSize(350, -1));
    m_refreshBtn = new wxButton(parent, 1002, "Refresh");
    procSizer->Add(m_processCombo, 0, wxRIGHT, 5);
    procSizer->Add(m_refreshBtn, 0);
    sizer->Add(procSizer, 0, wxEXPAND | wxALL, 5);
    
    wxBoxSizer* searchSizer = new wxBoxSizer(wxHORIZONTAL);
    searchSizer->Add(new wxStaticText(parent, wxID_ANY, "Value:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_searchValue = new wxTextCtrl(parent, wxID_ANY, "", wxDefaultPosition, wxSize(150, -1));
    
    wxArrayString types;
    types.Add("int8");
    types.Add("int16");
    types.Add("int32");
    types.Add("int64");
    types.Add("float");
    types.Add("double");
    types.Add("byte");
    types.Add("string");
    types.Add("wstring");
    types.Add("pointer");
    types.Add("aob");
    m_dataType = new wxComboBox(parent, wxID_ANY, "int32", wxDefaultPosition, wxSize(100, -1), types);
    m_dataType->SetSelection(2);
    
    wxArrayString filters;
    filters.Add("Exact");
    filters.Add("Increased");
    filters.Add("Decreased");
    filters.Add("Unchanged");
    m_scanFilter = new wxComboBox(parent, wxID_ANY, "Exact", wxDefaultPosition, wxSize(100, -1), filters);
    
    m_scanBtn = new wxButton(parent, 1003, "First Scan");
    m_nextScanBtn = new wxButton(parent, 1004, "Next Scan");
    m_resetBtn = new wxButton(parent, 1005, "Reset");
    m_stopBtn = new wxButton(parent, 1006, "Stop");
    m_aobScanBtn = new wxButton(parent, 1007, "AOB Scan");
    m_nextScanBtn->Enable(false);
    m_stopBtn->Enable(false);
    
    searchSizer->Add(m_searchValue, 0, wxRIGHT, 5);
    searchSizer->Add(new wxStaticText(parent, wxID_ANY, "Type:"), 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT, 5);
    searchSizer->Add(m_dataType, 0, wxRIGHT, 5);
    searchSizer->Add(new wxStaticText(parent, wxID_ANY, "Filter:"), 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT, 5);
    searchSizer->Add(m_scanFilter, 0, wxRIGHT, 5);
    searchSizer->Add(m_scanBtn, 0, wxRIGHT, 5);
    searchSizer->Add(m_nextScanBtn, 0, wxRIGHT, 5);
    searchSizer->Add(m_resetBtn, 0, wxRIGHT, 5);
    searchSizer->Add(m_stopBtn, 0, wxRIGHT, 5);
    searchSizer->Add(m_aobScanBtn, 0);
    sizer->Add(searchSizer, 0, wxEXPAND | wxALL, 5);
    
    m_progressGauge = new wxGauge(parent, wxID_ANY, 100, wxDefaultPosition, wxSize(-1, 20));
    sizer->Add(m_progressGauge, 0, wxEXPAND | wxALL, 5);
    
    m_resultsList = new wxListView(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, 
        wxLC_REPORT | wxLC_SINGLE_SEL);
    m_resultsList->InsertColumn(0, "Address", 0, 150);
    m_resultsList->InsertColumn(1, "Value", 0, 250);
    m_resultsList->InsertColumn(2, "Type", 0, 80);
    m_resultsList->InsertColumn(3, "Module", 0, 120);
    sizer->Add(m_resultsList, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 5);
    
    m_resultCountText = new wxStaticText(parent, wxID_ANY, "Results: 0");
    sizer->Add(m_resultCountText, 0, wxLEFT, 5);
    
    wxBoxSizer* writeSizer = new wxBoxSizer(wxHORIZONTAL);
    writeSizer->Add(new wxStaticText(parent, wxID_ANY, "New Value:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_writeValue = new wxTextCtrl(parent, wxID_ANY, "", wxDefaultPosition, wxSize(150, -1));
    m_writeBtn = new wxButton(parent, 1014, "Write");
    m_copyAddrBtn = new wxButton(parent, 1013, "Copy Address");
    m_saveResultsBtn = new wxButton(parent, 1011, "Save Results");
    m_loadResultsBtn = new wxButton(parent, 1012, "Load Results");
    writeSizer->Add(m_writeValue, 0, wxRIGHT, 5);
    writeSizer->Add(m_writeBtn, 0, wxRIGHT, 5);
    writeSizer->Add(m_copyAddrBtn, 0, wxRIGHT, 5);
    writeSizer->Add(m_saveResultsBtn, 0, wxRIGHT, 5);
    writeSizer->Add(m_loadResultsBtn, 0);
    sizer->Add(writeSizer, 0, wxEXPAND | wxALL, 5);
    
    parent->SetSizer(sizer);
}

void MainFrame::createPointerTab(wxPanel* parent) {
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    
    wxStaticText* infoText = new wxStaticText(parent, wxID_ANY, 
        "Pointer Scan: Encontra o caminho de ponteiros ate um endereco especifico.\n"
        "Isso ajuda a encontrar enderecos estaticos que nao mudam entre execucoes.");
    sizer->Add(infoText, 0, wxALL, 5);
    
    wxBoxSizer* inputSizer = new wxBoxSizer(wxHORIZONTAL);
    inputSizer->Add(new wxStaticText(parent, wxID_ANY, "Target Address (hex):"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_pointerAddress = new wxTextCtrl(parent, wxID_ANY, "", wxDefaultPosition, wxSize(200, -1));
    inputSizer->Add(m_pointerAddress, 0, wxRIGHT, 10);
    
    inputSizer->Add(new wxStaticText(parent, wxID_ANY, "Max Level:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_pointerMaxLevel = new wxSpinCtrl(parent, wxID_ANY, "3", wxDefaultPosition, wxSize(60, -1), 0, 1, 10);
    inputSizer->Add(m_pointerMaxLevel, 0, wxRIGHT, 10);
    
    inputSizer->Add(new wxStaticText(parent, wxID_ANY, "Max Results:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_pointerMaxResults = new wxSpinCtrl(parent, wxID_ANY, "10", wxDefaultPosition, wxSize(60, -1), 0, 1, 100);
    inputSizer->Add(m_pointerMaxResults, 0, wxRIGHT, 10);
    
    m_pointerScanBtn = new wxButton(parent, 1008, "Scan for Pointers");
    inputSizer->Add(m_pointerScanBtn, 0);
    sizer->Add(inputSizer, 0, wxEXPAND | wxALL, 5);
    
    m_pointerResultsList = new wxListView(parent, wxID_ANY, wxDefaultPosition, wxSize(-1, 300),
        wxLC_REPORT | wxLC_SINGLE_SEL);
    m_pointerResultsList->InsertColumn(0, "Pointer Address", 0, 150);
    m_pointerResultsList->InsertColumn(1, "Points To", 0, 150);
    m_pointerResultsList->InsertColumn(2, "Path", 0, 400);
    sizer->Add(m_pointerResultsList, 1, wxEXPAND | wxALL, 5);
    
    parent->SetSizer(sizer);
}

void MainFrame::createDumpTab(wxPanel* parent) {
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    
    wxStaticText* infoText = new wxStaticText(parent, wxID_ANY,
        "Dump de Memoria: Exporta uma regiao de memoria para um arquivo .bin\n"
        "Use para analisar dados em um editor hexadecimal.");
    sizer->Add(infoText, 0, wxALL, 5);
    
    wxBoxSizer* inputSizer = new wxBoxSizer(wxHORIZONTAL);
    inputSizer->Add(new wxStaticText(parent, wxID_ANY, "Address (hex):"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_dumpAddress = new wxTextCtrl(parent, wxID_ANY, "", wxDefaultPosition, wxSize(150, -1));
    inputSizer->Add(m_dumpAddress, 0, wxRIGHT, 10);
    
    inputSizer->Add(new wxStaticText(parent, wxID_ANY, "Size (bytes):"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_dumpSize = new wxTextCtrl(parent, wxID_ANY, "4096", wxDefaultPosition, wxSize(100, -1));
    inputSizer->Add(m_dumpSize, 0, wxRIGHT, 10);
    
    inputSizer->Add(new wxStaticText(parent, wxID_ANY, "File:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_dumpPath = new wxTextCtrl(parent, wxID_ANY, "dump.bin", wxDefaultPosition, wxSize(200, -1));
    inputSizer->Add(m_dumpPath, 1, wxRIGHT, 5);
    
    m_dumpBtn = new wxButton(parent, 1009, "Dump");
    inputSizer->Add(m_dumpBtn, 0);
    sizer->Add(inputSizer, 0, wxEXPAND | wxALL, 5);
    
    parent->SetSizer(sizer);
}

void MainFrame::createToolsTab(wxPanel* parent) {
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    
    wxStaticBox* dllBox = new wxStaticBox(parent, wxID_ANY, "DLL Injection");
    wxStaticBoxSizer* dllSizer = new wxStaticBoxSizer(dllBox, wxVERTICAL);
    
    wxStaticText* dllInfo = new wxStaticText(parent, wxID_ANY,
        "DLL Injection: Injeta uma DLL no processo selecionado.\n"
        "Use para carregar codigo customizado no processo.");
    dllSizer->Add(dllInfo, 0, wxALL, 5);
    
    wxBoxSizer* dllInputSizer = new wxBoxSizer(wxHORIZONTAL);
    dllInputSizer->Add(new wxStaticText(parent, wxID_ANY, "DLL Path:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_dllPath = new wxTextCtrl(parent, wxID_ANY, "", wxDefaultPosition, wxSize(400, -1));
    m_injectDllBtn = new wxButton(parent, 1010, "Inject DLL");
    dllInputSizer->Add(m_dllPath, 1, wxRIGHT, 5);
    dllInputSizer->Add(m_injectDllBtn, 0);
    dllSizer->Add(dllInputSizer, 0, wxEXPAND | wxALL, 5);
    
    sizer->Add(dllSizer, 0, wxEXPAND | wxALL, 5);
    
    wxStaticBox* aobBox = new wxStaticBox(parent, wxID_ANY, "AOB Scanning Info");
    wxStaticBoxSizer* aobSizer = new wxStaticBoxSizer(aobBox, wxVERTICAL);
    
    wxStaticText* aobInfo = new wxStaticText(parent, wxID_ANY,
        "AOB (Array of Bytes) Scan: Busca por padroes de bytes na memoria.\n\n"
        "Formato: Use hex bytes normais e ?? para wildcards.\n"
        "Exemplo: 48 8B 05 ?? ?? ?? ?? 8B D8 = Procura essa sequencia com 4 bytes desconhecidos\n\n"
        "Isso e util para encontrar codigo ou dados com offsets fixos.");
    aobSizer->Add(aobInfo, 0, wxALL, 5);
    sizer->Add(aobSizer, 0, wxEXPAND | wxALL, 5);
    
    parent->SetSizer(sizer);
}

void MainFrame::createSettingsTab(wxPanel* parent) {
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    
    wxStaticBox* precisionBox = new wxStaticBox(parent, wxID_ANY, "Float Precision");
    wxStaticBoxSizer* precisionSizer = new wxStaticBoxSizer(precisionBox, wxHORIZONTAL);
    
    wxStaticText* precisionInfo = new wxStaticText(parent, wxID_ANY, "Casas decimais para floats:");
    m_floatPrecision = new wxSpinCtrl(parent, 1015, "6", wxDefaultPosition, wxSize(60, -1), 0, 1, 15);
    precisionSizer->Add(precisionInfo, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    precisionSizer->Add(m_floatPrecision, 0);
    sizer->Add(precisionSizer, 0, wxEXPAND | wxALL, 5);
    
    wxStaticBox* filterBox = new wxStaticBox(parent, wxID_ANY, "Module Filters");
    wxStaticBoxSizer* filterSizer = new wxStaticBoxSizer(filterBox, wxVERTICAL);
    
    wxBoxSizer* filterInputSizer = new wxBoxSizer(wxHORIZONTAL);
    filterInputSizer->Add(new wxStaticText(parent, wxID_ANY, "Module:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_moduleFilterInput = new wxTextCtrl(parent, wxID_ANY, "", wxDefaultPosition, wxSize(200, -1));
    wxButton* addWhitelistBtn = new wxButton(parent, 1016, "Add Whitelist");
    wxButton* addBlacklistBtn = new wxButton(parent, 1017, "Add Blacklist");
    wxButton* clearFiltersBtn = new wxButton(parent, 1018, "Clear All");
    filterInputSizer->Add(m_moduleFilterInput, 0, wxRIGHT, 5);
    filterInputSizer->Add(addWhitelistBtn, 0, wxRIGHT, 5);
    filterInputSizer->Add(addBlacklistBtn, 0, wxRIGHT, 5);
    filterInputSizer->Add(clearFiltersBtn, 0);
    filterSizer->Add(filterInputSizer, 0, wxEXPAND | wxALL, 5);
    
    wxBoxSizer* listSizer = new wxBoxSizer(wxHORIZONTAL);
    
    listSizer->Add(new wxStaticText(parent, wxID_ANY, "Whitelist:"), 0, wxRIGHT, 5);
    m_whitelistBox = new wxListBox(parent, wxID_ANY, wxDefaultPosition, wxSize(200, 100));
    listSizer->Add(m_whitelistBox, 1, wxRIGHT, 10);
    
    listSizer->Add(new wxStaticText(parent, wxID_ANY, "Blacklist:"), 0, wxRIGHT, 5);
    m_blacklistBox = new wxListBox(parent, wxID_ANY, wxDefaultPosition, wxSize(200, 100));
    listSizer->Add(m_blacklistBox, 1);
    filterSizer->Add(listSizer, 0, wxEXPAND | wxALL, 5);
    
    wxStaticText* whitelistInfo = new wxStaticText(parent, wxID_ANY,
        "Whitelist: Escaneia apenas modulos listados (vazio = escaneia todos)\n"
        "Blacklist: Pula modulos listados (ex: ntdll.dll, kernelbase.dll)");
    filterSizer->Add(whitelistInfo, 0, wxALL, 5);
    
    sizer->Add(filterSizer, 0, wxEXPAND | wxALL, 5);
    
    parent->SetSizer(sizer);
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
    updateLog("Process list refreshed");
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
        
        m_memoryEngine->setProgressCallback([this](int percent) {
            wxThreadEvent event(wxEVT_THREAD);
            event.SetInt(percent);
            wxQueueEvent(this, event.Clone());
        });
        
        m_memoryEngine->setLogCallback([this](const std::string& msg) {
            wxThreadEvent event(wxEVT_THREAD);
            event.SetString(msg);
            wxQueueEvent(this, event.Clone());
        });
        
        m_initialScanDone = false;
        m_aobMode = false;
        m_results.clear();
        m_resultsList->DeleteAllItems();
        m_pointerResultsList->DeleteAllItems();
        m_scanBtn->SetLabel("First Scan");
        m_nextScanBtn->Enable(false);
        m_dataType->SetSelection(2);
        
        updateLog("Process opened: " + processes[selection].name + " (" + processes[selection].name + ")");
        m_statusText->SetLabel("Process: " + processes[selection].name);
    } else {
        updateLog("Failed to open process. Try running as administrator.");
    }
}

DataType MainFrame::getSelectedDataType() {
    int sel = m_dataType->GetSelection();
    switch (sel) {
        case 0: return DataType::INT8;
        case 1: return DataType::INT16;
        case 2: return DataType::INT32;
        case 3: return DataType::INT64;
        case 4: return DataType::FLOAT;
        case 5: return DataType::DOUBLE;
        case 6: return DataType::BYTE;
        case 7: return DataType::STRING;
        case 8: return DataType::WSTRING;
        case 9: return DataType::POINTER;
        case 10: return DataType::BYTEARRAY;
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

void MainFrame::onFirstScan(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        updateLog("Please select a process first");
        return;
    }
    
    wxString value = m_searchValue->GetValue();
    if (value.IsEmpty()) {
        updateLog("Please enter a value to search");
        return;
    }
    
    DataType type = getSelectedDataType();
    
    m_aobMode = (type == DataType::BYTEARRAY);
    
    if (type == DataType::BYTEARRAY) {
        m_results = m_memoryEngine->aobScan(value.ToStdString());
    } else {
        m_results = m_memoryEngine->initialScan(type, value.ToStdString());
    }
    
    m_initialScanDone = true;
    m_scanBtn->SetLabel("Next Scan");
    m_nextScanBtn->Enable(true);
    m_stopBtn->Enable(false);
    
    updateResultsList();
}

void MainFrame::onNextScan(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        updateLog("No process selected");
        return;
    }
    
    wxString value = m_searchValue->GetValue();
    if (value.IsEmpty()) {
        updateLog("Enter a value for next scan");
        return;
    }
    
    ScanFilter filter = getSelectedFilter();
    m_results = m_memoryEngine->nextScan(filter, value.ToStdString());
    
    updateResultsList();
}

void MainFrame::onResetScan(wxCommandEvent& event) {
    if (m_memoryEngine) {
        m_memoryEngine->stopScan();
        m_memoryEngine->clearResults();
    }
    m_initialScanDone = false;
    m_aobMode = false;
    m_results.clear();
    m_resultsList->DeleteAllItems();
    m_scanBtn->SetLabel("First Scan");
    m_nextScanBtn->Enable(false);
    m_stopBtn->Enable(false);
    m_progressGauge->SetValue(0);
    updateLog("Scan reset");
    updateResultsList();
}

void MainFrame::onStopScan(wxCommandEvent& event) {
    if (m_memoryEngine) {
        m_memoryEngine->stopScan();
        updateLog("Scan stopped by user");
    }
}

void MainFrame::onAOBScan(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        updateLog("Select a process first");
        return;
    }
    
    wxString pattern = m_searchValue->GetValue();
    if (pattern.IsEmpty()) {
        updateLog("Enter an AOB pattern (ex: 48 8B 05 ?? ?? ?? ??)");
        return;
    }
    
    m_results = m_memoryEngine->aobScan(pattern.ToStdString());
    m_aobMode = true;
    m_initialScanDone = true;
    m_scanBtn->SetLabel("Next Scan");
    m_nextScanBtn->Enable(true);
    
    updateResultsList();
}

void MainFrame::onPointerScan(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        updateLog("Select a process first");
        return;
    }
    
    wxString addrStr = m_pointerAddress->GetValue();
    if (addrStr.IsEmpty()) {
        updateLog("Enter a target address (hex)");
        return;
    }
    
    uintptr_t targetAddr = 0;
    std::istringstream iss(addrStr.ToStdString());
    iss >> std::hex >> targetAddr;
    
    int maxLevel = m_pointerMaxLevel->GetValue();
    int maxResults = m_pointerMaxResults->GetValue();
    
    updateLog("Starting pointer scan to 0x" + std::to_string(targetAddr) + "...");
    
    m_results = m_memoryEngine->pointerScan(targetAddr, maxLevel, maxResults);
    
    updatePointerResultsList();
}

void MainFrame::onDumpMemory(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        updateLog("Select a process first");
        return;
    }
    
    wxString addrStr = m_dumpAddress->GetValue();
    wxString sizeStr = m_dumpSize->GetValue();
    wxString pathStr = m_dumpPath->GetValue();
    
    if (addrStr.IsEmpty()) {
        updateLog("Enter an address to dump");
        return;
    }
    
    uintptr_t addr = 0;
    SIZE_T size = 4096;
    
    std::istringstream iss(addrStr.ToStdString());
    iss >> std::hex >> addr;
    
    {
        std::istringstream iss2(sizeStr.ToStdString());
        iss2 >> size;
    }
    
    if (m_memoryEngine->saveDumpToFile(pathStr.ToStdString(), addr, size)) {
        updateLog("Memory dumped to " + pathStr.ToStdString());
    } else {
        updateLog("Failed to dump memory");
    }
}

void MainFrame::onInjectDLL(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        updateLog("Select a process first");
        return;
    }
    
    wxString dllPath = m_dllPath->GetValue();
    if (dllPath.IsEmpty()) {
        updateLog("Enter DLL path");
        return;
    }
    
    if (m_memoryEngine->injectDLL(dllPath.ToStdString())) {
        updateLog("DLL injected: " + dllPath.ToStdString());
    } else {
        updateLog("DLL injection failed");
    }
}

void MainFrame::onSaveResults(wxCommandEvent& event) {
    if (m_results.empty()) {
        updateLog("No results to save");
        return;
    }
    
    wxFileDialog dialog(this, "Save Results", "", "results.json",
        "JSON files (*.json)|*.json", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    
    if (dialog.ShowModal() == wxID_OK) {
        std::ofstream file(dialog.GetPath().ToStdString());
        if (file.is_open()) {
            file << "{\n";
            file << "  \"results\": [\n";
            for (size_t i = 0; i < m_results.size(); i++) {
                const auto& r = m_results[i];
                file << "    {\n";
                file << "      \"address\": \"0x" << std::hex << r.address << "\",\n";
                file << "      \"type\": \"" << r.getTypeString() << "\",\n";
                file << "      \"value\": \"" << r.getValueString() << "\",\n";
                file << "      \"module\": \"" << r.moduleName << "\",\n";
                file << "      \"label\": \"" << r.label << "\"\n";
                file << "    }" << (i < m_results.size() - 1 ? "," : "") << "\n";
            }
            file << "  ]\n";
            file << "}\n";
            file.close();
            updateLog("Results saved to " + dialog.GetPath().ToStdString());
        }
    }
}

void MainFrame::onLoadResults(wxCommandEvent& event) {
    wxFileDialog dialog(this, "Load Results", "", "results.json",
        "JSON files (*.json)|*.json", wxFD_OPEN);
    
    if (dialog.ShowModal() == wxID_OK) {
        std::ifstream file(dialog.GetPath().ToStdString());
        if (file.is_open()) {
            std::string content((std::istreambuf_iterator<char>(file)),
                                 std::istreambuf_iterator<char>());
            file.close();
            
            updateLog("Results loaded from " + dialog.GetPath().ToStdString());
            updateLog("(Note: Loaded results are for reference only. Re-scan to verify addresses.)");
        }
    }
}

void MainFrame::onCopyAddress(wxCommandEvent& event) {
    int selected = m_resultsList->GetFirstSelected();
    if (selected == -1) {
        updateLog("Select an address to copy");
        return;
    }
    
    if (selected >= (int)m_results.size()) return;
    
    std::ostringstream oss;
    oss << "0x" << std::hex << m_results[selected].address;
    
    if (wxTheClipboard->Open()) {
        wxTheClipboard->SetData(new wxTextDataObject(oss.str()));
        wxTheClipboard->Close();
        updateLog("Address copied: " + oss.str());
    }
}

void MainFrame::onWriteValue(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        updateLog("No process selected");
        return;
    }
    
    int selected = m_resultsList->GetFirstSelected();
    if (selected == -1) {
        updateLog("Select an address from results");
        return;
    }
    
    wxString value = m_writeValue->GetValue();
    if (value.IsEmpty()) {
        updateLog("Enter a value to write");
        return;
    }
    
    if (selected >= (int)m_results.size()) return;
    
    auto& result = m_results[selected];
    if (m_memoryEngine->writeMemory(result.address, result.type, value.ToStdString())) {
        std::ostringstream oss;
        oss << "Written '" << value.ToStdString() << "' to 0x" << std::hex << result.address;
        updateLog(oss.str());
    } else {
        updateLog("Failed to write memory. Try running as administrator.");
    }
}

void MainFrame::onPrecisionChanged(wxSpinEvent& event) {
    if (m_memoryEngine) {
        m_memoryEngine->setFloatPrecision(event.GetInt());
        updateLog("Float precision set to " + std::to_string(event.GetInt()) + " decimal places");
    }
}

void MainFrame::onModuleWhitelistAdd(wxCommandEvent& event) {
    wxString module = m_moduleFilterInput->GetValue();
    if (!module.IsEmpty()) {
        m_whitelistBox->Append(module);
        if (m_memoryEngine) {
            m_memoryEngine->addWhitelistModule(module.ToStdString());
        }
        updateLog("Added to whitelist: " + module.ToStdString());
    }
}

void MainFrame::onModuleBlacklistAdd(wxCommandEvent& event) {
    wxString module = m_moduleFilterInput->GetValue();
    if (!module.IsEmpty()) {
        m_blacklistBox->Append(module);
        if (m_memoryEngine) {
            m_memoryEngine->addBlacklistModule(module.ToStdString());
        }
        updateLog("Added to blacklist: " + module.ToStdString());
    }
}

void MainFrame::onModuleFilterClear(wxCommandEvent& event) {
    m_whitelistBox->Clear();
    m_blacklistBox->Clear();
    if (m_memoryEngine) {
        m_memoryEngine->clearModuleFilters();
    }
    updateLog("Module filters cleared");
}

void MainFrame::updateProgress(int percent) {
    m_progressGauge->SetValue(percent);
}

void MainFrame::updateLog(const std::string& message) {
    m_logBox->AppendText(wxDateTime::Now().Format("%H:%M:%S").ToStdString() + " - " + message + "\n");
}

void MainFrame::updateResultsList() {
    m_resultsList->DeleteAllItems();
    
    for (size_t i = 0; i < m_results.size(); i++) {
        const auto& result = m_results[i];
        std::ostringstream addr;
        addr << "0x" << std::hex << std::uppercase << result.address;
        
        m_resultsList->InsertItem(i, addr.str());
        m_resultsList->SetItem(i, 1, result.getValueString());
        m_resultsList->SetItem(i, 2, result.getTypeString());
        m_resultsList->SetItem(i, 3, result.moduleName);
    }
    
    std::ostringstream status;
    status << "Found " << m_results.size() << " addresses";
    m_resultCountText->SetLabel(status.str());
    m_statusText->SetLabel(status.str());
}

void MainFrame::updatePointerResultsList() {
    m_pointerResultsList->DeleteAllItems();
    
    for (size_t i = 0; i < m_results.size(); i++) {
        const auto& result = m_results[i];
        std::ostringstream ptrAddr, targetAddr;
        ptrAddr << "0x" << std::hex << result.address;
        targetAddr << "0x" << std::hex << (uintptr_t)result.numericValue;
        
        m_pointerResultsList->InsertItem(i, ptrAddr.str());
        m_pointerResultsList->SetItem(i, 1, targetAddr.str());
        m_pointerResultsList->SetItem(i, 2, result.label);
    }
    
    std::ostringstream status;
    status << "Found " << m_results.size() << " pointer paths";
    m_statusText->SetLabel(status.str());
    updateLog(status.str());
}
