#include "MainFrame.h"
#include <wx/event.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <wx/filedlg.h>
#include <wx/msgdlg.h>
#include <wx/clipbrd.h>

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
    EVT_BUTTON(1019, MainFrame::onRefreshThreads)
    EVT_BUTTON(1020, MainFrame::onSuspendThread)
    EVT_BUTTON(1021, MainFrame::onResumeThread)
    EVT_BUTTON(1022, MainFrame::onSuspendProcess)
    EVT_BUTTON(1023, MainFrame::onResumeProcess)
    EVT_BUTTON(1024, MainFrame::onRefreshModules)
    EVT_BUTTON(1025, MainFrame::onShowModuleExports)
    EVT_BUTTON(1026, MainFrame::onSetBreakpoint)
    EVT_BUTTON(1027, MainFrame::onClearBreakpoint)
    EVT_BUTTON(1028, MainFrame::onRefreshBreakpoints)
    EVT_BUTTON(1029, MainFrame::onRefreshMemory)
    EVT_BUTTON(1030, MainFrame::onChangeProtection)
    EVT_BUTTON(1031, MainFrame::onAllocateMemory)
    EVT_BUTTON(1032, MainFrame::onFreeMemory)
    EVT_BUTTON(1033, MainFrame::onRefreshPEB)
wxEND_EVENT_TABLE()

MainFrame::MainFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(1100, 800)),
      m_memoryEngine(nullptr), m_initialScanDone(false), m_aobMode(false), m_selectedTID(0) {
    
    SetMinSize(wxSize(1000, 700));
    
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
    
    wxPanel* threadsPanel = new wxPanel(m_notebook, wxID_ANY);
    createThreadsTab(threadsPanel);
    m_notebook->AddPage(threadsPanel, "Threads");
    
    wxPanel* modulesPanel = new wxPanel(m_notebook, wxID_ANY);
    createModulesTab(modulesPanel);
    m_notebook->AddPage(modulesPanel, "Modules");
    
    wxPanel* bpPanel = new wxPanel(m_notebook, wxID_ANY);
    createBreakpointsTab(bpPanel);
    m_notebook->AddPage(bpPanel, "HW Breakpoints");
    
    wxPanel* memPanel = new wxPanel(m_notebook, wxID_ANY);
    createMemoryTab(memPanel);
    m_notebook->AddPage(memPanel, "Memory Regions");
    
    wxPanel* infoPanel = new wxPanel(m_notebook, wxID_ANY);
    createInfoTab(infoPanel);
    m_notebook->AddPage(infoPanel, "PEB Info");
    
    wxPanel* toolsPanel = new wxPanel(m_notebook, wxID_ANY);
    createToolsTab(toolsPanel);
    m_notebook->AddPage(toolsPanel, "Tools");
    
    wxPanel* settingsPanel = new wxPanel(m_notebook, wxID_ANY);
    createSettingsTab(settingsPanel);
    m_notebook->AddPage(settingsPanel, "Settings");
    
    mainSizer->Add(m_notebook, 1, wxEXPAND | wxALL, 5);
    
    m_logBox = new wxTextCtrl(mainPanel, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 100), 
        wxTE_MULTILINE | wxTE_READONLY | wxTE_WORDWRAP);
    mainSizer->Add(m_logBox, 0, wxEXPAND | wxALL, 5);
    
    m_statusText = new wxStaticText(mainPanel, wxID_ANY, "Select a process to begin");
    mainSizer->Add(m_statusText, 0, wxEXPAND | wxALL, 5);
    
    mainPanel->SetSizer(mainSizer);
    
    populateProcessList();
    
    wxAcceleratorEntry entries[6];
    entries[0].Set(wxACCEL_CTRL, (int)'F', 1003);
    entries[1].Set(wxACCEL_CTRL, (int)'N', 1004);
    entries[2].Set(wxACCEL_CTRL, (int)'R', 1005);
    entries[3].Set(wxACCEL_CTRL, (int)'W', 1014);
    entries[4].Set(wxACCEL_CTRL, (int)'C', 1013);
    entries[5].Set(wxACCEL_CTRL, (int)'S', 1011);
    wxAcceleratorTable accel(6, entries);
    SetAcceleratorTable(accel);
    
    updateLog("System ready. Request debug privilege automatically on process open.");
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
    types.Add("int8"); types.Add("int16"); types.Add("int32"); types.Add("int64");
    types.Add("float"); types.Add("double"); types.Add("byte");
    types.Add("string"); types.Add("wstring"); types.Add("pointer"); types.Add("aob");
    m_dataType = new wxComboBox(parent, wxID_ANY, "int32", wxDefaultPosition, wxSize(100, -1), types);
    m_dataType->SetSelection(2);
    
    wxArrayString filters;
    filters.Add("Exact"); filters.Add("Increased"); filters.Add("Decreased"); filters.Add("Unchanged");
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
    m_saveResultsBtn = new wxButton(parent, 1011, "Save");
    m_loadResultsBtn = new wxButton(parent, 1012, "Load");
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
        "Pointer Scan: Encontra caminhos de ponteiros ate um endereco especifico.\n"
        "Isso ajuda a encontrar enderecos estaticos que nao mudam entre execucoes.\n"
        "Exemplo de uso: Encontre um valor na memoria, pegue o endereco, use este scan para encontrar um ponteiro estatico.");
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
    m_pointerResultsList->InsertColumn(2, "Path", 0, 500);
    sizer->Add(m_pointerResultsList, 1, wxEXPAND | wxALL, 5);
    
    parent->SetSizer(sizer);
}

void MainFrame::createDumpTab(wxPanel* parent) {
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    
    wxStaticText* infoText = new wxStaticText(parent, wxID_ANY,
        "Dump de Memoria: Exporta uma regiao de memoria para um arquivo .bin\n"
        "Use para analisar dados em um editor hexadecimal como ImHex, HxD, ou 010 Editor.");
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

void MainFrame::createThreadsTab(wxPanel* parent) {
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    
    wxStaticText* infoText = new wxStaticText(parent, wxID_ANY,
        "Thread Viewer: Lista todas as threads do processo selecionado.\n"
        "Permite suspender/resumir threads individuais ou todo o processo.\n"
        "Nota: Suspender todas as threads = freeze do processo.");
    sizer->Add(infoText, 0, wxALL, 5);
    
    wxBoxSizer* btnSizer = new wxBoxSizer(wxHORIZONTAL);
    m_refreshThreadsBtn = new wxButton(parent, 1019, "Refresh Threads");
    m_suspendThreadBtn = new wxButton(parent, 1020, "Suspend Thread");
    m_resumeThreadBtn = new wxButton(parent, 1021, "Resume Thread");
    m_suspendProcessBtn = new wxButton(parent, 1022, "Suspend All");
    m_resumeProcessBtn = new wxButton(parent, 1023, "Resume All");
    btnSizer->Add(m_refreshThreadsBtn, 0, wxRIGHT, 5);
    btnSizer->Add(m_suspendThreadBtn, 0, wxRIGHT, 5);
    btnSizer->Add(m_resumeThreadBtn, 0, wxRIGHT, 5);
    btnSizer->Add(m_suspendProcessBtn, 0, wxRIGHT, 5);
    btnSizer->Add(m_resumeProcessBtn, 0);
    sizer->Add(btnSizer, 0, wxEXPAND | wxALL, 5);
    
    m_threadsList = new wxListView(parent, wxID_ANY, wxDefaultPosition, wxSize(-1, 400),
        wxLC_REPORT | wxLC_SINGLE_SEL);
    m_threadsList->InsertColumn(0, "TID", 0, 80);
    m_threadsList->InsertColumn(1, "Priority", 0, 80);
    m_threadsList->InsertColumn(2, "State", 0, 120);
    m_threadsList->InsertColumn(3, "TEB Address", 0, 150);
    sizer->Add(m_threadsList, 1, wxEXPAND | wxALL, 5);
    
    parent->SetSizer(sizer);
}

void MainFrame::createModulesTab(wxPanel* parent) {
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    
    wxStaticText* infoText = new wxStaticText(parent, wxID_ANY,
        "Module Viewer: Lista todos os modulos (DLLs/EXEs) carregados no processo.\n"
        "Mostra base address, tamanho, e path completo.");
    sizer->Add(infoText, 0, wxALL, 5);
    
    wxBoxSizer* btnSizer = new wxBoxSizer(wxHORIZONTAL);
    m_refreshModulesBtn = new wxButton(parent, 1024, "Refresh Modules");
    m_showExportsBtn = new wxButton(parent, 1025, "Show Exports");
    btnSizer->Add(m_refreshModulesBtn, 0, wxRIGHT, 5);
    btnSizer->Add(m_showExportsBtn, 0);
    sizer->Add(btnSizer, 0, wxEXPAND | wxALL, 5);
    
    m_modulesList = new wxListView(parent, wxID_ANY, wxDefaultPosition, wxSize(-1, 400),
        wxLC_REPORT | wxLC_SINGLE_SEL);
    m_modulesList->InsertColumn(0, "Name", 0, 150);
    m_modulesList->InsertColumn(1, "Base Address", 0, 150);
    m_modulesList->InsertColumn(2, "Size", 0, 100);
    m_modulesList->InsertColumn(3, "Path", 0, 400);
    sizer->Add(m_modulesList, 1, wxEXPAND | wxALL, 5);
    
    parent->SetSizer(sizer);
}

void MainFrame::createBreakpointsTab(wxPanel* parent) {
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    
    wxStaticText* infoText = new wxStaticText(parent, wxID_ANY,
        "Hardware Breakpoints: Usa Debug Registers (DR0-DR3) para definir breakpoints.\n"
        "Tipos: Execute (codigo), Write (memoria alterada), Read/Write (memoria acessada).\n"
        "Limite: 4 breakpoints simultaneos (por thread).");
    sizer->Add(infoText, 0, wxALL, 5);
    
    wxBoxSizer* inputSizer = new wxBoxSizer(wxHORIZONTAL);
    inputSizer->Add(new wxStaticText(parent, wxID_ANY, "Address (hex):"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_dumpAddress = new wxTextCtrl(parent, wxID_ANY, "", wxDefaultPosition, wxSize(150, -1));
    inputSizer->Add(m_dumpAddress, 0, wxRIGHT, 10);
    
    wxArrayString types;
    types.Add("Execute"); types.Add("Write"); types.Add("Read/Write");
    m_breakpointType = new wxComboBox(parent, wxID_ANY, "Execute", wxDefaultPosition, wxSize(100, -1), types);
    inputSizer->Add(new wxStaticText(parent, wxID_ANY, "Type:"), 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT, 5);
    inputSizer->Add(m_breakpointType, 0, wxRIGHT, 10);
    
    wxArrayString lengths;
    lengths.Add("1 byte"); lengths.Add("2 bytes"); lengths.Add("4 bytes"); lengths.Add("8 bytes");
    m_breakpointLength = new wxComboBox(parent, wxID_ANY, "1 byte", wxDefaultPosition, wxSize(80, -1), lengths);
    inputSizer->Add(new wxStaticText(parent, wxID_ANY, "Length:"), 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT, 5);
    inputSizer->Add(m_breakpointLength, 0, wxRIGHT, 10);
    
    m_setBreakpointBtn = new wxButton(parent, 1026, "Set BP");
    m_clearBreakpointBtn = new wxButton(parent, 1027, "Clear BP");
    m_refreshBreakpointsBtn = new wxButton(parent, 1028, "Refresh");
    inputSizer->Add(m_setBreakpointBtn, 0, wxRIGHT, 5);
    inputSizer->Add(m_clearBreakpointBtn, 0, wxRIGHT, 5);
    inputSizer->Add(m_refreshBreakpointsBtn, 0);
    sizer->Add(inputSizer, 0, wxEXPAND | wxALL, 5);
    
    m_breakpointsList = new wxListView(parent, wxID_ANY, wxDefaultPosition, wxSize(-1, 200),
        wxLC_REPORT | wxLC_SINGLE_SEL);
    m_breakpointsList->InsertColumn(0, "Index", 0, 60);
    m_breakpointsList->InsertColumn(1, "Address", 0, 150);
    m_breakpointsList->InsertColumn(2, "Type", 0, 100);
    m_breakpointsList->InsertColumn(3, "Length", 0, 80);
    m_breakpointsList->InsertColumn(4, "Enabled", 0, 80);
    sizer->Add(m_breakpointsList, 1, wxEXPAND | wxALL, 5);
    
    parent->SetSizer(sizer);
}

void MainFrame::createMemoryTab(wxPanel* parent) {
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    
    wxStaticText* infoText = new wxStaticText(parent, wxID_ANY,
        "Memory Regions: Lista todas as regioes de memoria do processo.\n"
        "Mostra protecao, estado, e tipo de cada regiao.\n"
        "Permite mudar protecao e alocar memoria no processo.");
    sizer->Add(infoText, 0, wxALL, 5);
    
    wxBoxSizer* btnSizer = new wxBoxSizer(wxHORIZONTAL);
    m_refreshMemoryBtn = new wxButton(parent, 1029, "Refresh");
    m_changeProtectionBtn = new wxButton(parent, 1030, "Change Protection");
    m_allocateMemoryBtn = new wxButton(parent, 1031, "Allocate");
    m_freeMemoryBtn = new wxButton(parent, 1032, "Free");
    btnSizer->Add(m_refreshMemoryBtn, 0, wxRIGHT, 5);
    btnSizer->Add(m_changeProtectionBtn, 0, wxRIGHT, 5);
    btnSizer->Add(m_allocateMemoryBtn, 0, wxRIGHT, 5);
    btnSizer->Add(m_freeMemoryBtn, 0);
    sizer->Add(btnSizer, 0, wxEXPAND | wxALL, 5);
    
    m_memoryList = new wxListView(parent, wxID_ANY, wxDefaultPosition, wxSize(-1, 400),
        wxLC_REPORT | wxLC_SINGLE_SEL);
    m_memoryList->InsertColumn(0, "Address", 0, 120);
    m_memoryList->InsertColumn(1, "Size", 0, 80);
    m_memoryList->InsertColumn(2, "Protect", 0, 120);
    m_memoryList->InsertColumn(3, "State", 0, 80);
    m_memoryList->InsertColumn(4, "Type", 0, 80);
    m_memoryList->InsertColumn(5, "Allocation Base", 0, 120);
    sizer->Add(m_memoryList, 1, wxEXPAND | wxALL, 5);
    
    parent->SetSizer(sizer);
}

void MainFrame::createInfoTab(wxPanel* parent) {
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    
    wxStaticText* infoText = new wxStaticText(parent, wxID_ANY,
        "PEB (Process Environment Block): Informacoes do processo a nivel de sistema.\n"
        "Inclui command line, loaded modules, debug info, e muito mais.");
    sizer->Add(infoText, 0, wxALL, 5);
    
    m_refreshPEBBtn = new wxButton(parent, 1033, "Refresh PEB Info");
    sizer->Add(m_refreshPEBBtn, 0, wxALL, 5);
    
    m_pebInfo = new wxTextCtrl(parent, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 500),
        wxTE_MULTILINE | wxTE_READONLY | wxTE_WORDWRAP);
    sizer->Add(m_pebInfo, 1, wxEXPAND | wxALL, 5);
    
    parent->SetSizer(sizer);
}

void MainFrame::createToolsTab(wxPanel* parent) {
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    
    wxStaticBox* dllBox = new wxStaticBox(parent, wxID_ANY, "DLL Injection");
    wxStaticBoxSizer* dllSizer = new wxStaticBoxSizer(dllBox, wxVERTICAL);
    
    wxStaticText* dllInfo = new wxStaticText(parent, wxID_ANY,
        "DLL Injection: Injeta uma DLL no processo selecionado via LoadLibrary.\n"
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
        "Formato: Hex bytes normais + ?? para wildcards.\n"
        "Exemplo: 48 8B 05 ?? ?? ?? ?? = Procura essa sequencia com 4 bytes desconhecidos\n\n"
        "Use para encontrar codigo com offsets fixos (ex: instruction patterns).");
    aobSizer->Add(aobInfo, 0, wxALL, 5);
    sizer->Add(aobSizer, 0, wxEXPAND | wxALL, 5);
    
    wxStaticBox* debugBox = new wxStaticBox(parent, wxID_ANY, "SE_DEBUG Privilege");
    wxStaticBoxSizer* debugSizer = new wxStaticBoxSizer(debugBox, wxVERTICAL);
    
    wxStaticText* debugInfo = new wxStaticText(parent, wxID_ANY,
        "SE_DEBUG: Quando voce abre um processo, o sistema automaticamente requisita\n"
        "este privilegio. Isso permite acessar processos protegidos como lsass.exe.\n"
        "Apenas processos com privilegios de admin podem obter este privilegio.");
    debugSizer->Add(debugInfo, 0, wxALL, 5);
    sizer->Add(debugSizer, 0, wxEXPAND | wxALL, 5);
    
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

void MainFrame::populateThreadList() {
    m_threadsList->DeleteAllItems();
    auto threads = m_processManager.getThreadList();
    
    for (size_t i = 0; i < threads.size(); i++) {
        const auto& t = threads[i];
        std::ostringstream oss;
        oss << t.tid;
        m_threadsList->InsertItem(i, oss.str());
        m_threadsList->SetItem(i, 1, std::to_string(t.priority));
        m_threadsList->SetItem(i, 2, t.state);
        oss.str("");
        oss << "0x" << std::hex << t.tebAddress;
        m_threadsList->SetItem(i, 3, oss.str());
    }
}

void MainFrame::populateModuleList() {
    m_modulesList->DeleteAllItems();
    auto modules = m_processManager.getModuleList();
    
    for (size_t i = 0; i < modules.size(); i++) {
        const auto& m = modules[i];
        m_modulesList->InsertItem(i, m.name);
        std::ostringstream oss;
        oss << "0x" << std::hex << m.baseAddress;
        m_modulesList->SetItem(i, 1, oss.str());
        oss.str("");
        oss << "0x" << std::hex << m.size;
        m_modulesList->SetItem(i, 2, oss.str());
        m_modulesList->SetItem(i, 3, m.fullPath);
    }
}

void MainFrame::populateMemoryRegionList() {
    m_memoryList->DeleteAllItems();
    auto regions = m_processManager.getMemoryRegions();
    
    for (size_t i = 0; i < regions.size(); i++) {
        const auto& r = regions[i];
        std::ostringstream oss;
        oss << "0x" << std::hex << r.address;
        m_memoryList->InsertItem(i, oss.str());
        oss.str("");
        oss << "0x" << std::hex << r.size;
        m_memoryList->SetItem(i, 1, oss.str());
        m_memoryList->SetItem(i, 2, r.protectString);
        m_memoryList->SetItem(i, 3, r.stateString);
        m_memoryList->SetItem(i, 4, r.typeString);
        oss.str("");
        oss << "0x" << std::hex << r.allocationBase;
        m_memoryList->SetItem(i, 5, oss.str());
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
    
    updateLog("Opening process " + processes[selection].name + " with SE_DEBUG privilege...");
    
    if (m_processManager.openProcess(pid, true)) {
        delete m_memoryEngine;
        m_memoryEngine = new MemoryEngine(m_processManager.getHandle(), m_processManager.is64Bit());
        
        m_memoryEngine->setProgressCallback([this](int percent) {
        });
        
        m_memoryEngine->setLogCallback([this](const std::string& msg) {
            updateLog(msg);
        });
        
        m_initialScanDone = false;
        m_aobMode = false;
        m_results.clear();
        m_resultsList->DeleteAllItems();
        m_pointerResultsList->DeleteAllItems();
        m_scanBtn->SetLabel("First Scan");
        m_nextScanBtn->Enable(false);
        m_dataType->SetSelection(2);
        
        std::ostringstream oss;
        oss << "Process opened: " << processes[selection].name;
        if (m_processManager.hasDebugPrivilege()) {
            oss << " (SE_DEBUG: OK)";
        } else {
            oss << " (SE_DEBUG: Failed - admin required)";
        }
        updateLog(oss.str());
        m_statusText->SetLabel("Process: " + processes[selection].name);
        
        populateThreadList();
        populateModuleList();
        populateMemoryRegionList();
    } else {
        updateLog("Failed to open process. Try running as administrator.");
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
            file << "{\n  \"results\": [\n";
            for (size_t i = 0; i < m_results.size(); i++) {
                const auto& r = m_results[i];
                file << "    {\n";
                file << "      \"address\": \"0x" << std::hex << r.address << "\",\n";
                file << "      \"type\": \"" << r.getTypeString() << "\",\n";
                file << "      \"value\": \"" << r.getValueString() << "\",\n";
                file << "      \"module\": \"" << r.moduleName << "\"\n";
                file << "    }" << (i < m_results.size() - 1 ? "," : "") << "\n";
            }
            file << "  ]\n}\n";
            file.close();
            updateLog("Results saved to " + dialog.GetPath().ToStdString());
        }
    }
}

void MainFrame::onLoadResults(wxCommandEvent& event) {
    wxFileDialog dialog(this, "Load Results", "", "results.json",
        "JSON files (*.json)|*.json", wxFD_OPEN);
    
    if (dialog.ShowModal() == wxID_OK) {
        updateLog("Results loaded from " + dialog.GetPath().ToStdString());
        updateLog("(Note: Loaded results are for reference only. Re-scan to verify addresses.)");
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

void MainFrame::onRefreshThreads(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        updateLog("Select a process first");
        return;
    }
    populateThreadList();
    updateLog("Threads refreshed");
}

void MainFrame::onSuspendThread(wxCommandEvent& event) {
    int selected = m_threadsList->GetFirstSelected();
    if (selected == -1) {
        updateLog("Select a thread first");
        return;
    }
    
    auto threads = m_processManager.getThreadList();
    if (selected >= (int)threads.size()) return;
    
    if (m_processManager.suspendThread(threads[selected].tid)) {
        updateLog("Thread " + std::to_string(threads[selected].tid) + " suspended");
        populateThreadList();
    } else {
        updateLog("Failed to suspend thread");
    }
}

void MainFrame::onResumeThread(wxCommandEvent& event) {
    int selected = m_threadsList->GetFirstSelected();
    if (selected == -1) {
        updateLog("Select a thread first");
        return;
    }
    
    auto threads = m_processManager.getThreadList();
    if (selected >= (int)threads.size()) return;
    
    if (m_processManager.resumeThread(threads[selected].tid)) {
        updateLog("Thread " + std::to_string(threads[selected].tid) + " resumed");
        populateThreadList();
    } else {
        updateLog("Failed to resume thread");
    }
}

void MainFrame::onSuspendProcess(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        updateLog("Select a process first");
        return;
    }
    
    if (m_processManager.suspendProcess()) {
        updateLog("Process suspended (all threads paused)");
    } else {
        updateLog("Failed to suspend process");
    }
}

void MainFrame::onResumeProcess(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        updateLog("Select a process first");
        return;
    }
    
    if (m_processManager.resumeProcess()) {
        updateLog("Process resumed (all threads running)");
    } else {
        updateLog("Failed to resume process");
    }
}

void MainFrame::onRefreshModules(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        updateLog("Select a process first");
        return;
    }
    populateModuleList();
    updateLog("Modules refreshed");
}

void MainFrame::onShowModuleExports(wxCommandEvent& event) {
    int selected = m_modulesList->GetFirstSelected();
    if (selected == -1) {
        updateLog("Select a module first");
        return;
    }
    
    auto modules = m_processManager.getModuleList();
    if (selected >= (int)modules.size()) return;
    
    updateLog("Exports for " + modules[selected].name + ": (export listing not implemented in this version)");
}

void MainFrame::onSetBreakpoint(wxCommandEvent& event) {
    updateLog("Hardware breakpoints require thread handle. Use DebugActiveProcess API for full implementation.");
}

void MainFrame::onClearBreakpoint(wxCommandEvent& event) {
    updateLog("Hardware breakpoints require thread handle. Use DebugActiveProcess API for full implementation.");
}

void MainFrame::onRefreshBreakpoints(wxCommandEvent& event) {
    m_breakpointsList->DeleteAllItems();
    updateLog("Breakpoint list cleared (requires thread context)");
}

void MainFrame::onChangeProtection(wxCommandEvent& event) {
    int selected = m_memoryList->GetFirstSelected();
    if (selected == -1) {
        updateLog("Select a memory region first");
        return;
    }
    
    auto regions = m_processManager.getMemoryRegions();
    if (selected >= (int)regions.size()) return;
    
    updateLog("Protection change: Use VirtualProtectEx API for full implementation");
}

void MainFrame::onAllocateMemory(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        updateLog("Select a process first");
        return;
    }
    
    updateLog("Memory allocation: Use VirtualAllocEx API for full implementation");
}

void MainFrame::onFreeMemory(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        updateLog("Select a process first");
        return;
    }
    
    updateLog("Memory free: Use VirtualFreeEx API for full implementation");
}

void MainFrame::onRefreshPEB(wxCommandEvent& event) {
    if (!m_processManager.isProcessOpen()) {
        updateLog("Select a process first");
        return;
    }
    
    PEBInfo peb = m_processManager.getPEBInfo();
    
    std::ostringstream oss;
    oss << "=== PEB Information ===" << "\n\n";
    oss << "PEB Address: 0x" << std::hex << peb.pebAddress << "\n";
    oss << "Image Base: 0x" << std::hex << peb.imageBaseAddress << "\n";
    oss << "Process ID: " << std::dec << peb.processId << "\n";
    oss << "Parent PID: " << std::dec << peb.parentProcessId << "\n";
    oss << "OS Version: " << std::dec << peb.OSMajorVersion << "." << peb.OSMinorVersion << "." << peb.OSBuildNumber << "\n";
    oss << "Being Debugged: " << (peb.beingDebugged ? "Yes" : "No") << "\n\n";
    oss << "Command Line: " << peb.CommandLine << "\n\n";
    oss << "Current Directory: " << peb.CurrentDirectory << "\n\n";
    oss << "Window Title: " << peb.WindowTitle << "\n\n";
    oss << "Loaded Modules (" << peb.loadedModules.size() << "):" << "\n";
    for (size_t i = 0; i < peb.loadedModules.size() && i < 20; i++) {
        oss << "  - " << peb.loadedModules[i] << "\n";
    }
    if (peb.loadedModules.size() > 20) {
        oss << "  ... and " << (peb.loadedModules.size() - 20) << " more" << "\n";
    }
    
    m_pebInfo->SetValue(oss.str());
    updateLog("PEB info refreshed");
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
