# Memory Scanner & Writer

Aplicativo GUI para escanear e modificar valores na memória de processos em execução (x86 e x64). Semelhante ao Cheat Engine, feito em C++ com wxWidgets.

![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat&logo=windows&logoColor=white)

## Features

### Scanner (Tab Principal)
- **Lista de processos** — Exibe todos os processos em execução com PID e arquitetura (x86/x64)
- **Scanner de memória** — Busca por valores em todos os tipos de dados
- **Filtros** — "Exact", "Increased", "Decreased", "Unchanged"
- **Writer** — Modifica valores nos endereços encontrados
- **Tipos suportados** — int8, int16, int32, int64, float, double, byte, string, wstring, pointer, aob
- **Progresso** — Barra de progresso durante scans
- **Copy Address** — Copia endereço selecionado para clipboard
- **Save/Load** — Salva e carrega resultados em JSON

### AOB Scanner (Array of Bytes)
- **Busca por padrões de bytes** — Encontra sequências de bytes específicas
- **Wildcards** — Use `??` para bytes desconhecidos
- **Exemplo**: `48 8B 05 ?? ?? ?? ??` encontra `mov rax, [rax+????????]`

### Pointer Scanner
- **Encontra caminhos de ponteiros** — Dado um endereço, encontra ponteiros estáticos
- **Max Level** — Quantos níveis de ponteiros seguir
- **Max Results** — Limite de resultados
- **Útil para** — Encontrar endereços que não mudam entre execuções

### Memory Dump
- **Exporta memória para .bin** — Salva região de memória em arquivo
- **Parâmetros** — Endereço, tamanho, nome do arquivo
- **Útil para** — Analisar dados em hex editor

### DLL Injection
- **Injeta DLL no processo** — Carrega código customizado
- **Use com cautela** — Apenas em processos que você controla

### Configurações
- **Float Precision** — Ajusta casas decimais para floats
- **Module Filters** — Whitelist/Blacklist de módulos para escanear
- **Log de operações** — Registro de todas as ações

### Thread Viewer (Tab)
- **Lista todas as threads** do processo selecionado
- **TID, Prioridade, Estado, TEB Address**
- **Suspend/Resume** — Pausa threads individuais ou todo o processo

### Module Viewer (Tab)
- **Lista todos os módulos** (DLLs/EXEs) carregados
- **Base Address, Size, Path completo**
- **Useful for** — Identificar módulos do jogo/app

### Hardware Breakpoints (Tab)
- **Debug Registers (DR0-DR3)** — Breakpoints a nível de hardware
- **Tipos** — Execute, Write, Read/Write
- **Limite** — 4 breakpoints simultâneos por thread

### Memory Regions (Tab)
- **Lista todas as regiões** de memória do processo
- **Proteção, Estado, Tipo** — PAGE_READWRITE, MEM_COMMIT, etc.
- **Change Protection** — Altera flags de proteção
- **Allocate/Free** — Aloca ou libera memória no processo

### PEB Info (Tab)
- **Process Environment Block** — Informações do sistema sobre o processo
- **Command Line, Current Directory, Window Title**
- **Loaded Modules** — Lista de módulos carregados
- **Being Debugged** — Flag que indica se está sendo debugado

## Requisitos

- **Windows 10/11** (64-bit)
- **Visual Studio 2022** com "Desktop development with C++"
- **Git** instalado
- **PowerShell 5.0+**

## Como Compilar

### 1. Clone o repositório

```bash
git clone https://github.com/IuryAlmeidaDev/Testando_as_manha.git
cd Testando_as_manha/MemoryScannerWriter
```

### 2. Instale o vcpkg

O vcpkg é um gerenciador de pacotes C++ da Microsoft.

```powershell
# No diretório do projeto
git clone https://github.com/microsoft/vcpkg.git
.\vcpkg\bootstrap-vcpkg.bat
```

### 3. Configure o CMake com o vcpkg

```powershell
cmake -B build -DCMAKE_TOOLCHAIN_FILE="./vcpkg/scripts/buildsystems/vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows
```

### 4. Compile o projeto

```powershell
cmake --build build --config Release
```

O executável será gerado em:
```
build\Release\MemoryScannerWriter.exe
```

### 5. (Opcional) Gerar arquivos do Visual Studio

```powershell
cmake -B build -DCMAKE_TOOLCHAIN_FILE="./vcpkg/scripts/buildsystems/vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows -G "Visual Studio 17 2022"
```

Depois abra `build\MemoryScannerWriter.sln` no Visual Studio e compile pelo IDE.

## Como Usar

### Importante: Executar como Administrador

Este programa precisa de **privilégios de administrador** para ler/escrever na memória de outros processos.

1. Clique com botão direito no `.exe`
2. Selecione **"Executar como administrador"**

Ou clique com botão direito no atalho → Propriedades → Avançado → "Executar como administrador"

### Guia por Aba

#### Tab Scanner

1. **Selecione um processo**
   - Escolha na lista dropdown o processo que deseja analisar
   - O PID e arquitetura (x86/x64) são exibidos

2. **Primeiro Scan**
   - Digite o valor que procura (ex: `100`)
   - Selecione o tipo de dado (ex: `int32`)
   - Clique em **"First Scan"**
   - Resultados aparecerão na lista

3. **Próximos Scans (Filtros)**
   - Altere o valor no processo alvo
   - Digite o novo valor
   - Selecione o filtro:
     - **Exact** — valor igual
     - **Increased** — valor aumentou
     - **Decreased** — valor diminuiu
     - **Unchanged** — valor não mudou
   - Clique em **"Next Scan"**

4. **Modificar Valor (Writer)**
   - Selecione um endereço na lista de resultados
   - Digite o novo valor
   - Clique em **"Write"**

5. **Reset**
   - Clique em **"Reset"** para limpar os resultados

6. **Salvar Resultados**
   - Clique em **"Save Results"** para salvar em JSON
   - Use **"Load Results"** para carregar depois

#### Tab AOB Scan

1. Selecione um processo
2. Digite o padrão de bytes (ex: `48 8B 05 ?? ?? ?? ??`)
3. Clique em **"AOB Scan"**

**Formato AOB:**
- Bytes hex normais: `48 8B 05`
- Wildcards: `??` para byte desconhecido
- Espaços e hífens são ignorados

#### Tab Pointer Scan

1. Selecione um processo
2. Digite o endereço alvo em hexadecimal (ex: `0x140012345`)
3. Ajuste **Max Level** (níveis de ponteiros)
4. Ajuste **Max Results** (limite de resultados)
5. Clique em **"Scan for Pointers"**

**Isso encontra endereços estáticos que apontam para o endereço especificado.**

#### Tab Memory Dump

1. Digite o endereço inicial em hex (ex: `0x140000000`)
2. Digite o tamanho em bytes (ex: `4096`)
3. Digite o nome do arquivo (ex: `dump.bin`)
4. Clique em **"Dump"**

O arquivo será salvo no diretório do executável.

#### Tab Tools

- **DLL Injection**: Digite o caminho da DLL e clique em "Inject DLL"
- **Info AOB**: Exemplos de padrões AOB

#### Tab Settings

- **Float Precision**: Número de casas decimais para floats (1-15)
- **Module Filters**:
  - **Whitelist**: Escaneia apenas módulos listados (vazio = todos)
  - **Blacklist**: Pula módulos listados
  - Útil para pular `ntdll.dll`, `kernel32.dll`, etc.

## Estrutura do Projeto

```
MemoryScannerWriter/
├── CMakeLists.txt          # Configuração CMake
├── vcpkg.json              # Dependências (wxWidgets)
├── README.md               # Este arquivo
├── src/
│   ├── main.cpp            # Entry point wxWidgets
│   ├── gui/
│   │   ├── MainFrame.h     # Declaração da janela principal
│   │   └── MainFrame.cpp   # Implementação da GUI
│   ├── engine/
│   │   ├── ProcessManager.h   # Lista e abre processos
│   │   ├── ProcessManager.cpp
│   │   ├── MemoryEngine.h     # RPM/WPM e scanner
│   │   └── MemoryEngine.cpp
│   └── models/
│       ├── ScanResult.h    # Modelo de resultado de scan
│       └── ScanResult.cpp
└── build/                  # Diretório de build (gitignored)
```

## Resolução de Problemas

### "Failed to open process"

- Execute o programa como **Administrador**
- Alguns processos têm proteção adicional e não podem ser acessados

### "Access Denied" ao escanear

- Normal para regiões protegidas do sistema
- O scanner pula automaticamente páginas inacessíveis

### Scan não encontra valores

- Verifique se selecionou o **tipo de dado correto**
- Strings precisam ser **exatamente** iguais (case-sensitive)
- Alguns jogos usam proteção contra cheats

### Pointer Scan não encontra nada

- Tente aumentar **Max Level**
- Nem todos os endereços têm ponteiros apontando para eles
- Verifique se o endereço está correto

### DLL Injection falha

- A DLL deve ser compilada para a arquitetura do processo (x86/x64)
- Use o caminho completo da DLL
- Algumas DLLs têm dependências que precisam estar disponíveis

### Prompt UAC bloqueando

- Execute como Administrador desde o início
- Desabilite o UAC temporariamente (não recomendado)

## Exemplos Práticos

### Encontrar pontuação em jogo

1. Abra o jogo e note a pontuação
2. Abra o scanner, selecione o jogo
3. Digite a pontuação, tipo `int32`, clique **First Scan**
4. Altere a pontuação no jogo
5. Digite o novo valor, filtro `Exact`, clique **Next Scan**
6. Repita até sobrar poucos resultados
7. Selecione, digite novo valor, clique **Write**

### Encontrar money/health com AOB

1. Encontre o valor na memória
2. Use um debugger para ver o código que modifica o valor
3. Copie os bytes da instrução (ex: `48 8B 05 ?? ?? ?? ??`)
4. Use AOB Scan para encontrar essa instrução em futuras execuções

### Encontrar endereço estático com Pointer Scan

1. Encontre o endereço dinâmico do valor
2. Abra Pointer Scan
3. Digite o endereço em hex
4. Ajuste Max Level para 3-5
5. Aguarde o scan encontrar o ponteiro base

## Disclaimer

Esta ferramenta é para **fins educacionais e debugging legítimo**. Use com responsabilidade e apenas em processos que você tem direito de modificar.

## Licença

MIT License
