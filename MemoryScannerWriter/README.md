# Memory Scanner & Writer

Aplicativo GUI para escanear e modificar valores na memória de processos em execução (x86 e x64). Semelhante ao Cheat Engine, feito em C++ com wxWidgets.

![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat&logo=windows&logoColor=white)

## Features

- **Lista de processos** — Exibe todos os processos em execução com PID e arquitetura (x86/x64)
- **Scanner de memória** — Busca por valores em todos os tipos de dados
- **Filtros** — "Exact", "Increased", "Decreased", "Unchanged"
- **Writer** — Modifica valores nos endereços encontrados
- **Tipos suportados** — int8, int16, int32, int64, float, double, byte, string

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

### Passo a passo

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
   - Clique em **"Write to Selected"**

5. **Reset**
   - Clique em **"Reset"** para limpar os resultados e começar novamente

## Estrutura do Projeto

```
MemoryScannerWriter/
├── CMakeLists.txt          # Configuração CMake
├── vcpkg.json              # Dependências (wxWidgets)
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

### Prompt UAC bloqueando

- Execute como Administrador desde o início
- Desabilite o UAC temporariamente (não recomendado)

## Disclaimer

Este ferramenta é para **fins educacionais e debugging legítimo**. Use com responsabilidade e apenas em processos que você tem direito de modificar.

## Licença

MIT License
