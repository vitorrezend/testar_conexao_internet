# Monitor de Estabilidade de Internet (Rust)

Uma aplicação leve em Rust para monitorar a estabilidade da rede testando múltiplos endpoints, acompanhando latência, resolução de DNS e contexto de rede (IP/SSID).

## Funcionalidades
- **Organização de Logs Diários**: Os logs são organizados automaticamente em pastas por data (ex: `2026-02-10/`).
- **Diagnósticos Detalhados**:
    - `connectivity.txt`: RTT HTTP, tempo de resolução DNS e conectividade direta por IP.
    - `network_context.txt`: IP Interno, Gateway, IP Externo e SSID do Wi-Fi.
    - `incidents.txt`: Log dedicado para quedas e restaurações com rastreamento de duração.
- **Modo Silencioso**: Inicia oculto na bandeja do sistema (área de notificação).
- **Integração com a Bandeja (Tray)**:
    - Alternar visibilidade do console.
    - Acesso rápido às pastas de logs.
    - Monitoramento persistente em segundo plano.

## Como Executar
1. Certifique-se de ter o Rust instalado.
2. Clone o repositório.
3. Execute com:
   ```bash
   cargo run
   ```
4. Para a versão de produção otimizada:
   ```bash
   cargo build --release
   ```
   O executável estará em `target/release/testar_internet.exe`.

## Dependências
- `tokio`: Runtime assíncrono.
- `reqwest`: Cliente HTTP para testes e descoberta de IP externo.
- `tray-icon` & `tao`: Gerenciamento da bandeja do sistema e loop de eventos.
- `windows-sys`: API do Windows para gerenciamento de janelas.
- `chrono`: Rotação diária e data/hora.
