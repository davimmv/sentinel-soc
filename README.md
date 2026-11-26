# Sentinel SOC — Incident & Asset Tracker (PWA)

Aplicação web progressiva (PWA) offline-first para triagem, monitoramento, correlação e resposta a incidentes de cibersegurança em operações de SOC.

**Demo online (HTTPS):** [davimmv.github.io/sentinel-soc](https://davimmv.github.io/sentinel-soc/)

---

## Funcionalidades Principais

- **Gestão Completa de Incidentes (CRUD):** Registro, edição, classificação por severidade (`Crítica`, `Alta`, `Média`, `Baixa`) e controle de ciclo de vida (`Aberto`, `Em Contenção`, `Mitigado`).
- **Métricas Operacionais e SLA:** Cálculo automático em tempo real de **MTTA** (Mean Time to Acknowledge), **MTTR** (Mean Time to Resolve) e monitoramento de violação de SLA por severidade:
  - **Crítica:** 1h
  - **Alta:** 4h
  - **Média:** 24h
  - **Baixa:** 72h
- **Deduplicação e Correlação por Ativo / IOC:** Detecção automática de incidentes ativos que compartilham o mesmo hostname/IP ou Indicador de Comprometimento (IP origem, domínio, porta, hash ou CVE), permitindo anexar novos eventos ao incidente existente ou manter registros correlacionados.
- **Trilha de Auditoria:** Histórico cronológico imutável por incidente registrando criação, alterações de campos, mudanças de status, correlações e observações do analista.
- **Busca e Filtragem Dinâmica:** Filtro combinado por texto livre (ID, ativo, IOC, ameaça ou analista), severidade e status.
- **Portabilidade de Dados (JSON):** Exportação e importação da fila completa com trilha de auditoria e métricas consolidadas.
- **Arquitetura PWA Offline-First:** Persistência local via `localStorage`, instalação nativa em modo `standalone` (`manifest.json`) e cache de ativos via Service Worker (`sw.js`).

---

## Estrutura do Projeto

```text
sentinel-soc/
├── index.html      # Estrutura semântica SPA mobile-first e layout escuro
├── app.js          # Regras de negócio, SLA/MTTA/MTTR, correlação, auditoria e estado
├── manifest.json   # Metadados de instalação PWA (standalone, ícones e tema)
├── sw.js           # Service Worker com cache estático e fallback offline
└── README.md       # Documentação do projeto
