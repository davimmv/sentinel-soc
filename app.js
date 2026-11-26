(function () {
  const STORAGE_KEY = 'sentinel_soc_incidentes_v1';
  const SLA_HORAS = { Crítica: 1, Alta: 4, Média: 24, Baixa: 72 };
  const nowMs = Date.now();

  const iniciais = [
    {
      id: 'INC-1042',
      ativo: 'SRV-DB-01 (10.0.1.45)',
      ioc: '185.220.101.4',
      categoria: 'Tentativas de Brute Force SSH',
      severidade: 'Crítica',
      status: 'Aberto',
      analista: 'Davi Viana',
      data: '24/11/2026 14:10',
      criadoEm: new Date(nowMs - 95 * 60 * 1000).toISOString(),
      reconhecidoEm: null,
      mitigadoEm: null,
      historico: [
        { data: '24/11/2026 14:10', analista: 'Davi Viana', acao: 'Incidente criado com severidade Crítica e status Aberto.' }
      ]
    },
    {
      id: 'INC-1041',
      ativo: 'FW-EDGE-02 (192.168.0.1)',
      ioc: 'TCP:3389',
      categoria: 'Porta 3389 (RDP) Exposta Externamente',
      severidade: 'Alta',
      status: 'Em Contenção',
      analista: 'Davi Viana',
      data: '24/11/2026 11:35',
      criadoEm: new Date(nowMs - 140 * 60 * 1000).toISOString(),
      reconhecidoEm: new Date(nowMs - 122 * 60 * 1000).toISOString(),
      mitigadoEm: null,
      historico: [
        { data: '24/11/2026 11:35', analista: 'Davi Viana', acao: 'Incidente criado com severidade Alta e status Aberto.' },
        { data: '24/11/2026 11:50', analista: 'Davi Viana', acao: 'Status alterado de Aberto para Em Contenção.' }
      ]
    },
    {
      id: 'INC-1039',
      ativo: 'WKS-FIN-14 (10.0.4.22)',
      ioc: 'sha256:9f86d081884c7d65',
      categoria: 'Anexo Suspeito Bloqueado no Endpoint',
      severidade: 'Média',
      status: 'Mitigado',
      analista: 'Davi Viana',
      data: '23/11/2026 17:50',
      criadoEm: new Date(nowMs - 220 * 60 * 1000).toISOString(),
      reconhecidoEm: new Date(nowMs - 205 * 60 * 1000).toISOString(),
      mitigadoEm: new Date(nowMs - 170 * 60 * 1000).toISOString(),
      historico: [
        { data: '23/11/2026 17:50', analista: 'Davi Viana', acao: 'Incidente registrado e mitigado automaticamente no EDR.' }
      ]
    }
  ];

  let incidentes = [];
  let rascunhoPendente = null;

  function agoraFormatado() {
    return new Date().toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' });
  }

  function parseIsoValido(val) {
    if (!val || typeof val !== 'string') return null;
    const ms = Date.parse(val);
    return Number.isNaN(ms) ? null : new Date(ms).toISOString();
  }

  function formatarDuracaoMs(ms) {
    if (typeof ms !== 'number' || Number.isNaN(ms) || ms < 0) return '—';
    const totalMin = Math.round(ms / 60000);
    if (totalMin < 60) return `${totalMin}m`;
    const horas = Math.floor(totalMin / 60);
    const mins = totalMin % 60;
    return mins > 0 ? `${horas}h ${mins}m` : `${horas}h`;
  }

  function avaliarSla(inc) {
    const limiteHoras = SLA_HORAS[inc.severidade] || 24;
    const limiteMs = limiteHoras * 3600 * 1000;
    const criadoMs = parseIsoValido(inc.criadoEm) ? Date.parse(inc.criadoEm) : Date.now();
    const fimMs = inc.status === 'Mitigado' && parseIsoValido(inc.mitigadoEm)
      ? Date.parse(inc.mitigadoEm)
      : Date.now();
    const decorridoMs = Math.max(0, fimMs - criadoMs);
    const violado = decorridoMs > limiteMs;
    return {
      limiteHoras,
      decorridoMs,
      decorridoFmt: formatarDuracaoMs(decorridoMs),
      violado
    };
  }

  function calcularMetricasTempo() {
    const mttaAmostras = [];
    const mttrAmostras = [];
    let slaViolados = 0;

    incidentes.forEach((inc) => {
      const criadoMs = parseIsoValido(inc.criadoEm) ? Date.parse(inc.criadoEm) : null;
      const recIso = parseIsoValido(inc.reconhecidoEm) || (inc.status === 'Mitigado' ? parseIsoValido(inc.mitigadoEm) : null);
      if (criadoMs && recIso) {
        const diff = Date.parse(recIso) - criadoMs;
        if (diff >= 0) mttaAmostras.push(diff);
      }

      if (inc.status === 'Mitigado' && criadoMs && parseIsoValido(inc.mitigadoEm)) {
        const diffMttr = Date.parse(inc.mitigadoEm) - criadoMs;
        if (diffMttr >= 0) mttrAmostras.push(diffMttr);
      }

      if (avaliarSla(inc).violado) slaViolados += 1;
    });

    const media = (arr) => arr.length ? formatarDuracaoMs(arr.reduce((a, b) => a + b, 0) / arr.length) : '—';
    return {
      mtta: media(mttaAmostras),
      mttr: media(mttrAmostras),
      slaViolados
    };
  }

  function normalizarChave(val) {
    return String(val || '').trim().toLowerCase().replace(/\s+/g, ' ');
  }

  function normalizarEvento(ev, fallbackAnalista, fallbackData) {
    if (!ev || typeof ev !== 'object') return null;
    return {
      data: typeof ev.data === 'string' && ev.data.trim() ? ev.data.trim() : (fallbackData || agoraFormatado()),
      analista: typeof ev.analista === 'string' && ev.analista.trim() ? ev.analista.trim() : (fallbackAnalista || 'Sistema'),
      acao: typeof ev.acao === 'string' && ev.acao.trim() ? ev.acao.trim() : 'Evento registrado.'
    };
  }

  function normalizarIncidente(item, idx = 0) {
    const analista = typeof item?.analista === 'string' && item.analista.trim() ? item.analista.trim() : 'Davi Viana';
    const data = typeof item?.data === 'string' && item.data.trim() ? item.data.trim() : agoraFormatado();
    const status = ['Aberto', 'Em Contenção', 'Mitigado'].includes(item?.status) ? item.status : 'Aberto';
    const agoraIso = new Date().toISOString();
    const criadoEm = parseIsoValido(item?.criadoEm) || agoraIso;
    const reconhecidoEm = parseIsoValido(item?.reconhecidoEm) || (status !== 'Aberto' ? criadoEm : null);
    const mitigadoEm = parseIsoValido(item?.mitigadoEm) || (status === 'Mitigado' ? criadoEm : null);

    const rawHist = Array.isArray(item?.historico) ? item.historico.map((e) => normalizarEvento(e, analista, data)).filter(Boolean) : [];
    const hist = rawHist.length > 0
      ? rawHist
      : [{ data, analista, acao: 'Registro carregado sem histórico prévio.' }];

    return {
      id: typeof item?.id === 'string' && item.id.trim() ? item.id.trim() : `INC-${2000 + idx}`,
      ativo: typeof item?.ativo === 'string' && item.ativo.trim() ? item.ativo.trim() : 'Ativo não especificado',
      ioc: typeof item?.ioc === 'string' ? item.ioc.trim() : '',
      categoria: typeof item?.categoria === 'string' && item.categoria.trim() ? item.categoria.trim() : 'Categoria não informada',
      severidade: ['Baixa', 'Média', 'Alta', 'Crítica'].includes(item?.severidade) ? item.severidade : 'Média',
      status,
      analista,
      data,
      criadoEm,
      reconhecidoEm,
      mitigadoEm,
      historico: hist
    };
  }

  function encontrarCorrelatos(base, ignoreId = null, apenasAtivos = false) {
    const ativoKey = normalizarChave(base.ativo);
    const iocKey = normalizarChave(base.ioc);

    return incidentes.filter((cand) => {
      if (ignoreId && cand.id === ignoreId) return false;
      if (apenasAtivos && cand.status === 'Mitigado') return false;
      const matchAtivo = ativoKey && normalizarChave(cand.ativo) === ativoKey;
      const matchIoc = iocKey && normalizarChave(cand.ioc) === iocKey;
      return Boolean(matchAtivo || matchIoc);
    });
  }

  function setStatusPortabilidade(msg, isError = false) {
    const el = document.getElementById('status-portabilidade');
    if (!el) return;
    el.textContent = msg;
    el.className = isError ? 'text-xs text-red-400' : 'text-xs text-subtle';
  }

  function atualizarStatusRede() {
    const online = navigator.onLine !== false;
    const dot = document.getElementById('status-rede-dot');
    const txt = document.getElementById('status-rede-texto');
    if (dot) {
      dot.classList.toggle('bg-emerald-400', online);
      dot.classList.toggle('bg-amber-400', !online);
    }
    if (txt) txt.textContent = online ? 'Online' : 'Offline';
  }

  function limparAlertaDuplicidade() {
    rascunhoPendente = null;
    document.getElementById('alerta-duplicidade')?.classList.add('hidden');
    const listaEl = document.getElementById('lista-duplicados');
    if (listaEl) listaEl.textContent = '';
  }

  function exibirAlertaDuplicidade(rascunho, duplicadosAtivos) {
    rascunhoPendente = rascunho;
    const box = document.getElementById('alerta-duplicidade');
    const txt = document.getElementById('texto-duplicidade');
    const listaEl = document.getElementById('lista-duplicados');
    if (!box || !txt || !listaEl) return;

    txt.textContent = `Encontrado(s) ${duplicadosAtivos.length} incidente(s) ativo(s) com mesmo ativo ou IOC:`;
    listaEl.textContent = '';

    duplicadosAtivos.forEach((d) => {
      const motivos = [];
      if (normalizarChave(d.ativo) === normalizarChave(rascunho.ativo)) motivos.push('Ativo');
      if (rascunho.ioc && normalizarChave(d.ioc) === normalizarChave(rascunho.ioc)) motivos.push('IOC');
      const row = document.createElement('div');
      row.className = 'p-2.5 rounded-xl bg-card border border-line flex items-center justify-between text-xs';
      row.innerHTML = `<div><span class="font-semibold text-ink">${d.id}</span> <span class="text-subtle">(${d.status})</span><p class="text-[11px] text-muted">${d.categoria}</p></div><span class="text-[11px] text-amber-400 font-medium">${motivos.join(' + ')}</span>`;
      listaEl.appendChild(row);
    });

    box.classList.remove('hidden');
  }

  function inserirNovoIncidente(rascunho) {
    const stamp = agoraFormatado();
    const criadoEm = new Date().toISOString();
    const extraIoc = rascunho.ioc ? ` | IOC: ${rascunho.ioc}` : '';
    incidentes.unshift({
      id: 'INC-' + Math.floor(1000 + Math.random() * 9000),
      ativo: rascunho.ativo,
      ioc: rascunho.ioc,
      categoria: rascunho.categoria,
      severidade: rascunho.severidade,
      status: 'Aberto',
      analista: rascunho.analista,
      data: stamp,
      criadoEm,
      reconhecidoEm: null,
      mitigadoEm: null,
      historico: [
        { data: stamp, analista: rascunho.analista, acao: `Incidente criado (${rascunho.severidade}, Aberto)${extraIoc}.` }
      ]
    });
    salvar();
    limparAlertaDuplicidade();
    document.getElementById('form-create')?.reset();
    window.navegarPara('list');
  }

  function correlacionarNoExistente(rascunho, alvoId) {
    const idx = incidentes.findIndex((i) => i.id === alvoId);
    if (idx === -1) return;
    const atual = normalizarIncidente(incidentes[idx], idx);
    const stamp = agoraFormatado();
    const agoraIso = new Date().toISOString();
    const iocMsg = rascunho.ioc ? ` [IOC: ${rascunho.ioc}]` : '';
    const novaSeveridade = (rascunho.severidade === 'Crítica' && atual.severidade !== 'Crítica') ? 'Crítica' : atual.severidade;

    incidentes[idx] = {
      ...atual,
      ioc: atual.ioc || rascunho.ioc,
      severidade: novaSeveridade,
      reconhecidoEm: atual.reconhecidoEm || agoraIso,
      historico: [
        ...atual.historico,
        {
          data: stamp,
          analista: rascunho.analista,
          acao: `Evento correlacionado (deduplicado): "${rascunho.categoria}" (${rascunho.severidade})${iocMsg}.`
        }
      ]
    };

    salvar();
    limparAlertaDuplicidade();
    document.getElementById('form-create')?.reset();
    window.abrirEdicao(atual.id);
  }

  function exportarJson() {
    const payload = {
      sistema: 'Sentinel SOC',
      versao: 2,
      exportadoEm: agoraFormatado(),
      metricasTempo: calcularMetricasTempo(),
      totalIncidentes: incidentes.length,
      incidentes
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const isoDate = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `sentinel-soc-incidentes-${isoDate}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setStatusPortabilidade(`Exportados ${incidentes.length} incidente(s) com trilha de auditoria e métricas.`);
  }

  function importarJsonArquivo(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result || ''));
        const listaBruta = Array.isArray(parsed)
          ? parsed
          : (Array.isArray(parsed?.incidentes) ? parsed.incidentes : null);

        if (!listaBruta) {
          setStatusPortabilidade('JSON inválido: esperado um array ou objeto com "incidentes".', true);
          return;
        }

        incidentes = listaBruta.map((item, i) => normalizarIncidente(item, i));
        salvar();
        setStatusPortabilidade(`Importados ${incidentes.length} incidente(s) com trilha de auditoria.`);
      } catch (_) {
        setStatusPortabilidade('Falha ao ler JSON: arquivo malformado.', true);
      }
    };
    reader.onerror = () => setStatusPortabilidade('Erro ao ler o arquivo selecionado.', true);
    reader.readAsText(file, 'utf-8');
  }

  function carregar() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      const parsed = raw ? JSON.parse(raw) : null;
      incidentes = Array.isArray(parsed) ? parsed.map((it, i) => normalizarIncidente(it, i)) : iniciais.map((it, i) => normalizarIncidente(it, i));
    } catch (_) {
      incidentes = iniciais.map((it, i) => normalizarIncidente(it, i));
    }
    if (!localStorage.getItem(STORAGE_KEY)) salvar();
  }

  function salvar() {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(incidentes)); } catch (_) { }
    atualizarDashboard();
    renderizarLista();
  }

  window.navegarPara = function (tela) {
    ['home', 'list', 'create', 'edit'].forEach((t) => {
      const el = document.getElementById('view-' + t);
      if (el) el.classList.toggle('hidden', t !== tela);
    });
    ['home', 'list', 'create'].forEach((n) => {
      const btn = document.getElementById('nav-' + n);
      if (!btn) return;
      const ativo = n === tela || (tela === 'edit' && n === 'list');
      btn.classList.toggle('text-blue-400', ativo);
      btn.classList.toggle('text-slate-400', !ativo);
    });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  function atualizarDashboard() {
    const total = incidentes.length;
    const criticos = incidentes.filter((i) => i.severidade === 'Crítica' && i.status !== 'Mitigado').length;
    const mitigados = incidentes.filter((i) => i.status === 'Mitigado').length;
    const tempos = calcularMetricasTempo();
    const setTxt = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = String(v); };

    setTxt('stat-total', total);
    setTxt('stat-criticos', criticos);
    setTxt('stat-resolvidos', mitigados);
    setTxt('stat-mtta', tempos.mtta);
    setTxt('stat-mttr', tempos.mttr);
    setTxt('stat-sla-violado', tempos.slaViolados);

    const alertEl = document.getElementById('home-recent-alert');
    if (!alertEl) return;
    alertEl.textContent = '';
    const crit = incidentes.find((i) => i.severidade === 'Crítica' && i.status !== 'Mitigado');
    if (!crit) {
      alertEl.textContent = 'Nenhum incidente crítico ativo no momento.';
      return;
    }
    const card = document.createElement('div');
    card.className = 'cursor-pointer p-3 rounded-xl bg-card border border-line hover:border-zinc-700 space-y-1';
    card.onclick = () => window.abrirEdicao(crit.id);
    card.innerHTML = `<div class="flex items-center justify-between text-xs"><span class="text-red-400 font-medium">${crit.id} · ${crit.severidade}</span><span class="text-subtle">${crit.status}</span></div><p class="text-sm font-semibold text-ink">${crit.ativo}</p><p class="text-xs text-muted">${crit.categoria}</p>`;
    alertEl.appendChild(card);
  }

  function filtrados() {
    const q = (document.getElementById('filtro-busca')?.value || '').trim().toLowerCase();
    const sev = document.getElementById('filtro-severidade')?.value || 'Todas';
    const st = document.getElementById('filtro-status')?.value || 'Todos';
    return incidentes.filter((i) => {
      if (sev !== 'Todas' && i.severidade !== sev) return false;
      if (st !== 'Todos' && i.status !== st) return false;
      if (q && !(i.id + ' ' + i.ativo + ' ' + i.ioc + ' ' + i.categoria + ' ' + i.analista).toLowerCase().includes(q)) return false;
      return true;
    });
  }

  function renderizarLista() {
    const container = document.getElementById('lista-incidentes');
    if (!container) return;
    const lista = filtrados();
    const cnt = document.getElementById('contador-filtros');
    if (cnt) cnt.textContent = `${lista.length} de ${incidentes.length} exibidos`;

    container.textContent = '';
    if (lista.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'p-6 bg-surface border border-line rounded-2xl text-center';
      empty.innerHTML = `<p class="text-sm text-muted">${incidentes.length === 0 ? 'Nenhum incidente registrado na fila.' : 'Nenhum incidente corresponde aos filtros selecionados.'}</p>`;
      container.appendChild(empty);
      return;
    }

    lista.forEach((inc) => {
      const sevCls = inc.severidade === 'Crítica' ? 'bg-red-500/15 text-red-400 border border-red-500/30' : 'bg-card text-muted border border-line';
      const stCls = inc.status === 'Mitigado' ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' : 'bg-card text-ink border border-line';
      const sla = avaliarSla(inc);
      const slaCls = sla.violado
        ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
        : 'bg-card text-subtle border border-line';
      const slaLabel = sla.violado ? `SLA Estourado (${sla.decorridoFmt}/${sla.limiteHoras}h)` : `SLA OK (${sla.decorridoFmt}/${sla.limiteHoras}h)`;
      const eventosQtd = Array.isArray(inc.historico) ? inc.historico.length : 1;
      const relQtd = encontrarCorrelatos(inc, inc.id, false).length;
      const relBadge = relQtd > 0 ? `<span class="px-2 py-0.5 rounded-md text-[11px] font-medium bg-amber-500/15 text-amber-400 border border-amber-500/30">${relQtd} correlato(s)</span>` : '';
      const iocLinha = inc.ioc ? `<p class="text-xs text-subtle mt-1">IOC: <span class="text-muted">${inc.ioc}</span></p>` : '';

      const item = document.createElement('div');
      item.className = 'cursor-pointer p-4 bg-surface border border-line hover:bg-card rounded-2xl space-y-3';
      item.onclick = () => window.abrirEdicao(inc.id);
      item.innerHTML = `<div class="flex items-center justify-between gap-2"><span class="text-xs text-subtle">${inc.id} · ${eventosQtd} ev</span><div class="flex items-center gap-1.5 flex-wrap justify-end">${relBadge}<span class="px-2 py-0.5 rounded-md text-[11px] font-medium ${sevCls}">${inc.severidade}</span><span class="px-2 py-0.5 rounded-md text-[11px] font-medium ${stCls}">${inc.status}</span></div></div><div><h3 class="font-semibold text-[15px] text-ink">${inc.ativo}</h3><p class="text-sm text-muted mt-0.5">${inc.categoria}</p>${iocLinha}</div><div class="pt-2.5 border-t border-line flex items-center justify-between gap-2 text-xs text-subtle"><span class="px-2 py-0.5 rounded-md text-[11px] ${slaCls}">${slaLabel}</span><span class="text-ink font-medium shrink-0">Auditar →</span></div>`;
      container.appendChild(item);
    });
  }

  function renderizarResumoSlaEdit(inc) {
    const box = document.getElementById('resumo-sla-edit');
    if (!box || !inc) return;
    const sla = avaliarSla(inc);
    const badgeCls = sla.violado ? 'text-amber-400 font-semibold' : 'text-emerald-400 font-semibold';
    const estadoTxt = sla.violado ? 'SLA Estourado' : 'Dentro do SLA';
    box.innerHTML = `<div><span class="text-muted">Janela (${inc.severidade}):</span> <span class="text-ink font-medium">${sla.limiteHoras}h</span> · <span class="text-muted">Tempo:</span> <span class="text-ink font-medium">${sla.decorridoFmt}</span></div><span class="${badgeCls}">${estadoTxt}</span>`;
  }

  function renderizarCorrelacoes(inc) {
    const box = document.getElementById('lista-correlacionados');
    const cnt = document.getElementById('correlacao-contador');
    if (!box || !inc) return;
    const rels = encontrarCorrelatos(inc, inc.id, false);
    if (cnt) cnt.textContent = `${rels.length} relacionado(s)`;
    box.textContent = '';

    if (rels.length === 0) {
      box.innerHTML = '<p class="text-xs text-subtle">Nenhum outro incidente compartilha este ativo ou IOC.</p>';
      return;
    }

    rels.forEach((r) => {
      const motivos = [];
      if (normalizarChave(r.ativo) === normalizarChave(inc.ativo)) motivos.push('Ativo');
      if (inc.ioc && normalizarChave(r.ioc) === normalizarChave(inc.ioc)) motivos.push('IOC');

      const row = document.createElement('div');
      row.className = 'cursor-pointer p-2.5 rounded-xl bg-card border border-line hover:border-zinc-700 flex items-center justify-between gap-2 text-xs';
      row.onclick = () => window.abrirEdicao(r.id);
      row.innerHTML = `<div><span class="font-semibold text-ink">${r.id}</span> <span class="text-subtle">· ${r.status}</span><p class="text-muted mt-0.5">${r.categoria}</p></div><span class="text-[11px] text-brand font-medium shrink-0">${motivos.join(' + ')} →</span>`;
      box.appendChild(row);
    });
  }

  function renderizarAuditoria(inc) {
    const box = document.getElementById('trilha-auditoria');
    const cnt = document.getElementById('auditoria-contador');
    if (!box || !inc) return;
    const eventos = Array.isArray(inc.historico) ? inc.historico : [];
    if (cnt) cnt.textContent = `${eventos.length} evento(s)`;
    box.textContent = '';

    [...eventos].reverse().forEach((ev) => {
      const row = document.createElement('div');
      row.className = 'p-3 rounded-xl bg-card border border-line space-y-1';
      row.innerHTML = `<div class="flex items-center justify-between text-[11px] text-subtle"><span>${ev.data}</span><span class="text-ink font-medium">${ev.analista}</span></div><p class="text-xs text-muted leading-relaxed">${ev.acao}</p>`;
      box.appendChild(row);
    });
  }

  function registrarServiceWorker() {
    if (!('serviceWorker' in navigator)) return;
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('./sw.js').catch((err) => {
        console.error('Falha ao registrar Service Worker:', err);
      });
    });
  }

  window.limparFiltros = function () {
    const b = document.getElementById('filtro-busca');
    const s = document.getElementById('filtro-severidade');
    const t = document.getElementById('filtro-status');
    if (b) b.value = '';
    if (s) s.value = 'Todas';
    if (t) t.value = 'Todos';
    renderizarLista();
  };

  window.abrirEdicao = function (id) {
    const inc = incidentes.find((i) => i.id === id);
    if (!inc) return;
    const norm = normalizarIncidente(inc);
    document.getElementById('edit-id').value = norm.id;
    document.getElementById('edit-id-display').value = norm.id;
    document.getElementById('edit-ativo').value = norm.ativo;
    document.getElementById('edit-ioc').value = norm.ioc || '';
    document.getElementById('edit-categoria').value = norm.categoria;
    document.getElementById('edit-severidade').value = norm.severidade;
    document.getElementById('edit-status').value = norm.status;
    document.getElementById('edit-analista').value = norm.analista;
    const notaEl = document.getElementById('edit-nota-auditoria');
    if (notaEl) notaEl.value = '';
    renderizarResumoSlaEdit(norm);
    renderizarCorrelacoes(norm);
    renderizarAuditoria(norm);
    window.navegarPara('edit');
  };

  window.abrirModalDelete = () => document.getElementById('modal-delete')?.classList.remove('hidden');
  window.fecharModalDelete = () => document.getElementById('modal-delete')?.classList.add('hidden');
  window.confirmarExclusao = function () {
    const id = document.getElementById('edit-id').value;
    incidentes = incidentes.filter((i) => i.id !== id);
    salvar();
    window.fecharModalDelete();
    window.navegarPara('list');
  };

  function boot() {
    carregar();
    atualizarDashboard();
    renderizarLista();
    atualizarStatusRede();
    window.navegarPara('home');

    window.addEventListener('online', atualizarStatusRede);
    window.addEventListener('offline', atualizarStatusRede);

    document.getElementById('btn-exportar-json')?.addEventListener('click', exportarJson);
    const fileInput = document.getElementById('input-importar-json');
    document.getElementById('btn-importar-json')?.addEventListener('click', () => fileInput?.click());
    fileInput?.addEventListener('change', (e) => {
      const f = e.target.files?.[0];
      if (f) importarJsonArquivo(f);
      e.target.value = '';
    });

    ['create-ativo', 'create-ioc'].forEach((id) => {
      document.getElementById(id)?.addEventListener('input', limparAlertaDuplicidade);
    });

    document.getElementById('btn-forcar-criacao')?.addEventListener('click', () => {
      if (rascunhoPendente) inserirNovoIncidente(rascunhoPendente);
    });

    document.getElementById('btn-correlacionar-existente')?.addEventListener('click', () => {
      if (!rascunhoPendente) return;
      const dupAtivos = encontrarCorrelatos(rascunhoPendente, null, true);
      if (dupAtivos.length > 0) {
        correlacionarNoExistente(rascunhoPendente, dupAtivos[0].id);
      } else {
        inserirNovoIncidente(rascunhoPendente);
      }
    });

    document.getElementById('filtro-busca')?.addEventListener('input', renderizarLista);
    document.getElementById('filtro-severidade')?.addEventListener('change', renderizarLista);
    document.getElementById('filtro-status')?.addEventListener('change', renderizarLista);
    document.getElementById('btn-limpar-filtros')?.addEventListener('click', window.limparFiltros);

    document.getElementById('form-create')?.addEventListener('submit', (e) => {
      e.preventDefault();
      const rascunho = {
        ativo: document.getElementById('create-ativo').value.trim(),
        ioc: document.getElementById('create-ioc').value.trim(),
        categoria: document.getElementById('create-categoria').value.trim(),
        severidade: document.getElementById('create-severidade').value,
        analista: document.getElementById('create-analista').value.trim()
      };

      const dupAtivos = encontrarCorrelatos(rascunho, null, true);
      if (dupAtivos.length > 0) {
        exibirAlertaDuplicidade(rascunho, dupAtivos);
        return;
      }

      inserirNovoIncidente(rascunho);
    });

    document.getElementById('form-edit')?.addEventListener('submit', (e) => {
      e.preventDefault();
      const id = document.getElementById('edit-id').value;
      const idx = incidentes.findIndex((i) => i.id === id);
      if (idx !== -1) {
        const anterior = normalizarIncidente(incidentes[idx], idx);
        const novoAtivo = document.getElementById('edit-ativo').value.trim();
        const novoIoc = document.getElementById('edit-ioc').value.trim();
        const novaCategoria = document.getElementById('edit-categoria').value.trim();
        const novaSeveridade = document.getElementById('edit-severidade').value;
        const novoStatus = document.getElementById('edit-status').value;
        const novoAnalista = document.getElementById('edit-analista').value.trim();
        const nota = (document.getElementById('edit-nota-auditoria')?.value || '').trim();
        const agoraIso = new Date().toISOString();

        const reconhecidoEm = anterior.reconhecidoEm || (novoStatus !== 'Aberto' ? agoraIso : null);
        const mitigadoEm = novoStatus === 'Mitigado'
          ? (anterior.mitigadoEm || agoraIso)
          : null;

        const mudancas = [];
        if (anterior.ativo !== novoAtivo) mudancas.push(`ativo: "${anterior.ativo}" -> "${novoAtivo}"`);
        if ((anterior.ioc || '') !== novoIoc) mudancas.push(`ioc: "${anterior.ioc || '-'}" -> "${novoIoc || '-'}"`);
        if (anterior.categoria !== novaCategoria) mudancas.push(`categoria: "${anterior.categoria}" -> "${novaCategoria}"`);
        if (anterior.severidade !== novaSeveridade) mudancas.push(`severidade: ${anterior.severidade} -> ${novaSeveridade}`);
        if (anterior.status !== novoStatus) mudancas.push(`status: ${anterior.status} -> ${novoStatus}`);
        if (anterior.analista !== novoAnalista) mudancas.push(`analista: ${anterior.analista} -> ${novoAnalista}`);

        const partesAcao = [];
        if (mudancas.length > 0) partesAcao.push(`Alterado ${mudancas.join('; ')}.`);
        if (nota) partesAcao.push(`Nota: ${nota}`);
        if (partesAcao.length === 0) partesAcao.push('Registro revisado sem alteração de campos.');

        const atualizado = {
          ...anterior,
          ativo: novoAtivo,
          ioc: novoIoc,
          categoria: novaCategoria,
          severidade: novaSeveridade,
          status: novoStatus,
          analista: novoAnalista,
          reconhecidoEm,
          mitigadoEm,
          historico: [
            ...anterior.historico,
            { data: agoraFormatado(), analista: novoAnalista, acao: partesAcao.join(' ') }
          ]
        };

        incidentes[idx] = atualizado;
        salvar();
      }
      window.navegarPara('list');
    });

    registrarServiceWorker();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
