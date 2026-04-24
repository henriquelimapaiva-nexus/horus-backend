require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const helmet = require("helmet");
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'nexus_secret_key_2026';

// TRUST PROXY - NECESSÁRIO PARA RENDER
app.set('trust proxy', 1);

// ========================================
// 🛡️ CAMADA DE SEGURANÇA (HELMET & CORS)
// ========================================
app.use(helmet()); 

app.use(cors({
    origin: process.env.CLIENT_URL || "*", 
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

// ========================================
// 🕒 FUNÇÃO AUXILIAR PARA DATA LOCAL BRASIL
// ========================================
function getDataLocalBrasil() {
  const agora = new Date();
  const offset = -3; // Brasil (UTC-3)
  const dataLocal = new Date(agora.getTime() + (offset * 60 * 60 * 1000));
  return dataLocal.toISOString().split('T')[0];
}

// ========================================
// 🚦 GESTÃO DE TRÁFEGO (RATE LIMITING)
// ========================================
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { erro: "Muitas requisições. Tente novamente em 15 minutos." },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        // Usa o IP real quando estiver atrás de proxy (Render)
        return req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
    }
});

// ========================================
// 🔌 CONEXÃO COM O BANCO (POSTGRESQL)
// ========================================
const pool = new Pool({
    connectionString: process.env.DB_CONNECTION_STRING,
    ssl: process.env.DB_CONNECTION_STRING?.includes("neon.tech") 
        ? { rejectUnauthorized: false } 
        : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 15000,
});

pool.on('error', (err) => {
    console.error('❌ Erro Crítico no Pool de Dados:', err.message);
});

// ========================================
// 🔐 SEGURANÇA E CRIPTOGRAFIA (bloco 2)
// ========================================
const fetch = require('node-fetch'); 

// Validação de segurança (A variável JWT_SECRET já foi herdada do Bloco 1)
if (!JWT_SECRET) {
    console.error("❌ ERRO CRÍTICO: JWT_SECRET não definida no .env.");
    process.exit(1); 
}

// Configurações de Criptografia
const SALT_ROUNDS = 10;

// ========================================
// 🚦 GESTÃO DE FLUXO (RATE LIMITING)
// ========================================

// 1. Barreira de Força Bruta (Login):
// Protege contra invasão de contas. Use este middleware apenas na rota de POST /login.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5, 
  message: { 
    erro: "Segurança: Muitas tentativas de login. Acesso bloqueado por 15 minutos." 
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// ========================================
// 🔐 MIDDLEWARE DE AUTENTICAÇÃO (UNIFICADO)
// ========================================

/**
 * Valida o JWT e anexa o usuário à requisição.
 * Intercepta requisições para validar a identidade via JWT.
 */
function autenticarToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ erro: "Token não fornecido" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error("❌ Token inválido:", err.message);
      return res.status(403).json({ erro: "Token inválido ou expirado" });
    }

    if (!decoded.id) {
      return res.status(403).json({ erro: "Token não contém ID de usuário" });
    }

    req.usuario = {
      id: decoded.id,
      email: decoded.email,
      tipo: decoded.tipo
    };

    next();
  });
}

// ========================================
// 🔎 MONITORAMENTO (HEALTH CHECK)
// ========================================

/**
 * Rota Raiz: Confirmação de status do ecossistema Hórus.
 * Útil para balanceadores de carga e verificações rápidas de uptime.
 */
app.get("/", (req, res) => {
  res.status(200).json({
    status: "online",
    sistema: "Hórus Consultoria Industrial",
    timestamp: new Date().toISOString(),
    ambiente: process.env.NODE_ENV || "development",
    mensagem: "Cérebro operacional e pronto para processamento. 🧠"
  });
});

// ========================================
// 💰 CONFIGURAÇÃO DE SALÁRIO MÍNIMO
// ========================================
const CONFIG_SALARIO = {
  valores: {
    2025: 1518,
    2026: 1621,
    2027: 1700  // valor estimado, ajustar quando governo anunciar
  },
  
  getSalarioMinimo() {
    const anoAtual = new Date().getFullYear();
    return this.valores[anoAtual] || this.valores[2025];
  },
  
  getAcompanhamentoMinimo() {
    const salario = this.getSalarioMinimo();
    // Arredonda para cima na centena mais próxima
    return Math.ceil(salario * 3 / 100) * 100;
  }
};

console.log(`💰 Salário mínimo ${new Date().getFullYear()}: R$ ${CONFIG_SALARIO.getSalarioMinimo()}`);
console.log(`📊 Acompanhamento mínimo mensal: R$ ${CONFIG_SALARIO.getAcompanhamentoMinimo()}`);

// ========================================
// 📊 FUNÇÃO: CALCULAR PARCELAS DO DIAGNÓSTICO
// ========================================
function calcularParcelasDiagnostico(valorDiagnostico) {
  const PARCELA_MAXIMA = 5000;
  const ENTRADA_PERCENTUAL = 50;
  
  const valorEntrada = (valorDiagnostico * ENTRADA_PERCENTUAL) / 100;
  const valorSaldo = valorDiagnostico - valorEntrada;
  
  // Se o saldo for zero ou negativo, não há parcelamento
  if (valorSaldo <= 0) {
    return {
      entrada_percentual: ENTRADA_PERCENTUAL,
      valor_entrada: valorEntrada,
      num_parcelas: 0,
      valor_parcela: 0,
      tem_parcelamento: false
    };
  }
  
  // Calcular número de parcelas baseado no valor máximo por parcela
  let numParcelas = Math.ceil(valorSaldo / PARCELA_MAXIMA);
  numParcelas = Math.min(numParcelas, 12); // máximo 12 parcelas
  
  // Calcular valor da parcela (arredondado para cima na centena)
  let valorParcela = Math.ceil(valorSaldo / numParcelas / 100) * 100;
  
  // Ajuste para que a última parcela não seja muito diferente
  const totalParcelado = numParcelas * valorParcela;
  if (totalParcelado !== valorSaldo) {
    const diferenca = valorSaldo - totalParcelado;
    valorParcela += Math.ceil(diferenca / numParcelas / 100) * 100;
  }
  
  return {
    entrada_percentual: ENTRADA_PERCENTUAL,
    valor_entrada: valorEntrada,
    num_parcelas: numParcelas,
    valor_parcela: valorParcela,
    saldo_parcelado: numParcelas * valorParcela,
    tem_parcelamento: true
  };
}

// ========================================
// 💰 FUNÇÃO: CALCULAR PREÇO DO PROJETO (NOVA LÓGICA - SEM FATURAMENTO)
// ========================================
function calcularPrecoProjeto(dados) {
  const { 
    linhas = 1,
    postos = 0,
    complexidade = 'media',
    urgencia = 'normal',
    projeto_piloto = false
  } = dados;
  
  // Valores base
  const VALOR_POR_LINHA = 50000;
  const VALOR_POR_POSTO = 3000;
  
  // Multiplicadores ajustados (compensando remoção do "acesso a dados")
  const MULTIPLICADORES = {
    complexidade: { 
      baixa: 1.0, 
      media: 1.40, 
      alta: 1.72, 
      muito_alta: 1.93 
    },
    urgencia: { 
      normal: 1.0, 
      alta: 1.24, 
      muito_alta: 1.34 
    }
  };
  
  // 1. Cálculo base
  let precoBase = (linhas * VALOR_POR_LINHA) + (postos * VALOR_POR_POSTO);
  
  // 2. Aplicar multiplicadores
  precoBase *= MULTIPLICADORES.complexidade[complexidade];
  precoBase *= MULTIPLICADORES.urgencia[urgencia];
  
  // 3. Desconto para projeto piloto
  if (projeto_piloto) precoBase *= 0.85;
  
  // 4. Arredondar para milhar
  const precoFinal = precoBase;
  
  // 5. Distribuição entre fases
  const diagnostico = Math.max(5000, precoFinal * 0.25);
  const implementacao = precoFinal * 0.50;
  const acompanhamentoTotal = precoFinal * 0.25;
  const acompanhamentoMensal = acompanhamentoTotal / 3;
  
  return {
    total: precoFinal,
    diagnostico: diagnostico,
    implementacao: implementacao,
    acompanhamento_total: acompanhamentoTotal,
    acompanhamento_mensal: acompanhamentoMensal,
    participacao_percentual: 20,
    detalhamento: {
      valor_por_linha: VALOR_POR_LINHA,
      valor_por_posto: VALOR_POR_POSTO,
      multiplicadores_aplicados: {
        complexidade: complexidade + ' (×' + MULTIPLICADORES.complexidade[complexidade] + ')',
        urgencia: urgencia + ' (×' + MULTIPLICADORES.urgencia[urgencia] + ')',
        projeto_piloto: projeto_piloto ? '-15%' : '0%'
      }
    }
  };
}

// ========================================
// 🏢 MÓDULO: GESTÃO DE EMPRESAS (CLIENTES)
// ========================================

/**
 * 1️⃣ LISTAR EMPRESAS
 * Rota protegida que retorna todos os clientes da consultoria.
 * Padrão: Plural-Strict e ordenação cronológica inversa.
 */
app.get("/api/companies", autenticarToken, async (req, res) => {
  try {
    const query = `
      SELECT 
        id, 
        nome, 
        cnpj, 
        segmento, 
        regime_tributario,
        turnos,
        dias_produtivos_mes,
        meta_mensal,
        status,
        valor_contrato,
        data_inicio,
        data_previsao_fim,
        criado_em 
      FROM empresas 
      ORDER BY criado_em DESC
    `;
    
    const result = await pool.query(query);
    res.status(200).json(result.rows || []);

  } catch (error) {
    console.error("❌ Erro ao buscar empresas:", error.message);
    res.status(500).json({ erro: "Falha ao carregar empresas" });
  }
});

// ========================================
// 🏢 MÓDULO: GESTÃO DE EMPRESAS (CLIENTES)
// ========================================

/**
 * 2️⃣ CADASTRAR EMPRESA
 * Com sanitização rigorosa e proteção de duplicidade.
 */
app.post("/api/companies", autenticarToken, async (req, res) => {
  const {
    nome,
    cnpj,
    segmento,
    regime_tributario,
    turnos,
    dias_produtivos_mes,
    meta_mensal,
    status,
    valor_contrato,
    data_inicio,
    data_previsao_fim
  } = req.body;

  // Validação Crítica de Presença
  if (!nome || !cnpj) {
    return res.status(400).json({ erro: "Nome e CNPJ são campos obrigatórios." });
  }

  try {
    // Sanitização de Dados (Engineered Inputs)
    const values = [
      nome.trim(),
      cnpj.replace(/\D/g, ''), // Remove tudo que não for dígito
      segmento || 'Não Definido',
      regime_tributario || 'Outros',
      Math.abs(parseInt(turnos, 10)) || 0,
      Math.abs(parseInt(dias_produtivos_mes, 10)) || 0,
      Math.abs(parseFloat(meta_mensal)) || 0,
      status || 'diagnostico',
      Math.abs(parseFloat(valor_contrato)) || 0,
      data_inicio || null,
      data_previsao_fim || null
    ];

    const query = `
      INSERT INTO empresas 
      (nome, cnpj, segmento, regime_tributario, turnos, dias_produtivos_mes, meta_mensal, status, valor_contrato, data_inicio, data_previsao_fim) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) 
      RETURNING *;
    `;

    const result = await pool.query(query, values);
    
    // ========================================
    // 💾 VINCULAR CONTRATO DA FASE 1 (SE EXISTIR)
    // ========================================
    try {
      // Buscar contrato da Fase 1 pelo nome da empresa
      const contratoExistente = await pool.query(`
        SELECT id, valor_total_projeto, valor_fase1_diagnostico, forma_pagamento, num_parcelas
        FROM contratos_fase1 
        WHERE empresa_nome = $1 AND empresa_id IS NULL
        ORDER BY id DESC 
        LIMIT 1
      `, [nome.trim()]);

      if (contratoExistente.rows.length > 0) {
        const contrato = contratoExistente.rows[0];
        
        // Atualizar o contrato com o empresa_id correto
        await pool.query(`
          UPDATE contratos_fase1 
          SET empresa_id = $1 
          WHERE id = $2
        `, [result.rows[0].id, contrato.id]);
        
        console.log(`✅ Contrato Fase 1 vinculado à empresa: ${nome} (ID: ${result.rows[0].id})`);
      } else {
        console.log(`ℹ️ Nenhum contrato da Fase 1 pendente para empresa: ${nome}`);
      }
    } catch (saveError) {
      console.error("❌ Erro ao vincular contrato:", saveError.message);
    }
    
    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error("❌ Erro POST /companies:", error.message);
    
    // Tratamento de erro de CNPJ duplicado (Constraint UNIQUE no banco)
    if (error.code === '23505') {
      return res.status(400).json({ erro: "Este CNPJ já está cadastrado no sistema." });
    }
    
    res.status(500).json({ erro: "Falha ao salvar empresa no banco de dados" });
  }
});

// ========================================
// 🏭 MÓDULO: LINHAS DE PRODUÇÃO
// ========================================

/**
 * 1️⃣ LISTAR LINHAS POR EMPRESA
 * Essencial para o dashboard: filtra apenas as linhas do cliente selecionado.
 */
app.get("/api/lines/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;

  try {
    const result = await pool.query(
      "SELECT * FROM linhas_producao WHERE empresa_id = $1 ORDER BY nome ASC",
      [empresaId]
    );

    // Garantia de array para o Front-end
    res.status(200).json(result.rows || []);
  } catch (error) {
    console.error("❌ Erro GET /lines:", error.message);
    res.status(500).json({ erro: "Erro ao carregar linhas de produção" });
  }
});

/**
 * 2️⃣ CADASTRAR LINHA
 * Com validação de integridade para evitar cálculos de Takt impossíveis.
 */
app.post("/api/lines", autenticarToken, async (req, res) => {
  const { 
    empresa_id, 
    nome, 
    produto_id, 
    takt_time_segundos, 
    meta_diaria 
  } = req.body;

  // Validação de Negócio: Não existe linha sem nome ou sem empresa vinculada
  if (!empresa_id || !nome) {
    return res.status(400).json({ erro: "Empresa e Nome da linha são obrigatórios." });
  }

  try {
    const query = `
      INSERT INTO linha_producao
      (empresa_id, nome, produto_id, takt_time_segundos, meta_diaria)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `;

    const values = [
      empresa_id,
      nome.trim(),
      produto_id || null,
      Math.max(0.1, parseFloat(takt_time_segundos) || 0), // Evita divisão por zero no futuro
      Math.abs(parseInt(meta_diaria, 10)) || 0
    ];

    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error("❌ Erro POST /lines:", error.message);
    
    // Erro de Chave Estrangeira (se a empresa ou produto não existirem)
    if (error.code === '23503') {
      return res.status(400).json({ erro: "Empresa ou Produto inexistente. Verifique os IDs." });
    }

    res.status(500).json({ erro: "Falha ao criar linha de produção" });
  }
});

/**
 * 3️⃣ EXCLUIR LINHA
 * Remove uma linha de produção e seus vínculos (produtos)
 */
app.delete("/api/lines/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Primeiro, excluir os vínculos com produtos (linha_produto)
    await pool.query("DELETE FROM linha_produto WHERE linha_id = $1", [id]);
    
    // Depois, excluir a linha
    const result = await pool.query(
      "DELETE FROM linhas_producao WHERE id = $1 RETURNING *", 
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Linha não encontrada." });
    }

    res.status(200).json({ 
      mensagem: "Linha e seus vínculos removidos com sucesso.",
      linha: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro DELETE /lines:", error.message);
    
    // Se houver postos vinculados, o banco vai lançar erro de FK
    if (error.code === '23503') {
      return res.status(409).json({ 
        erro: "Não é possível excluir: existem postos de trabalho vinculados a esta linha." 
      });
    }

    res.status(500).json({ erro: "Erro ao excluir linha." });
  }
});

/**
 * 4️⃣ EDITAR LINHA (PUT) - CORRIGIDO ✅
 * Atualiza os dados básicos da linha e suas associações com produtos
 * ✅ CORREÇÃO: Recalcula takt_time_segundos e meta_diaria quando produtos são alterados
 */
app.put("/api/lines/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { nome, produtos } = req.body;
  
// 🔥 CORREÇÃO: Só atualiza horas se o campo foi enviado
  let horasNumericas = null;
  if (req.body.horas_disponiveis !== undefined) {
    horasNumericas = parseFloat(req.body.horas_disponiveis) || 16;
  } else if (req.body.horas_produtivas_dia !== undefined) {
    horasNumericas = parseFloat(req.body.horas_produtivas_dia) || 16;
  }
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // 1. Atualizar a linha (nome e horas - com COALESCE)
    const result = await client.query(
      `UPDATE linhas_producao 
       SET nome = COALESCE($1, nome), 
           horas_disponiveis = COALESCE($2, horas_disponiveis)
       WHERE id = $3 RETURNING *`,
      [nome, horasNumericas, id]
    );
    
    if (result.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ erro: "Linha não encontrada" });
    }
    
    // 2. Se veio produtos, atualizar associações e recalcular takt/meta
    if (produtos && produtos.length > 0) {
      // Remover associações antigas
      await client.query('DELETE FROM linha_produto WHERE linha_id = $1', [id]);
      
      // 🔥 CALCULAR takt e meta da linha (média dos produtos)
      let taktTotal = 0;
      let metaTotal = 0;
      
      // Inserir novas associações e acumular totais
      for (const prod of produtos) {
        const taktProd = parseFloat(prod.takt_time_segundos || prod.takt || 0);
        const metaProd = parseInt(prod.meta_diaria || prod.meta || 0);
        
        taktTotal += taktProd;
        metaTotal += metaProd;
        
        await client.query(
          `INSERT INTO linha_produto (linha_id, produto_id, takt_time_segundos, meta_diaria)
           VALUES ($1, $2, $3, $4)`,
          [id, prod.produto_id || prod.id, taktProd, metaProd]
        );
      }
      
      // 🔥 RECALCULAR e atualizar takt e meta da linha
      const totalProdutos = produtos.length;
      const novoTakt = Math.round(taktTotal / totalProdutos);
      const novaMeta = Math.round(metaTotal / totalProdutos);
      
      await client.query(
        `UPDATE linhas_producao 
         SET takt_time_segundos = $1, 
             meta_diaria = $2
         WHERE id = $3`,
        [novoTakt, novaMeta, id]
      );
      
      console.log(`✅ Linha ID ${id} atualizada: takt=${novoTakt}s, meta=${novaMeta}pç/dia`);
    }
    
    await client.query('COMMIT');
    
    // Buscar a linha atualizada com os produtos
    const linhaAtualizada = await client.query(
      `SELECT l.*, 
        COALESCE(
          json_agg(
            json_build_object(
              'id', lp.id,
              'produto_id', lp.produto_id,
              'takt_time_segundos', lp.takt_time_segundos,
              'meta_diaria', lp.meta_diaria,
              'nome', p.nome,
              'valor_unitario', p.valor_unitario
            )
          ) FILTER (WHERE lp.produto_id IS NOT NULL), 
          '[]'
        ) as produtos
       FROM linhas_producao l
       LEFT JOIN linha_produto lp ON l.id = lp.linha_id
       LEFT JOIN produtos p ON lp.produto_id = p.id
       WHERE l.id = $1
       GROUP BY l.id`,
      [id]
    );
    
    res.json(linhaAtualizada.rows[0]);
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error("❌ Erro ao atualizar linha:", error.message);
    res.status(500).json({ erro: "Erro ao atualizar linha" });
  } finally {
    client.release();
  }
});

// ========================================
// 🏭 MÓDULO: LINHAS MASTER (MULTIDATA) - CORRIGIDO ✅
// ========================================

/**
 * ROTA: CRIAR LINHA COM MÚLTIPLOS PRODUTOS
 * Permite definir Takts e Metas específicas para cada produto na mesma linha.
 * ✅ CORREÇÃO: Agora calcula e salva takt_time_segundos e meta_diaria na tabela linhas_producao
 */
app.post("/api/lines-master", autenticarToken, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { 
      empresa_id, 
      nome, 
      horas_produtivas, 
      produtos // Array de objetos: [{id: 1, takt: 15, meta: 2000}, ...]
    } = req.body;

    // 1. Validação de Consistência
    if (!empresa_id || !nome || !produtos || produtos.length === 0) {
      return res.status(400).json({ 
        erro: "Dados insuficientes. Certifique-se de preencher o nome e selecionar produtos." 
      });
    }

    await client.query('BEGIN');

    // 🔥 CORREÇÃO: Calcular takt e meta da linha (média dos produtos)
    let taktTotal = 0;
    let metaTotal = 0;
    
    produtos.forEach(p => {
      const taktProd = parseFloat(p.takt) || 0;
      const metaProd = parseInt(p.meta) || 0;
      taktTotal += taktProd;
      metaTotal += metaProd;
    });
    
    const taktLinha = Math.round(taktTotal / produtos.length);
    const metaLinha = Math.round(metaTotal / produtos.length);

    // 2. Criar a Cabeça da Linha (Master) - AGORA COM TAKT E META
    const linhaQuery = `
      INSERT INTO linhas_producao (empresa_id, nome, horas_disponiveis, takt_time_segundos, meta_diaria)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id;
    `;
    const linhaRes = await client.query(linhaQuery, [
      empresa_id, 
      nome.trim(), 
      parseFloat(horas_produtivas) || 8.8,
      taktLinha,   // ✅ NOVO: takt calculado
      metaLinha    // ✅ NOVO: meta calculada
    ]);
    
    const linhaId = linhaRes.rows[0].id;

    // 3. Vincular Produtos
    const insertPromessas = produtos.map(p => {
      const pQuery = `
        INSERT INTO linha_produto (linha_id, produto_id, takt_time_segundos, meta_diaria)
        VALUES ($1, $2, $3, $4)
      `;
      const pValues = [
        linhaId, 
        p.id, 
        Math.max(0.1, parseFloat(p.takt) || 0), 
        Math.abs(parseInt(p.meta, 10)) || 0
      ];
      return client.query(pQuery, pValues);
    });

    await Promise.all(insertPromessas);
    await client.query('COMMIT');
    
    console.log(`✅ Linha "${nome}" criada com takt=${taktLinha}s e meta=${metaLinha}pç/dia`);
    
    res.status(201).json({ 
      mensagem: "Linha Master e performances de produtos registradas.",
      linha_id: linhaId,
      takt_calculado: taktLinha,
      meta_calculada: metaLinha
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("❌ Erro Crítico Master Route:", error.message);
    
    if (error.code === '23503') {
      return res.status(400).json({ erro: "Violação de integridade: Produto ou Empresa não existem." });
    }

    res.status(500).json({ erro: "Falha ao processar o cadastro mestre da linha." });
  } finally {
    client.release();
  }
});

// ========================================
// 🏗️ MÓDULO: POSTOS DE TRABALHO
// ========================================

/**
 * 1️⃣ LISTAR POSTOS POR LINHA
 * Ordenação por fluxo garante a visualização correta da sequência produtiva.
 */
app.get("/api/work-stations/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;

  try {
    const result = await pool.query(
      "SELECT * FROM posto_trabalho WHERE linha_id = $1 ORDER BY ordem_fluxo ASC",
      [linhaId]
    );

    res.status(200).json(result.rows || []);
  } catch (error) {
    console.error("❌ Erro GET /work-stations:", error.message);
    res.status(500).json({ erro: "Erro ao buscar postos de trabalho" });
  }
});

/**
 * 2️⃣ CADASTRAR POSTO
 * Agora respeita a ordem_fluxo enviada pelo frontend
 */
app.post("/api/work-stations", autenticarToken, async (req, res) => {
  const {
    linha_id,
    nome,
    tempo_ciclo_segundos,
    tempo_setup_minutos,
    cargo_id,
    disponibilidade_percentual,
    ordem_fluxo
  } = req.body;

  if (!linha_id || !nome) {
    return res.status(400).json({ erro: "Linha e Nome do posto são obrigatórios." });
  }

  try {
    // Determinar a ordem final
    let ordemFinal = ordem_fluxo;
    
    // Se não veio ordem do frontend, calcular automaticamente
    if (!ordemFinal) {
      const ordemResult = await pool.query(
        "SELECT COALESCE(MAX(ordem_fluxo), 0) + 1 as proxima_ordem FROM posto_trabalho WHERE linha_id = $1",
        [linha_id]
      );
      ordemFinal = ordemResult.rows[0].proxima_ordem;
    }

    const query = `
      INSERT INTO posto_trabalho
      (linha_id, nome, tempo_ciclo_segundos, tempo_setup_minutos, cargo_id, disponibilidade_percentual, ordem_fluxo)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `;

    const values = [
      linha_id,
      nome.trim(),
      parseFloat(tempo_ciclo_segundos) || 0,
      parseFloat(tempo_setup_minutos) || 0,
      cargo_id || null,
      parseFloat(disponibilidade_percentual) || 100,
      ordemFinal // 👈 AGORA USA A ORDEM CORRETA
    ];

    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro POST /work-stations:", error.message);
    res.status(500).json({ erro: "Falha ao registrar posto de trabalho" });
  }
});

/**
 * 3️⃣ PUT INTELIGENTE (WHITELISTED)
 * Atualiza apenas os campos permitidos, protegendo a estrutura do banco.
 */
app.put("/api/work-stations/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const fields = [];
  const values = [];
  let index = 1;

  // LISTA BRANCA: Apenas estes campos podem ser alterados
  const allowedFields = [
    'nome', 
    'tempo_ciclo_segundos', 
    'tempo_setup_minutos', 
    'cargo_id', 
    'disponibilidade_percentual', 
    'ordem_fluxo'
  ];

  try {
    for (let key in req.body) {
      if (allowedFields.includes(key)) {
        fields.push(`${key} = $${index}`);
        values.push(req.body[key]);
        index++;
      }
    }

    if (fields.length === 0) {
      return res.status(400).json({ erro: "Nenhum campo válido enviado para atualização" });
    }

    const query = `
      UPDATE posto_trabalho
      SET ${fields.join(", ")}
      WHERE id = $${index}
      RETURNING *;
    `;

    values.push(id); // O ID entra como último parâmetro

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Posto de trabalho não encontrado" });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro PUT /work-stations:", error.message);
    res.status(500).json({ erro: "Erro ao atualizar dados do posto" });
  }
});

/**
 * ROTA: EXCLUIR POSTO
 * Remove um posto de trabalho pelo ID
 */
app.delete("/api/work-stations/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  
  try {
    // 1. Verificar se o posto existe
    const posto = await pool.query(
      "SELECT * FROM posto_trabalho WHERE id = $1",
      [id]
    );
    
    if (posto.rows.length === 0) {
      return res.status(404).json({ 
        erro: "Posto de trabalho não encontrado" 
      });
    }
    
    // 2. Tentar excluir o posto
    const result = await pool.query(
      "DELETE FROM posto_trabalho WHERE id = $1 RETURNING *",
      [id]
    );
    
    console.log(`✅ Posto excluído: ${result.rows[0].nome} (ID: ${id})`);
    
    res.status(200).json({ 
      mensagem: "Posto excluído com sucesso!",
      posto: result.rows[0]
    });
    
  } catch (error) {
    console.error("❌ Erro ao excluir posto:", error.message);
    
    // 3. Tratamento de erro de chave estrangeira (se tiver vínculos)
    if (error.code === '23503') {
      return res.status(409).json({ 
        erro: "Não é possível excluir: existem alocações ou medições vinculadas a este posto.",
        detalhe: "Remova os vínculos antes de excluir o posto."
      });
    }
    
    res.status(500).json({ 
      erro: "Erro interno ao excluir posto" 
    });
  }
});

// ========================================
// 📈 MÓDULO: CRONOANÁLISE (VARIABILIDADE)
// ========================================

/**
 * ROTA: REGISTRAR MEDIÇÃO DE CICLO
 * Coleta o tempo de execução de uma tarefa em um posto específico.
 */
app.post("/api/cycle-measurements", autenticarToken, async (req, res) => {
  const { 
    posto_id, 
    operador_id,
    atividade,      // 👈 atividade executada
    tempo_ciclo_segundos, 
    metodo,         // 👈 método (padrao, melhorado, fora_padrao)
    observacao      // 👈 observações livres
  } = req.body;

  // Validação rigorosa
  if (!posto_id || !tempo_ciclo_segundos || parseFloat(tempo_ciclo_segundos) <= 0) {
    return res.status(400).json({ 
      erro: "Dados inválidos. O posto_id é obrigatório e o tempo deve ser maior que zero." 
    });
  }

  if (!atividade) {
    return res.status(400).json({ 
      erro: "Descreva a atividade executada." 
    });
  }

  try {
    // Gerar hora local do Brasil (UTC-3)
    const agora = new Date();
    const dataLocal = agora.toISOString().split('T')[0]; // YYYY-MM-DD
    const horaLocal = agora.toLocaleTimeString('pt-BR', { hour12: false }); // HH:MM:SS
    
    const query = `
      INSERT INTO ciclo_medicao 
      (posto_id, operador_id, atividade, tempo_ciclo_segundos, metodo, observacao, data_medicao, hora_medicao)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `;

    const values = [
      posto_id,
      operador_id || null,
      atividade.trim(),
      parseFloat(tempo_ciclo_segundos),
      metodo || 'padrao',
      observacao || null,
      dataLocal,
      horaLocal
    ];

    const result = await pool.query(query, values);
    
    console.log(`⏱️ Medição registrada: Posto ${posto_id} | ${atividade} | ${tempo_ciclo_segundos}s | ${dataLocal} ${horaLocal}`);
    
    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error("❌ Erro ao registrar cronoanálise:", error.message);
    
    if (error.code === '23503') {
      return res.status(400).json({ erro: "O posto de trabalho informado não existe." });
    }

    res.status(500).json({ erro: "Falha técnica ao salvar medição de ciclo" });
  }
});

/**
 * ROTA: BUSCAR MEDIÇÕES DE CICLO
 * Retorna todas as medições de um posto
 */
app.get("/api/cycle-measurements", autenticarToken, async (req, res) => {
  const { posto_id } = req.query;
  
  if (!posto_id) {
    return res.status(400).json({ erro: "posto_id é obrigatório" });
  }
  
  try {
    const result = await pool.query(`
      SELECT 
        id, 
        posto_id,
        operador_id,
        atividade,
        tempo_ciclo_segundos,
        metodo,
        observacao,
        data_medicao,
        hora_medicao
      FROM ciclo_medicao 
      WHERE posto_id = $1 
      ORDER BY data_medicao DESC, hora_medicao DESC
    `, [posto_id]);
    
    res.json(result.rows);
  } catch (error) {
    console.error("❌ Erro ao buscar medições:", error.message);
    res.status(500).json({ erro: "Erro ao buscar medições" });
  }
});

/**
 * ROTA: ATUALIZAR MEDIÇÃO DE CICLO
 */
app.put("/api/cycle-measurements/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { operador_id, atividade, tempo_ciclo_segundos, metodo, observacao } = req.body;
  
  try {
    const result = await pool.query(`
      UPDATE ciclo_medicao SET
        operador_id = COALESCE($1, operador_id),
        atividade = COALESCE($2, atividade),
        tempo_ciclo_segundos = COALESCE($3, tempo_ciclo_segundos),
        metodo = COALESCE($4, metodo),
        observacao = COALESCE($5, observacao),
        data_medicao = data_medicao,
        hora_medicao = hora_medicao
      WHERE id = $6
      RETURNING *
    `, [operador_id, atividade, tempo_ciclo_segundos, metodo, observacao, id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Medição não encontrada" });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro ao atualizar medição:", error.message);
    res.status(500).json({ erro: "Erro ao atualizar medição" });
  }
});

/**
 * ROTA: EXCLUIR MEDIÇÃO DE CICLO
 */
app.delete("/api/cycle-measurements/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query(
      "DELETE FROM ciclo_medicao WHERE id = $1 RETURNING id",
      [id]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Medição não encontrada" });
    }
    
    res.json({ mensagem: "Medição excluída com sucesso" });
  } catch (error) {
    console.error("❌ Erro ao excluir medição:", error.message);
    res.status(500).json({ erro: "Erro ao excluir medição" });
  }
});

// ========================================
// 👷 MÓDULO: GESTÃO DE CARGOS E CUSTOS
// ========================================

/**
 * 1️⃣ LISTAR CARGOS POR DEPARTAMENTO
 * Permite filtrar a estrutura hierárquica da empresa.
 */
app.get("/api/roles/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;

  try {
    const result = await pool.query(
      "SELECT * FROM cargos WHERE empresa_id = $1 ORDER BY nome ASC",
      [empresaId]
    );

    res.status(200).json(result.rows || []);
  } catch (error) {
    console.error("❌ Erro GET /roles:", error.message);
    res.status(500).json({ erro: "Falha ao recuperar cargos" });
  }
});

/**
 * 2️⃣ CADASTRAR CARGO
 * Foco em precisão financeira para cálculos de OEE e Custo.
 */
app.post("/api/roles", autenticarToken, async (req, res) => {
  const { 
    empresa_id, 
    nome, 
    salario_base, 
    encargos_percentual 
  } = req.body;

  if (!empresa_id || !nome) {
    return res.status(400).json({ erro: "Empresa e Nome do cargo são obrigatórios." });
  }

  try {
    const query = `
      INSERT INTO cargos
      (empresa_id, nome, salario_base, encargos_percentual)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `;

    // No Hórus, tratamos dinheiro com precisão.
    // Encargos padrão de 70% é uma estimativa segura para indústria (Brasil).
    const values = [
      empresa_id,
      nome.trim(),
      Math.abs(parseFloat(salario_base)) || 0,
      Math.abs(parseFloat(encargos_percentual)) || 70
    ];

    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error("❌ Erro POST /roles:", error.message);
    
    if (error.code === '23503') {
      return res.status(400).json({ erro: "Empresa inexistente." });
    }

    res.status(500).json({ erro: "Erro ao registrar novo cargo" });
  }
});

/**
 * 3️⃣ EXCLUIR CARGO
 * Verifica se existem colaboradores vinculados antes de deletar (Integridade).
 */
app.delete("/api/roles/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query("DELETE FROM cargos WHERE id = $1 RETURNING *", [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Cargo não encontrado para exclusão." });
    }

    res.status(200).json({ mensagem: "Cargo removido com sucesso." });
  } catch (error) {
    console.error("❌ Erro DELETE /roles:", error.message);
    
    // Se o cargo estiver sendo usado por um colaborador (FK), o banco barra.
    if (error.code === '23503') {
      return res.status(400).json({ 
        erro: "Não é possível excluir: existem colaboradores ou postos vinculados a este cargo." 
      });
    }

    res.status(500).json({ erro: "Erro técnico ao tentar excluir o cargo" });
  }
});

/**
 * 4️⃣ ATUALIZAR CARGO
 * Permite editar nome, salário e encargos
 */
app.put("/api/roles/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { nome, salario_base, encargos_percentual } = req.body;

  try {
    const query = `
      UPDATE cargos 
      SET 
        nome = COALESCE($1, nome),
        salario_base = COALESCE($2, salario_base),
        encargos_percentual = COALESCE($3, encargos_percentual)
      WHERE id = $4
      RETURNING *;
    `;

    const values = [
      nome?.trim(),
      salario_base !== undefined ? parseFloat(salario_base) : null,
      encargos_percentual !== undefined ? parseFloat(encargos_percentual) : null,
      id
    ];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Cargo não encontrado." });
    }

    res.status(200).json({
      mensagem: "Cargo atualizado com sucesso!",
      cargo: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro PUT /roles:", error.message);
    res.status(500).json({ erro: "Erro ao atualizar cargo" });
  }
});

// ========================================
// 👤 MÓDULO: GESTÃO DE COLABORADORES
// ========================================

/**
 * 1️⃣ LISTAR COLABORADORES POR EMPRESA
 * Traz a força de trabalho ativa da unidade.
 */
app.get("/api/employees/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;

  try {
    const query = `
      SELECT c.*, ca.nome as cargo_nome 
      FROM colaborador c
      LEFT JOIN cargos ca ON c.cargo_id = ca.id
      WHERE c.empresa_id = $1 
      ORDER BY c.nome ASC
    `;
    
    const result = await pool.query(query, [empresaId]);

    res.status(200).json(result.rows || []);
  } catch (error) {
    console.error("❌ Erro GET /employees:", error.message);
    res.status(500).json({ erro: "Erro ao buscar lista de colaboradores" });
  }
});

/**
 * 2️⃣ CADASTRAR COLABORADOR
 * Vincula o indivíduo à hierarquia da empresa.
 */
app.post("/api/employees", autenticarToken, async (req, res) => {
  const { empresa_id, cargo_id, nome } = req.body;

  // Validação Crítica
  if (!empresa_id || !nome || !nome.trim()) {
    return res.status(400).json({ erro: "Empresa e Nome do colaborador são obrigatórios." });
  }

  try {
    const query = `
      INSERT INTO colaborador (empresa_id, cargo_id, nome)
      VALUES ($1, $2, $3)
      RETURNING *;
    `;

    const values = [
      empresa_id,
      cargo_id || null, // Permite colaborador sem cargo temporariamente
      nome.trim()
    ];

    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro POST /employees:", error.message);

    if (error.code === '23503') {
      return res.status(400).json({ erro: "Empresa ou Cargo inexistente." });
    }

    res.status(500).json({ erro: "Falha ao registrar colaborador" });
  }
});

/**
 * 3️⃣ EXCLUIR COLABORADOR
 * Remove o vínculo, mas preserva a integridade de medições passadas.
 */
app.delete("/api/employees/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Verificar se o colaborador existe
    const colaboradorCheck = await client.query(
      "SELECT nome FROM colaborador WHERE id = $1",
      [id]
    );
    
    if (colaboradorCheck.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ erro: "Colaborador não encontrado." });
    }

    const colaboradorNome = colaboradorCheck.rows[0].nome;

    // 🔥 PRIMEIRO: Remover medições de ciclo onde ele é operador
    await client.query(
      "DELETE FROM ciclo_medicao WHERE operador_id = $1",
      [id]
    );

    // 🔥 SEGUNDO: Remover alocações do colaborador
    await client.query(
      "DELETE FROM alocacao_colaborador WHERE colaborador_id = $1",
      [id]
    );

    // 🔥 TERCEIRO: Remover o colaborador
    const result = await client.query(
      "DELETE FROM colaborador WHERE id = $1 RETURNING nome",
      [id]
    );

    await client.query('COMMIT');

    console.log(`✅ Colaborador removido: ${colaboradorNome}`);
    res.status(200).json({ 
      mensagem: `Colaborador "${colaboradorNome}" removido com sucesso.` 
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("❌ Erro DELETE /employees:", error.message);
    res.status(500).json({ 
      erro: "Erro ao excluir colaborador. Verifique se há vínculos ativos.",
      detalhe: error.message
    });
  } finally {
    client.release();
  }
});

/**
 * 4️⃣ ATUALIZAR COLABORADOR
 * Permite editar nome, empresa e cargo
 */
app.put("/api/employees/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { nome, empresa_id, cargo_id } = req.body;

  // Validação básica
  if (!nome || !empresa_id) {
    return res.status(400).json({ erro: "Nome e empresa são obrigatórios." });
  }

  try {
    // Verificar se colaborador existe
    const existe = await pool.query(
      "SELECT id FROM colaborador WHERE id = $1",
      [id]
    );

    if (existe.rowCount === 0) {
      return res.status(404).json({ erro: "Colaborador não encontrado." });
    }

    // Atualizar colaborador
    const query = `
      UPDATE colaborador 
      SET 
        nome = $1,
        empresa_id = $2,
        cargo_id = $3
      WHERE id = $4
      RETURNING *;
    `;

    const values = [
      nome.trim(),
      parseInt(empresa_id),
      cargo_id ? parseInt(cargo_id) : null,
      id
    ];

    const result = await pool.query(query, values);

    console.log(`✅ Colaborador atualizado: ${result.rows[0].nome}`);
    res.status(200).json(result.rows[0]);

  } catch (error) {
    console.error("❌ Erro PUT /employees/:id:", error.message);
    
    // Erro de chave estrangeira
    if (error.code === '23503') {
      return res.status(400).json({ 
        erro: "Empresa ou cargo inválido. Verifique os IDs." 
      });
    }

    res.status(500).json({ erro: "Erro ao atualizar colaborador" });
  }
});

// ========================================
// 📊 MÓDULO: INTELIGÊNCIA DE LINHA (ANALYSIS)
// ========================================

/**
 * ROTA: VISÃO MASTER DA LINHA
 * Consolida estrutura física, RH e Financeiro para análise de gargalos e custos.
 */
app.get("/api/line-intelligence/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;

  try {
    const query = `
      SELECT 
        lp.id AS linha_id,
        lp.nome AS linha_nome,
        lp.horas_disponiveis,
        pt.id AS posto_id,
        pt.nome AS posto_nome,
        pt.ordem_fluxo,
        pt.tempo_ciclo_segundos,
        pt.tempo_setup_minutos,
        pt.disponibilidade_percentual,
        c.nome AS cargo_nome,
        c.salario_base,
        c.encargos_percentual,
        -- Cálculo de Custo Estimado por Hora (Salário + Encargos / 220h padrão)
        ROUND(((c.salario_base * (1 + (c.encargos_percentual / 100))) / 220)::numeric, 2) AS custo_hora_estimado
      FROM linhas_producao lp
      LEFT JOIN posto_trabalho pt ON pt.linha_id = lp.id
      LEFT JOIN cargos c ON c.id = pt.cargo_id
      WHERE lp.id = $1
      ORDER BY pt.ordem_fluxo ASC;
    `;

    const result = await pool.query(query, [linhaId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Linha de produção não encontrada ou sem postos configurados." });
    }

    // Retorna os dados prontos para o gráfico de Balanceamento (Yamazumi)
    res.status(200).json(result.rows);

  } catch (error) {
    console.error("❌ Erro ao montar Inteligência de Linha:", error.message);
    res.status(500).json({ erro: "Falha ao processar os dados analíticos da linha." });
  }
});

// ========================================
// 🧠 MÓDULO: MOTOR DE ANÁLISE TÉCNICA
// ========================================

/**
 * ROTA: ANÁLISE DE PERFORMANCE E GARGALOS
 * Calcula Eficiência, Capacidade Real e identifica a Restrição (Gargalo).
 */
app.get("/api/line-analysis/:linhaId", autenticarToken, async (req, res) => {
  try {
    const { linhaId } = req.params;

    const result = await pool.query(`
      SELECT 
        lp.takt_time_segundos,
        lp.meta_diaria,
        pt.id,
        pt.nome,
        pt.tempo_ciclo_segundos,
        COALESCE(pt.disponibilidade_percentual, 100) as disponibilidade
      FROM linhas_producao lp
      LEFT JOIN posto_trabalho pt ON pt.linha_id = lp.id
      WHERE lp.id = $1
      ORDER BY pt.ordem_fluxo ASC
    `, [linhaId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Linha não encontrada." });
    }

    const takt = parseFloat(result.rows[0].takt_time_segundos) || 0;
    const metaPlanejada = parseFloat(result.rows[0].meta_diaria) || 0;

    // Se a linha não tem Takt, a análise de eficiência fica comprometida
    if (takt <= 0) {
      return res.status(422).json({ 
        erro: "Takt Time não definido para esta linha. Impossível calcular eficiência." 
      });
    }

    let maiorCicloReal = 0;
    let nomeGargalo = "N/A";

    const analisePostos = result.rows
      .filter(p => p.id !== null) // Ignora linhas sem postos (LEFT JOIN result)
      .map(p => {
        const cicloNominal = parseFloat(p.tempo_ciclo_segundos) || 0;
        const disp = (parseFloat(p.disponibilidade) || 100) / 100;
        
        // Ciclo Real ajustado pela disponibilidade (OEE-based cycle)
        const cicloReal = disp > 0 ? cicloNominal / disp : 0;

        if (cicloReal > maiorCicloReal) {
          maiorCicloReal = cicloReal;
          nomeGargalo = p.nome;
        }

        return {
          posto: p.nome,
          ciclo_nominal: cicloNominal,
          disponibilidade: p.disponibilidade + "%",
          ciclo_real: parseFloat(cicloReal.toFixed(2))
        };
      });

    if (analisePostos.length === 0) {
      return res.status(200).json({ mensagem: "Linha sem postos cadastrados para análise." });
    }

    // Cálculos de Performance Industrial
    const eficiencia = ((takt / maiorCicloReal) * 100).toFixed(2);
    const capacidadeRealDia = Math.floor((metaPlanejada * takt) / maiorCicloReal);

    res.status(200).json({
      metricas_globais: {
        takt_time_alvo: takt,
        meta_planejada: metaPlanejada,
        gargalo_identificado: nomeGargalo,
        ciclo_do_gargalo: parseFloat(maiorCicloReal.toFixed(2)),
        eficiencia_de_balanceamento: eficiencia + "%",
        capacidade_real_estimada: capacidadeRealDia
      },
      detalhamento_postos: analisePostos
    });

  } catch (error) {
    console.error("❌ Erro Crítico na Análise de Linha:", error.message);
    res.status(500).json({ erro: "Falha ao processar inteligência da linha." });
  }
});

// ========================================
// 💰 MÓDULO: SIMULAÇÃO E IMPACTO (OEE)
// ========================================

/**
 * ROTA: SIMULAÇÃO DE LINHA E PERDAS
 * Calcula a capacidade real descontando perdas de disponibilidade, performance e qualidade.
 */
app.get("/api/simulation/:linhaId", autenticarToken, async (req, res) => {
  try {
    const { linhaId } = req.params;

    const query = `
      SELECT 
        lp_prod.id as linha_produto_id,
        p.nome as produto_nome,
        lp_prod.takt_time_segundos,
        lp_prod.meta_diaria,
        l.horas_disponiveis as horas_produtivas_dia,
        e.dias_produtivos_mes,
        pt.nome as posto_nome,
        pt.tempo_ciclo_segundos,
        pt.tempo_setup_minutos,
        COALESCE(pt.disponibilidade_percentual, 100) as disponibilidade,
        COALESCE(pl.microparadas_minutos, 0) as microparadas,
        COALESCE(pl.retrabalho_pecas, 0) as retrabalho,
        COALESCE(pl.refugo_pecas, 0) as refugo
      FROM linha_produto lp_prod
      JOIN produtos p ON p.id = lp_prod.produto_id
      JOIN linhas_producao l ON l.id = lp_prod.linha_id
      JOIN empresas e ON e.id = l.empresa_id
      LEFT JOIN posto_trabalho pt ON pt.linha_id = l.id
      LEFT JOIN perdas_linha pl ON pl.linha_produto_id = lp_prod.id
      WHERE l.id = $1
      ORDER BY lp_prod.id, pt.ordem_fluxo;
    `;

    const result = await pool.query(query, [linhaId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Dados insuficientes para simulação nesta linha." });
    }

    const horasProdutivas = parseFloat(result.rows[0].horas_produtivas_dia) || 8.8;
    const diasMes = parseFloat(result.rows[0].dias_produtivos_mes) || 22;

    // 1. Agrupamento por Produto
    const produtosMap = {};
    result.rows.forEach(row => {
      if (!produtosMap[row.linha_produto_id]) {
        produtosMap[row.linha_produto_id] = {
          nome: row.produto_nome,
          takt: parseFloat(row.takt_time_segundos),
          metaDiaria: parseFloat(row.meta_diaria),
          microparadas: parseFloat(row.microparadas),
          retrabalho: parseFloat(row.retrabalho),
          refugo: parseFloat(row.refugo),
          postos: []
        };
      }
      if (row.posto_nome) {
        produtosMap[row.linha_produto_id].postos.push({
          nome: row.posto_nome,
          ciclo: parseFloat(row.tempo_ciclo_segundos || 0),
          setup: parseFloat(row.tempo_setup_minutos || 0),
          disponibilidade: (parseFloat(row.disponibilidade) || 100) / 100
        });
      }
    });

    // 2. Processamento de Engenharia
    const analiseFinal = Object.values(produtosMap).map(prod => {
      let maiorCicloReal = 0;
      let setupTotalMin = 0;
      let nomeGargalo = "N/A";

      prod.postos.forEach(p => {
        setupTotalMin += p.setup;
        const cicloReal = p.disponibilidade > 0 ? p.ciclo / p.disponibilidade : 0;
        
        if (cicloReal > maiorCicloReal) {
          maiorCicloReal = cicloReal;
          nomeGargalo = p.nome;
        }
      });

      // Cálculo de Tempos (Segundos)
      const tempoTotalDisponivel = horasProdutivas * 3600;
      const tempoPerdaDisponibilidade = (setupTotalMin * 60) + (prod.microparadas * 60);
      const tempoLiquidoOperando = Math.max(0, tempoTotalDisponivel - tempoPerdaDisponibilidade);

      // Capacidade e Qualidade
      const capacidadeBruta = maiorCicloReal > 0 ? Math.floor(tempoLiquidoOperando / maiorCicloReal) : 0;
      const producaoBoa = Math.max(0, capacidadeBruta - prod.refugo);
      
      // Indicadores OEE (Simplificados)
      const disponibilidadeOEE = (tempoLiquidoOperando / tempoTotalDisponivel) * 100;
      const qualidadeOEE = capacidadeBruta > 0 ? (producaoBoa / capacidadeBruta) * 100 : 0;
      const performanceOEE = (maiorCicloReal > 0 && prod.takt > 0) ? (prod.takt / maiorCicloReal) * 100 : 0;

      return {
        produto: prod.nome,
        gargalo: nomeGargalo,
        capacidade_real_dia: producaoBoa,
        perda_diaria_pecas: prod.metaDiaria - producaoBoa,
        indicadores: {
          disponibilidade: disponibilidadeOEE.toFixed(2) + "%",
          performance: performanceOEE.toFixed(2) + "%",
          qualidade: qualidadeOEE.toFixed(2) + "%",
          oee_global: ((disponibilidadeOEE * performanceOEE * qualidadeOEE) / 10000).toFixed(2) + "%"
        }
      };
    });

    res.status(200).json({
      configuracao: { horas_dia: horasProdutivas, dias_mes: diasMes },
      simulacao: analiseFinal
    });

  } catch (error) {
    console.error("❌ Erro no Motor de Simulação:", error.message);
    res.status(500).json({ erro: "Falha ao calcular impacto financeiro." });
  }
});

// ========================================
// 📊 MOTOR DE CÁLCULO OEE (VERSÃO NEXUS - CORRIGIDO)
// ========================================
app.post("/api/simulador-oee", async (req, res) => {
  try {
    const { linhaId, horasProdutivas, produtos } = req.body;

    // Validação de entrada
    if (!produtos || !Array.isArray(produtos)) {
      return res.status(400).json({ erro: "Dados de produtos inválidos." });
    }

    let resultados = [];

    for (const produto of produtos) {
      // 1. CONVERSÃO PARA BASE SEGUNDOS (Padronização de Engenharia)
      const tempoPlanejadoSegundos = horasProdutivas * 3600; 
      const disponibilidadeDecimal = (produto.disponibilidade || 100) / 100;
      const tempoOperandoSegundos = tempoPlanejadoSegundos * disponibilidadeDecimal;

      // 2. IDENTIFICAÇÃO DO GARGALO (Maior ciclo entre os postos)
      const temposCiclo = produto.postos?.map(p => p.tempo_ciclo || 0) || [0];
      const gargalo = Math.max(...temposCiclo) || 1; // Evita divisão por zero
      
      // 3. 🔥 CORREÇÃO: Buscar TAKT REAL do produto (se disponível)
      let taktReal = produto.takt || gargalo;
      
      // Se o takt veio do frontend, validar se é razoável
      if (produto.takt && produto.takt > 0) {
        taktReal = produto.takt;
      } else if (produto.takt_time_segundos && produto.takt_time_segundos > 0) {
        taktReal = produto.takt_time_segundos;
      }
      
      // 3. CÁLCULO DE CAPACIDADE E PRODUÇÃO
      const capacidadeBruta = Math.floor(tempoOperandoSegundos / gargalo);
      
      // Produção Boa = Capacidade * Índice de Qualidade
      const qualidadeDecimal = (produto.qualidade || 100) / 100;
      const producaoBoa = Math.floor(capacidadeBruta * qualidadeDecimal);

      // 4. CÁLCULO DOS PILARES OEE (Normalizados 0 a 1)
      const disponibilidadeOEE = disponibilidadeDecimal;
      
      // 🔥 CORREÇÃO: Performance usando TAKT REAL
      const performanceOEE = tempoOperandoSegundos > 0 && taktReal > 0
        ? Math.min(1, (capacidadeBruta * taktReal) / tempoOperandoSegundos)
        : 0;

      const qualidadeOEE = capacidadeBruta > 0 ? producaoBoa / capacidadeBruta : 0;
      
      // Cálculo Final: Disponibilidade x Performance x Qualidade
      const oeeFinal = disponibilidadeOEE * performanceOEE * qualidadeOEE;

      // 5. COMPILAÇÃO DO RELATÓRIO
      resultados.push({
        produto: produto.produto_nome,
        meta_diaria_planejada: produto.metaDiaria || 0,
        capacidade_bruta_dia: capacidadeBruta,
        producao_boa_dia: producaoBoa,
        deficit_pecas_dia: Math.max(0, (produto.metaDiaria || 0) - producaoBoa),
        gargalo_identificado: `${gargalo}s`,
        takt_utilizado: taktReal,
        indicadores: {
          disponibilidade_percentual: (disponibilidadeOEE * 100).toFixed(2),
          performance_percentual: (performanceOEE * 100).toFixed(2),
          qualidade_percentual: (qualidadeOEE * 100).toFixed(2),
          oee_global_percentual: (oeeFinal * 100).toFixed(2)
        }
      });
    }

    // Resposta final para o Front-end/Thunder Client
    res.status(200).json({
      status: "sucesso_v2",
      linha_id: linhaId,
      timestamp: new Date().toISOString(),
      analise_por_produto: resultados
    });

  } catch (error) {
    console.error("❌ Erro Crítico no Motor OEE:", error.message);
    res.status(500).json({ 
      erro: "Falha interna no motor de cálculo", 
      detalhe: error.message 
    });
  }
});

// ========================================
// ⚖️ MÓDULO: ENGENHARIA DE BALANCEAMENTO
// ========================================

/**
 * ROTA: ANÁLISE DE BALANCEAMENTO (YAMAZUMI)
 * Identifica o desvio entre postos e o potencial de redistribuição de carga.
 */
app.get("/api/line-balancing/:linhaId", autenticarToken, async (req, res) => {
  try {
    const { linhaId } = req.params;

    const result = await pool.query(`
      SELECT 
        nome,
        tempo_ciclo_segundos,
        COALESCE(disponibilidade_percentual, 100) as disponibilidade
      FROM posto_trabalho
      WHERE linha_id = $1
      ORDER BY ordem_fluxo ASC
    `, [linhaId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Nenhum posto encontrado para esta linha." });
    }

    let somaCiclosReais = 0;
    let maiorCicloReal = 0;
    let menorCicloReal = Infinity;

    const postosProcessados = result.rows.map(p => {
      const cicloNominal = parseFloat(p.tempo_ciclo_segundos) || 0;
      const disp = (parseFloat(p.disponibilidade) || 100) / 100;
      
      // Ciclo ajustado: Reflete o tempo real que o posto "ocupa" na linha
      const cicloReal = disp > 0 ? cicloNominal / disp : 0;

      somaCiclosReais += cicloReal;
      if (cicloReal > maiorCicloReal) maiorCicloReal = cicloReal;
      if (cicloReal < menorCicloReal && cicloReal > 0) menorCicloReal = cicloReal;

      return {
        posto: p.nome,
        ciclo_nominal: cicloNominal,
        ciclo_real: parseFloat(cicloReal.toFixed(2))
      };
    });

    const qtdPostos = postosProcessados.length;
    const tempoMedio = somaCiclosReais / qtdPostos;

    // Índice de Balanceamento: Quanto mais próximo de 100%, mais equilibrada a linha.
    const indiceBalanceamento = maiorCicloReal > 0 
      ? ((tempoMedio / maiorCicloReal) * 100).toFixed(2) 
      : 0;

    // Perda por Balanceamento: O quanto de capacidade você "joga fora" por ter postos desiguais.
    const perdaBalanceamento = (100 - indiceBalanceamento).toFixed(2);

    res.status(200).json({
      resumo_executivo: {
        total_postos: qtdPostos,
        tempo_total_agregado: parseFloat(somaCiclosReais.toFixed(2)),
        ritmo_da_linha_seg: parseFloat(maiorCicloReal.toFixed(2)),
        indice_balanceamento: indiceBalanceamento + "%",
        perda_por_desbalanceamento: perdaBalanceamento + "%"
      },
      detalhes_por_posto: postosProcessados
    });

  } catch (error) {
    console.error("❌ Erro no cálculo de balanceamento:", error.message);
    res.status(500).json({ erro: "Falha técnica ao processar balanceamento de linha." });
  }
});

// ========================================
// 🌎 MÓDULO: EFICIÊNCIA GLOBAL (MACRO) - CORRIGIDO ✅
// ========================================

/**
 * ROTA: RESUMO DE PERFORMANCE GLOBAL
 * Entrega os KPIs mestres para o dashboard do Diretor/Dono da fábrica.
 */
app.get("/api/global-efficiency/:linhaId", autenticarToken, async (req, res) => {
  try {
    const { linhaId } = req.params;

    // 1. Buscar dados da linha e postos
    const result = await pool.query(`
      SELECT 
        lp.takt_time_segundos,
        lp.meta_diaria,
        lp.horas_disponiveis,
        pt.tempo_ciclo_segundos,
        COALESCE(pt.disponibilidade_percentual, 100) as disponibilidade
      FROM linhas_producao lp
      LEFT JOIN posto_trabalho pt ON pt.linha_id = lp.id
      WHERE lp.id = $1
    `, [linhaId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Linha de produção não localizada." });
    }

    const taktAlvo = parseFloat(result.rows[0].takt_time_segundos) || 0;
    const metaDiaria = parseFloat(result.rows[0].meta_diaria) || 0;
    const horasDisponiveis = parseFloat(result.rows[0].horas_disponiveis) || 8.8;

    let ritmoGargalo = 0;
    let totalPostos = 0;
    let somaDisponibilidade = 0;

    // Calcular ritmo do gargalo e disponibilidade média
    result.rows.forEach(p => {
      if (p.tempo_ciclo_segundos !== null) {
        totalPostos++;
        const cicloNominal = parseFloat(p.tempo_ciclo_segundos) || 0;
        const disp = (parseFloat(p.disponibilidade) || 100) / 100;
        const cicloAjustado = disp > 0 ? cicloNominal / disp : 0;
        somaDisponibilidade += disp;

        if (cicloAjustado > ritmoGargalo) ritmoGargalo = cicloAjustado;
      }
    });

    // Validação de dados
    if (ritmoGargalo === 0 || metaDiaria === 0 || taktAlvo === 0 || totalPostos === 0) {
      return res.status(200).json({
        alerta: "Estrutura de linha incompleta",
        mensagem: "Certifique-se de que a meta, o takt e os tempos de ciclo dos postos estão cadastrados.",
        meta_planejada: metaDiaria,
        takt_configurado: taktAlvo,
        postos_encontrados: totalPostos,
        ritmo_gargalo: ritmoGargalo
      });
    }

    // 🔥 CORREÇÃO: Disponibilidade baseada em dados reais
    const disponibilidadeMedia = totalPostos > 0 ? somaDisponibilidade / totalPostos : 0.85;
    const disponibilidade = Math.min(1, Math.max(0, disponibilidadeMedia));

    // 🔥 Buscar dados de produção para calcular disponibilidade real
    const producaoQuery = `
      SELECT 
        COALESCE(AVG(disponibilidade), 0) as disp_media,
        COUNT(*) as total_registros
      FROM producao_oee
      WHERE linha_id = $1
    `;
    const producaoRes = await pool.query(producaoQuery, [linhaId]);
    
    let disponibilidadeReal = disponibilidade;
    if (producaoRes.rows[0]?.total_registros > 0) {
      const dispFromOEE = parseFloat(producaoRes.rows[0]?.disp_media) / 100;
      if (dispFromOEE > 0) {
        disponibilidadeReal = Math.min(1, Math.max(0, dispFromOEE));
      }
    }

    // 2. 🔥 BUSCAR DADOS DE QUALIDADE (REFUGO)
    const qualidadeQuery = `
      SELECT 
        COALESCE(SUM(pl.refugo_pecas), 0) as total_refugo,
        COALESCE(SUM(pl.retrabalho_pecas), 0) as total_retrabalho
      FROM perdas_linha pl
      JOIN linha_produto lp ON lp.id = pl.linha_produto_id
      WHERE lp.linha_id = $1
    `;
    const qualidadeRes = await pool.query(qualidadeQuery, [linhaId]);
    const totalRefugo = parseInt(qualidadeRes.rows[0]?.total_refugo) || 0;
    const totalRetrabalho = parseInt(qualidadeRes.rows[0]?.total_retrabalho) || 0;

    // 3. 🔥 CÁLCULO DOS PILARES OEE
    // Performance (ritmo teórico vs ritmo real)
    const performance = Math.min(1, taktAlvo / ritmoGargalo);
    
    // Qualidade (peças boas vs peças totais)
    const pecasBoas = metaDiaria - totalRefugo - totalRetrabalho;
    const qualidade = metaDiaria > 0 ? Math.max(0, pecasBoas / metaDiaria) : 0;

    // OEE Final = Disponibilidade × Performance × Qualidade
    const oeeCalculado = disponibilidadeReal * performance * qualidade;

    // 4. CAPACIDADE REAL (considerando qualidade)
    const capacidadeReal = Math.floor((metaDiaria * taktAlvo) / ritmoGargalo);
    const producaoRealComQualidade = Math.floor(capacidadeReal * qualidade);

    // 5. 🔥 NOVO: Cálculo dos 3 pilares
    const pilares = {
      disponibilidade_percentual: (disponibilidadeReal * 100).toFixed(2),
      performance_percentual: (performance * 100).toFixed(2),
      qualidade_percentual: (qualidade * 100).toFixed(2),
      oee_percentual: (oeeCalculado * 100).toFixed(2)
    };

    res.status(200).json({
      oee: parseFloat(pilares.oee_percentual),
      eficiencia_global: pilares.oee_percentual + "%",
      capacidade_estimada: producaoRealComQualidade,
      gargalo_identificado: ritmoGargalo,
      takt_time: taktAlvo,
      meta_diaria: metaDiaria,
      horas_disponiveis: horasDisponiveis,
      // 🔥 NOVO: 3 pilares do OEE
      pilares: {
        disponibilidade: parseFloat(pilares.disponibilidade_percentual),
        performance: parseFloat(pilares.performance_percentual),
        qualidade: parseFloat(pilares.qualidade_percentual)
      },
      perdas_qualidade: {
        refugo: totalRefugo,
        retrabalho: totalRetrabalho,
        total_perdas_pecas: totalRefugo + totalRetrabalho
      },
      detalhes: {
        ritmo_gargalo: ritmoGargalo,
        takt_alvo: taktAlvo,
        capacidade_teorica: capacidadeReal,
        producao_real_estimada: producaoRealComQualidade,
        meta_diaria: metaDiaria,
        total_postos: totalPostos,
        disponibilidade_calculada: (disponibilidadeReal * 100).toFixed(2) + "%"
      }
    });

  } catch (error) {
    console.error("❌ Erro no cálculo de eficiência macro:", error.message);
    res.status(500).json({ erro: "Erro ao processar visão macro de eficiência." });
  }
});

// ========================================
// 📊 MÓDULO: ESTABILIDADE E VARIABILIDADE
// ========================================

/**
 * ROTA: ANÁLISE ESTATÍSTICA DO POSTO
 * Avalia se o processo é repetível ou se há descontrole operacional.
 */
app.get("/api/variability/:postoId", autenticarToken, async (req, res) => {
  try {
    const { postoId } = req.params;

    const result = await pool.query(
      `SELECT tempo_ciclo_segundos 
       FROM ciclo_medicao 
       WHERE posto_id = $1 
       ORDER BY data_medicao DESC`, 
      [postoId]
    );

    const n = result.rows.length;

    if (n === 0) {
      return res.status(404).json({ erro: "Nenhuma medição encontrada para este posto." });
    }

    const valores = result.rows.map(r => parseFloat(r.tempo_ciclo_segundos));
    const soma = valores.reduce((a, b) => a + b, 0);
    const media = soma / n;

    // Cálculo da Variância Amostral (n-1 para maior precisão estatística em amostras)
    const variancia = n > 1 
      ? valores.reduce((acc, val) => acc + Math.pow(val - media, 2), 0) / (n - 1)
      : 0;

    const desvioPadrao = Math.sqrt(variancia);
    
    // Coeficiente de Variação (CV) - Mede a dispersão em relação à média
    const cv = media > 0 ? (desvioPadrao / media) * 100 : 0;

    // Classificação Industrial de Estabilidade
    let classificacao = "";
    let statusColor = "";

    if (cv < 5) {
      classificacao = "Processo sob controle (Excelente)";
      statusColor = "green";
    } else if (cv < 10) {
      classificacao = "Processo estável (Aceitável)";
      statusColor = "blue";
    } else if (cv < 20) {
      classificacao = "Processo instável (Requer atenção)";
      statusColor = "yellow";
    } else {
      classificacao = "Processo crítico (Alto risco de gargalo)";
      statusColor = "red";
    }

    res.status(200).json({
      metadados: {
        posto_id: postoId,
        total_amostras: n
      },
      estatisticas: {
        media_segundos: parseFloat(media.toFixed(2)),
        desvio_padrao: parseFloat(desvioPadrao.toFixed(2)),
        coeficiente_variacao: cv.toFixed(2) + "%"
      },
      diagnostico: {
        classificacao,
        status_slug: statusColor,
        acao_recomendada: cv >= 20 
          ? "Realizar novo treinamento ou revisar método de trabalho (PO)." 
          : "Manter monitoramento periódico."
      }
    });

  } catch (error) {
    console.error("❌ Erro na análise estatística:", error.message);
    res.status(500).json({ erro: "Falha ao processar análise de variabilidade." });
  }
});

// ========================================
// 🔗 MÓDULO: VÍNCULO PRODUTO-LINHA
// ========================================

/**
 * ROTA: VINCULAR OU ATUALIZAR PERFORMANCE DE PRODUTO NA LINHA
 * Define como um produto específico deve se comportar em uma linha específica.
 */
app.post("/api/line-product", autenticarToken, async (req, res) => {
  const { 
    linha_id, 
    produto_id, 
    takt_time_segundos, 
    meta_diaria 
  } = req.body;

  // 1. Validação de Presença e Tipo
  if (!linha_id || !produto_id) {
    return res.status(400).json({ erro: "ID da Linha e ID do Produto são obrigatórios." });
  }

  // 2. Sanitização de Valores de Engenharia
  // Impedimos Takt ou Meta zero/negativo para não quebrar cálculos de eficiência (divisão por zero)
  const taktLimpo = Math.max(0.1, parseFloat(takt_time_segundos) || 0);
  const metaLimpa = Math.max(1, parseInt(meta_diaria, 10) || 0);

  try {
    const query = `
      INSERT INTO linha_produto (linha_id, produto_id, takt_time_segundos, meta_diaria)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (linha_id, produto_id) 
      DO UPDATE SET 
        takt_time_segundos = EXCLUDED.takt_time_segundos,
        meta_diaria = EXCLUDED.meta_diaria
      RETURNING *;
    `;

    const values = [linha_id, produto_id, taktLimpo, metaLimpa];

    const result = await pool.query(query, values);
    
    res.status(201).json({
      mensagem: "Vínculo de produção registrado com sucesso.",
      dados: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro ao vincular produto:", error.message);

    if (error.code === '23503') {
      return res.status(400).json({ erro: "Linha ou Produto inexistente no banco de dados." });
    }

    res.status(500).json({ erro: "Falha técnica ao processar vínculo de produção." });
  }
});

// ========================================
// 🔗 MÓDULO: ATUALIZAR PRODUTO NA LINHA (PUT INDIVIDUAL)
// ========================================

/**
 * ROTA: ATUALIZAR VÍNCULO PRODUTO-LINHA
 * Atualiza takt e meta de um produto específico em uma linha
 */
app.put("/api/line-product/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { takt_time_segundos, meta_diaria } = req.body;

  try {
    const query = `
      UPDATE linha_produto 
      SET 
        takt_time_segundos = COALESCE($1, takt_time_segundos),
        meta_diaria = COALESCE($2, meta_diaria)
      WHERE id = $3
      RETURNING *;
    `;

    const values = [
      takt_time_segundos !== undefined ? parseFloat(takt_time_segundos) : null,
      meta_diaria !== undefined ? parseInt(meta_diaria) : null,
      id
    ];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Vínculo produto-linha não encontrado." });
    }

    res.status(200).json({
      mensagem: "Produto na linha atualizado com sucesso.",
      dados: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro PUT /line-product/:id:", error.message);
    res.status(500).json({ erro: "Erro ao atualizar produto na linha." });
  }
});

// ========================================
// 🔗 MÓDULO: REMOVER PRODUTO DA LINHA (DELETE)
// ========================================

/**
 * ROTA: REMOVER VÍNCULO PRODUTO-LINHA
 * Exclui um produto específico de uma linha
 */
app.delete("/api/line-product/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      "DELETE FROM linha_produto WHERE id = $1 RETURNING *",
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Vínculo produto-linha não encontrado." });
    }

    res.status(200).json({
      mensagem: "Produto removido da linha com sucesso.",
      dados: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro DELETE /line-product/:id:", error.message);
    res.status(500).json({ erro: "Erro ao remover produto da linha." });
  }
});

// ========================================
// 📉 MÓDULO: GESTÃO DE DESPERDÍCIOS (PERDAS)
// ========================================

/**
 * ROTA: REGISTRAR OU ATUALIZAR PERDAS
 * Alimenta os pilares de Disponibilidade e Qualidade do OEE.
 */
app.post("/api/losses", autenticarToken, async (req, res) => {
  const {
    linha_produto_id,
    microparadas_minutos,
    retrabalho_pecas,
    refugo_pecas,
    data_perda  // 👈 ADICIONADO!
  } = req.body;

  if (!linha_produto_id) {
    return res.status(400).json({ erro: "ID do vínculo linha-produto é obrigatório." });
  }

  // Sanitização: Garantir que perdas nunca sejam negativas
  const micro = Math.max(0, parseFloat(microparadas_minutos) || 0);
  const retrabalho = Math.max(0, parseInt(retrabalho_pecas, 10) || 0);
  const refugo = Math.max(0, parseInt(refugo_pecas, 10) || 0);
  
  // Usar data enviada ou data atual
  const data = data_perda || new Date().toISOString().split('T')[0];

  try {
    // Lógica de Upsert: Se já houver registro de perdas para este produto nesta DATA, ele atualiza.
    const query = `
      INSERT INTO perdas_linha 
      (linha_produto_id, microparadas_minutos, retrabalho_pecas, refugo_pecas, data_perda)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (linha_produto_id, data_perda) 
      DO UPDATE SET 
        microparadas_minutos = EXCLUDED.microparadas_minutos,
        retrabalho_pecas = EXCLUDED.retrabalho_pecas,
        refugo_pecas = EXCLUDED.refugo_pecas
      RETURNING *;
    `;

    const values = [linha_produto_id, micro, retrabalho, refugo, data];

    const result = await pool.query(query, values);
    
    res.status(201).json({
      mensagem: "Registro de perdas consolidado.",
      dados: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro ao registrar perdas industriais:", error.message);
    
    if (error.code === '23503') {
      return res.status(400).json({ erro: "Vínculo de linha-produto não encontrado." });
    }

    if (error.code === '23505') {
      return res.status(409).json({ erro: "Já existe um registro para esta data." });
    }

    res.status(500).json({ erro: "Falha técnica ao salvar indicadores de perda." });
  }
});

// ========================================
// 📊 MÓDULO: ANALÍTICO DE DESPERDÍCIOS
// ========================================

/**
 * ROTA: LISTAR HISTÓRICO DE PERDAS POR LINHA COM FILTRO DE DATAS
 */
app.get("/api/losses/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;
  const { data_inicio, data_fim } = req.query;  // 👈 PEGAR DATAS DA QUERY

  try {
    let query = `
      SELECT 
        pl.id as perda_id,
        p.nome as produto_nome,
        pl.microparadas_minutos,
        pl.retrabalho_pecas,
        pl.refugo_pecas,
        TO_CHAR(pl.data_perda, 'DD/MM/YYYY') as data_perda,
        lp.takt_time_segundos,
        (pl.microparadas_minutos * 60) as tempo_parada_total_seg
      FROM perdas_linha pl
      JOIN linha_produto lp ON lp.id = pl.linha_produto_id
      JOIN produtos p ON p.id = lp.produto_id
      WHERE lp.linha_id = $1
    `;

    const values = [linhaId];
    let paramIndex = 2;

    // Adicionar filtro de data_inicio se fornecido
    if (data_inicio) {
      query += ` AND pl.data_perda >= $${paramIndex}`;
      values.push(data_inicio);
      paramIndex++;
    }

    // Adicionar filtro de data_fim se fornecido
    if (data_fim) {
      query += ` AND pl.data_perda <= $${paramIndex}`;
      values.push(data_fim);
      paramIndex++;
    }

    query += ` ORDER BY pl.data_perda DESC, pl.id DESC;`;

    const result = await pool.query(query, values);
    res.status(200).json(result.rows);

  } catch (error) {
    console.error("❌ Erro GET /losses:", error.message);
    res.status(500).json({ 
      erro: "Falha ao recuperar histórico de desperdícios da linha." 
    });
  }
});

// ========================================
// ✏️ MÓDULO: AJUSTE DE INDICADORES (PERDAS)
// ========================================

/**
 * ROTA: ATUALIZAR REGISTRO DE PERDA EXISTENTE
 * Permite correções de auditoria em registros de desperdício.
 */
app.put("/api/losses/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { microparadas_minutos, retrabalho_pecas, refugo_pecas } = req.body;

  // Sanitização Preventiva: Não aceitamos perdas negativas em ajustes.
  // Se o valor for enviado, garantimos que seja >= 0.
  const micro = microparadas_minutos !== undefined ? Math.max(0, parseFloat(microparadas_minutos)) : null;
  const retrabalho = retrabalho_pecas !== undefined ? Math.max(0, parseInt(retrabalho_pecas, 10)) : null;
  const refugo = refugo_pecas !== undefined ? Math.max(0, parseInt(refugo_pecas, 10)) : null;

  try {
    const query = `
      UPDATE perdas_linha 
      SET 
        microparadas_minutos = COALESCE($1, microparadas_minutos),
        retrabalho_pecas = COALESCE($2, retrabalho_pecas),
        refugo_pecas = COALESCE($3, refugo_pecas)
      WHERE id = $4
      RETURNING *;
    `;

    const result = await pool.query(query, [micro, retrabalho, refugo, id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Registro de perda não localizado para atualização." });
    }

    res.status(200).json({
      mensagem: "Indicadores de perda atualizados com sucesso.",
      dados: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro PUT /losses:", error.message);
    res.status(500).json({ erro: "Erro técnico ao atualizar indicadores de desperdício." });
  }
});

// ========================================
// 🗑️ MÓDULO: PURGA DE DADOS (PERDAS)
// ========================================

/**
 * ROTA: REMOVER REGISTRO DE PERDA
 * Utilizado para limpar erros de entrada que não podem ser corrigidos via UPDATE.
 */
app.delete("/api/losses/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      "DELETE FROM perdas_linha WHERE id = $1 RETURNING id", 
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ 
        erro: "Registro de perda não encontrado para remoção." 
      });
    }

    // Ao excluir uma perda, o motor de OEE (Bloco 19) recalculará 
    // automaticamente a eficiência na próxima requisição.
    res.status(200).json({ 
      mensagem: "Registro de desperdício removido com sucesso.",
      id_removido: id 
    });

  } catch (error) {
    console.error("❌ Erro DELETE /losses:", error.message);
    
    // Verificação de restrição de chave estrangeira (caso você decida travar o delete no futuro)
    if (error.code === '23503') {
      return res.status(400).json({ 
        erro: "Não é possível excluir este registro pois ele está vinculado a um relatório consolidado." 
      });
    }

    res.status(500).json({ erro: "Erro técnico ao tentar excluir registro de perda." });
  }
});

// ========================================
// 🔐 MÓDULO: SEGURANÇA E IDENTIDADE
// ========================================

/**
 * ROTA: REGISTRO DE CONSULTOR (ADMIN)
 * Cria o acesso inicial ao sistema Hórus.
 */
app.post("/api/auth/register", async (req, res) => {
  const { nome, email, senha } = req.body;

  // 1. Validação de Presença e Integridade
  if (!nome || !email || !senha) {
    return res.status(400).json({ erro: "Dados incompletos. Nome, e-mail e senha são mandatórios." });
  }

  if (senha.length < 8) {
    return res.status(400).json({ erro: "Segurança fraca: a senha deve ter no mínimo 8 caracteres." });
  }

  // 2. Sanitização Rigorosa
  const emailLimpo = email.trim().toLowerCase();
  const nomeLimpo = nome.trim();

  try {
    // 3. Verificação de Duplicidade (Prevenir vazamento de erro do banco)
    const userExists = await pool.query("SELECT id FROM usuarios WHERE email = $1", [emailLimpo]);
    if (userExists.rowCount > 0) {
      return res.status(409).json({ erro: "Este e-mail já está vinculado a uma conta ativa." });
    }

    // 4. Hashing de Alta Segurança
    // O saltRounds 10 balanceia custo computacional e segurança.
    const saltRounds = 10;
    const senhaHash = await bcrypt.hash(senha, saltRounds);

    const query = `
      INSERT INTO usuarios (nome, email, senha_hash)
      VALUES ($1, $2, $3)
      RETURNING id, nome, email, criado_at;
    `;

    const result = await pool.query(query, [nomeLimpo, emailLimpo, senhaHash]);

    res.status(201).json({
      mensagem: "Usuário consultor registrado com sucesso.",
      usuario: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro Crítico no Registro:", error.message);
    res.status(500).json({ erro: "Falha interna ao processar registro de segurança." });
  }
});

// ========================================
// 🔑 MÓDULO: MOTOR DE AUTENTICAÇÃO (JWT)
// ========================================

/**
 * ROTA: LOGIN DE CONSULTOR
 * Valida credenciais e emite o passaporte digital (Token) para acesso às rotas protegidas.
 */
app.post("/api/auth/login", loginLimiter, async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ erro: "E-mail e senha são obrigatórios" });
  }

  try {
    const result = await pool.query(
      "SELECT id, nome, email, senha, tipo FROM usuarios WHERE email = $1",
      [email.toLowerCase().trim()]
    );

    const usuario = result.rows[0];

    if (!usuario) {
      return res.status(401).json({ erro: "E-mail ou senha inválidos." });
    }

    if (usuario.senha !== senha) {
      return res.status(401).json({ erro: "E-mail ou senha inválidos." });
    }

    const token = jwt.sign(
      { 
        id: usuario.id, 
        email: usuario.email,
        tipo: usuario.tipo || 'consultor'
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    console.log(`✅ Login: ${usuario.email} (ID: ${usuario.id}, Tipo: ${usuario.tipo || 'consultor'})`);

    res.json({
      success: true,
      token,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
        tipo: usuario.tipo || 'consultor'
      }
    });

  } catch (error) {
    console.error("❌ Erro no login:", error.message);
    res.status(500).json({ erro: "Erro interno ao fazer login" });
  }
});


// ========================================
// 📝 MÓDULO: PLANO DE AÇÃO (KAIZEN)
// ========================================

/**
 * ROTA: LISTAR AÇÕES POR LINHA
 * Recupera o checklist de melhorias vinculadas a uma linha específica.
 */
app.get("/api/actions/:linhaId", autenticarToken, async (req, res) => {
  try {
    const { linhaId } = req.params;
    
    const query = `
      SELECT a.*, u.nome as autor
      FROM acoes_consultor a
      LEFT JOIN usuarios u ON u.id = a.criado_por
      WHERE a.linha_id = $1 
      ORDER BY 
        CASE a.prioridade 
          WHEN 'alta' THEN 1 
          WHEN 'media' THEN 2 
          WHEN 'baixa' THEN 3 
        END ASC, 
        a.data_criacao DESC
    `;
    
    const result = await pool.query(query, [linhaId]);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("❌ Erro ao buscar ações:", error.message);
    res.status(500).json({ erro: "Falha ao recuperar plano de ação." });
  }
});

/**
 * ROTA: CRIAR AÇÃO DE MELHORIA
 * Registra uma nova tarefa no ciclo PDCA.
 */
app.post("/api/actions", autenticarToken, async (req, res) => {
  const { linha_id, texto, prioridade } = req.body;
  const usuario_id = req.usuario.id;

  if (!linha_id || !texto) {
    return res.status(400).json({ erro: "Linha e descrição da ação são obrigatórios." });
  }

  // Normalização da prioridade
  const prioridadeValida = ['alta', 'media', 'baixa'].includes(prioridade) ? prioridade : 'media';

  try {
    const query = `
      INSERT INTO acoes_consultor (linha_id, texto, prioridade, criado_por)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `;

    const result = await pool.query(query, [linha_id, texto, prioridadeValida, usuario_id]);
    res.status(201).json({ mensagem: "Ação registrada no plano de melhorias.", acao: result.rows[0] });
  } catch (error) {
    console.error("❌ Erro ao criar ação:", error.message);
    res.status(500).json({ erro: "Erro ao registrar nova ação." });
  }
});

/**
 * ROTA: ATUALIZAR STATUS/TEXTO DA AÇÃO
 * Gerencia a conclusão de tarefas e alteração de prioridades.
 */
app.put("/api/actions/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { texto, concluida, prioridade } = req.body;

  try {
    // 1. Buscamos o estado atual para lógica de data de conclusão
    const current = await pool.query("SELECT concluida FROM acoes_consultor WHERE id = $1", [id]);
    if (current.rowCount === 0) return res.status(404).json({ erro: "Ação não encontrada." });

    const statusAnterior = current.rows[0].concluida;
    const novoStatus = concluida !== undefined ? concluida : statusAnterior;
    
    // 2. Definimos se a data de conclusão deve ser setada ou limpa
    let dataConclusao = null;
    if (novoStatus === true && statusAnterior === false) dataConclusao = 'CURRENT_TIMESTAMP';
    else if (novoStatus === false) dataConclusao = 'NULL';
    else dataConclusao = 'data_conclusao'; // Mantém o valor atual se não houver mudança para true

    const query = `
      UPDATE acoes_consultor 
      SET 
        texto = COALESCE($1, texto),
        concluida = $2,
        prioridade = COALESCE($3, prioridade),
        data_conclusao = ${dataConclusao === 'CURRENT_TIMESTAMP' ? 'CURRENT_TIMESTAMP' : dataConclusao === 'NULL' ? 'NULL' : 'data_conclusao'}
      WHERE id = $4
      RETURNING *
    `;

    const result = await pool.query(query, [texto, novoStatus, prioridade, id]);
    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro ao atualizar ação:", error.message);
    res.status(500).json({ erro: "Erro técnico ao modificar ação." });
  }
});

// ========================================
// 📊 MÓDULO: AUDITORIA GRANULAR DE PROCESSO
// ========================================

/**
 * ROTA: REGISTRAR EVENTO DE CHÃO DE FÁBRICA
 * Captura ciclos, quebras ou eventos qualitativos com carimbo de autoria.
 */
app.post("/api/measurements", autenticarToken, async (req, res) => {
  const { 
    posto_id, 
    tipo,           // 'ciclo', 'parada', 'manutencao', 'setup'
    valor_numerico, 
    turno,          // 1, 2 ou 3
    descricao,
    data_medicao
  } = req.body;

  const usuario_id = req.usuario.id;

  if (!posto_id || !tipo || valor_numerico === undefined) {
    return res.status(400).json({ erro: "Posto, tipo e valor são campos mandatórios." });
  }

  try {
    const query = `
      INSERT INTO medicoes_detalhadas 
      (posto_id, tipo, valor_numerico, turno, descricao, data_medicao, criado_por)
      VALUES ($1, $2, $3, $4, $5, COALESCE($6, CURRENT_DATE), $7)
      RETURNING *
    `;

    const result = await pool.query(query, [
      posto_id, 
      tipo.toLowerCase(), 
      valor_numerico, 
      turno || 1, 
      descricao, 
      data_medicao, 
      usuario_id
    ]);

    res.status(201).json({
      mensagem: "Medição registrada com sucesso.",
      protocolo: result.rows[0].id,
      dados: result.rows[0]
    });
  } catch (error) {
    console.error("❌ Erro no registro de medição:", error.message);
    res.status(500).json({ erro: "Falha técnica ao salvar medição detalhada." });
  }
});

/**
 * ROTA: DASHBOARD ESTATÍSTICO DO POSTO
 * Consolida os KPIs de variabilidade e médias para o consultor.
 */
app.get("/api/measurements/stats/:postoId", autenticarToken, async (req, res) => {
  try {
    const { postoId } = req.params;

    const query = `
      SELECT 
        tipo,
        COUNT(*) as amostras,
        ROUND(AVG(valor_numerico), 2) as media,
        ROUND(MIN(valor_numerico), 2) as minimo,
        ROUND(MAX(valor_numerico), 2) as maximo,
        ROUND(STDDEV(valor_numerico), 2) as desvio_padrao,
        -- Coeficiente de Variação (CV): Mede a estabilidade do tipo de evento
        ROUND((STDDEV(valor_numerico) / NULLIF(AVG(valor_numerico), 0)) * 100, 2) as cv_percentual
      FROM medicoes_detalhadas
      WHERE posto_id = $1
      GROUP BY tipo
      ORDER BY amostras DESC
    `;

    const result = await pool.query(query, [postoId]);

    if (result.rowCount === 0) {
      return res.status(200).json({ mensagem: "Sem dados para estatísticas neste posto.", dados: [] });
    }

    res.status(200).json({
      posto_id: postoId,
      analise_estatistica: result.rows
    });
  } catch (error) {
    console.error("❌ Erro ao calcular estatísticas:", error.message);
    res.status(500).json({ erro: "Erro ao processar inteligência estatística." });
  }
});

// ========================================
// 🚀 MÓDULO: SETUP E INICIALIZAÇÃO (MASTER)
// ========================================

/**
 * ROTA: SETUP GLOBAL
 * Cria a estrutura de dados completa, respeitando as dependências de engenharia.
 */
app.get("/api/admin/setup-db", async (req, res) => {
  // Nota: Em produção, esta rota deve ser protegida por uma chave de API 
  // ou desativada após a primeira execução.
  
  try {
    // 1. Tabela de Usuários (Base para Auditoria)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        nome VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        senha_hash TEXT NOT NULL,
        criado_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 2. Estrutura Física (Linhas e Postos)
    // Assumindo que linha_producao e posto_trabalho já existem conforme blocos anteriores
    // mas garantindo as tabelas de suporte do consultor:

    await pool.query(`
      CREATE TABLE IF NOT EXISTS acoes_consultor (
        id SERIAL PRIMARY KEY,
        linha_id INTEGER NOT NULL REFERENCES linha_producao(id) ON DELETE CASCADE,
        texto TEXT NOT NULL,
        concluida BOOLEAN DEFAULT FALSE,
        prioridade VARCHAR(20) CHECK (prioridade IN ('baixa', 'media', 'alta')) DEFAULT 'media',
        data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        data_conclusao TIMESTAMP,
        criado_por INTEGER REFERENCES usuarios(id) ON DELETE SET NULL
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS medicoes_detalhadas (
        id SERIAL PRIMARY KEY,
        posto_id INTEGER NOT NULL REFERENCES posto_trabalho(id) ON DELETE CASCADE,
        tipo VARCHAR(20) NOT NULL, -- 'ciclo', 'parada', 'setup', 'evento'
        valor_numerico DECIMAL(10,2) NOT NULL,
        turno INTEGER CHECK (turno IN (1, 2, 3)),
        descricao TEXT,
        data_medicao DATE DEFAULT CURRENT_DATE,
        hora_medicao TIME DEFAULT CURRENT_TIME,
        criado_por INTEGER REFERENCES usuarios(id) ON DELETE SET NULL
      );
    `);

    // 3. Índice de Performance (Otimização de buscas por data)
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_medicoes_data ON medicoes_detalhadas(data_medicao);`);

    res.status(200).json({ 
      status: "Sucesso",
      mensagem: "Infraestrutura Hórus consolidada.",
      tabelas_verificadas: ["usuarios", "acoes_consultor", "medicoes_detalhadas"]
    });

  } catch (error) {
    console.error("❌ FALHA NO SETUP CRÍTICO:", error.message);
    res.status(500).json({ erro: "Falha ao estruturar banco de dados." });
  }
});

// ========================================
// 🗑️ MÓDULO: PURGA DE AUDITORIA
// ========================================

/**
 * ROTA: EXCLUIR MEDIÇÃO DETALHADA
 * Remove registros de ciclos ou paradas que foram inseridos incorretamente.
 */
app.delete("/api/measurements/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Retornamos o tipo e o valor para que o log de auditoria seja preciso
    const result = await pool.query(
      "DELETE FROM medicoes_detalhadas WHERE id = $1 RETURNING id, tipo, valor_numerico",
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Medição não localizada para exclusão." });
    }

    // Log interno para controle do consultor
    console.warn(`[DATA_CLEANUP] Medição ${id} removida por Usuário ID: ${req.usuario.id}`);

    res.status(200).json({ 
      mensagem: "Registro de medição removido com sucesso.",
      detalhes: result.rows[0]
    });
  } catch (error) {
    console.error("❌ Erro ao excluir medição:", error.message);
    res.status(500).json({ erro: "Falha técnica ao remover registro de auditoria." });
  }
});

// ========================================
// 📈 MÓDULO: INTELIGÊNCIA TEMPORAL (BI)
// ========================================

/**
 * ROTA: TENDÊNCIA HISTÓRICA DE PERFORMANCE
 * Gera a série temporal para gráficos de linha (OEE vs Estabilidade).
 * ✅ CORRIGIDO: Agora inclui média de ciclo e desvio padrão
 */
app.get("/api/history/line/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;

  try {
    // Buscar dados agregados por mês da tabela producao_oee
    // e também dados de ciclo das medições
    const query = `
      WITH dados_oee_por_mes AS (
        SELECT 
          DATE_TRUNC('month', data) as mes,
          AVG(oee) as oee_medio,
          AVG(disponibilidade) as disponibilidade_media,
          AVG(performance) as performance_media,
          AVG(qualidade) as qualidade_media,
          COUNT(*) as quantidade_registros
        FROM producao_oee
        WHERE linha_id = $1
        GROUP BY DATE_TRUNC('month', data)
      ),
      dados_ciclo_por_mes AS (
        SELECT 
          DATE_TRUNC('month', cm.data_medicao) as mes,
          AVG(cm.tempo_ciclo_segundos::numeric) as media_ciclo,
          STDDEV(cm.tempo_ciclo_segundos::numeric) as desvio_ciclo
        FROM ciclo_medicao cm
        JOIN posto_trabalho pt ON pt.id = cm.posto_id
        WHERE pt.linha_id = $1
        GROUP BY DATE_TRUNC('month', cm.data_medicao)
      )
      SELECT 
        TO_CHAR(COALESCE(o.mes, c.mes), 'YYYY-MM') as periodo,
        ROUND(COALESCE(o.oee_medio, 0), 2) as oee_performance,
        ROUND(COALESCE(o.disponibilidade_media, 0), 2) as disponibilidade,
        ROUND(COALESCE(o.performance_media, 0), 2) as performance,
        ROUND(COALESCE(o.qualidade_media, 0), 2) as qualidade,
        COALESCE(o.quantidade_registros, 0) as medicoes,
        ROUND(COALESCE(c.media_ciclo, 0), 2) as media_ciclo,
        ROUND(COALESCE(c.desvio_ciclo, 0), 2) as desvio_padrao
      FROM dados_oee_por_mes o
      FULL OUTER JOIN dados_ciclo_por_mes c ON o.mes = c.mes
      ORDER BY periodo ASC
    `;

    const result = await pool.query(query, [linhaId]);

    if (result.rows.length === 0) {
      return res.status(200).json({ 
        mensagem: "Histórico insuficiente para análise de tendência.",
        historico: [],
        dados: []
      });
    }

    res.status(200).json({
      linha_id: linhaId,
      periodo: "Últimos meses",
      historico: result.rows,
      dados: result.rows
    });

  } catch (error) {
    console.error("❌ Erro na análise histórica:", error.message);
    res.status(500).json({ erro: "Falha ao processar inteligência temporal." });
  }
});

// ========================================
// 📦 MÓDULO: CATÁLOGO DE PRODUTOS
// ========================================

/**
 * ROTA: FILTRAR PRODUTOS POR EMPRESA
 * Essencial para o seletor dinâmico do Dashboard Hórus.
 */
app.get("/api/products/company/:empresa_id", autenticarToken, async (req, res) => {
  const { empresa_id } = req.params;

  try {
    const idNum = parseInt(empresa_id, 10);
    if (isNaN(idNum)) {
      return res.status(400).json({ erro: "ID da empresa inválido." });
    }

    const query = `
      SELECT id, nome, valor_unitario 
      FROM produtos 
      WHERE empresa_id = $1 
      ORDER BY nome ASC
    `;

    const result = await pool.query(query, [idNum]);
    
    // Retornamos um array vazio caso não haja produtos, para não quebrar o .map() no Front
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("❌ Erro ao filtrar produtos:", error.message);
    res.status(500).json({ erro: "Falha técnica ao recuperar catálogo da empresa." });
  }
});

/**
 * ROTA: CRIAR NOVO PRODUTO
 * Vincula o item à empresa para garantir a separação de dados (Multi-tenant).
 */
app.post("/api/products", autenticarToken, async (req, res) => {
  const { nome, valor_unitario, empresa_id } = req.body;

  if (!nome || !empresa_id) {
    return res.status(400).json({ erro: "Nome e ID da empresa são obrigatórios." });
  }

  try {
    const query = `
      INSERT INTO produtos (nome, valor_unitario, empresa_id)
      VALUES ($1, $2, $3)
      RETURNING *
    `;

    const result = await pool.query(query, [
      nome.trim(), 
      parseFloat(valor_unitario) || 0, 
      empresa_id
    ]);

    res.status(201).json({
      mensagem: "Produto cadastrado com sucesso.",
      produto: result.rows[0]
    });
  } catch (error) {
    console.error("❌ Erro ao criar produto:", error.message);
    res.status(500).json({ erro: "Erro ao processar cadastro de produto." });
  }
});

/**
 * ROTA: ATUALIZAR PRODUTO
 */
app.put("/api/products/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { nome, valor_unitario } = req.body;

  try {
    const query = `
      UPDATE produtos 
      SET 
        nome = COALESCE($1, nome), 
        valor_unitario = COALESCE($2, valor_unitario)
      WHERE id = $3
      RETURNING *
    `;

    const result = await pool.query(query, [
      nome ? nome.trim() : null, 
      valor_unitario !== undefined ? parseFloat(valor_unitario) : null, 
      id
    ]);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Produto não localizado." });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro ao atualizar produto:", error.message);
    res.status(500).json({ erro: "Erro técnico na atualização do produto." });
  }
});

/**
 * ROTA: EXCLUIR PRODUTO
 */
app.delete("/api/products/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query("DELETE FROM produtos WHERE id = $1 RETURNING nome", [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Produto não localizado." });
    }

    res.status(200).json({ mensagem: `Produto '${result.rows[0].nome}' removido com sucesso.` });
  } catch (error) {
    console.error("❌ Erro ao excluir produto:", error.message);
    // Verificação de FK: Não deixa excluir produto se ele estiver em uma linha_produto
    if (error.code === '23503') {
      return res.status(400).json({ erro: "Não é possível excluir um produto vinculado a linhas de produção ativas." });
    }
    res.status(500).json({ erro: "Erro ao tentar remover o produto." });
  }
});

// ========================================
// 📦 MÓDULO: CATALOGO POR CLIENTE
// ========================================

/**
 * ROTA: LISTAR PRODUTOS POR EMPRESA
 * Sincroniza o seletor de produtos com o cliente selecionado no Hórus.
 */
app.get("/api/products/by-company/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;

  try {
    // Garantimos que o ID é um número para evitar ataques de injeção ou erros de tipo
    const idValidado = parseInt(empresaId, 10);
    
    if (isNaN(idValidado)) {
      return res.status(400).json({ erro: "O ID da empresa fornecido é inválido." });
    }

    // Query otimizada na tabela correta (plural)
    const query = `
      SELECT 
        id, 
        nome, 
        valor_unitario,
        criado_at
      FROM produtos 
      WHERE empresa_id = $1 
      ORDER BY nome ASC
    `;

    const result = await pool.query(query, [idValidado]);

    // Retorno de sucesso, mesmo que a lista esteja vazia
    res.status(200).json(result.rows);

  } catch (error) {
    console.error("❌ Erro GET /products/by-company:", error.message);
    res.status(500).json({ 
      erro: "Falha ao recuperar o catálogo de produtos desta unidade." 
    });
  }
});

// ========================================
// 🔗 MÓDULO: VÍNCULO OPERAÇÃO-PRODUTO
// ========================================

/**
 * ROTA: LISTAR PRODUTOS CONFIGURADOS NA LINHA
 * Recupera o mix de produção e as metas específicas (Takt) de cada SKU.
 */
app.get("/api/line-products/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;

  try {
    const query = `
      SELECT 
        lp.id as vinculo_id,
        lp.produto_id,
        p.nome as produto_nome,
        p.valor_unitario,
        lp.takt_time_segundos as takt_configurado,
        lp.meta_diaria,
        -- KPI: Capacidade Teórica (Peças/Hora) baseada no Takt
        ROUND(3600 / NULLIF(lp.takt_time_segundos, 0), 2) as capacidade_teorica_hora
      FROM linha_produto lp
      JOIN produtos p ON p.id = lp.produto_id
      WHERE lp.linha_id = $1
      ORDER BY p.nome ASC
    `;

    const result = await pool.query(query, [linhaId]);

    if (result.rowCount === 0) {
      return res.status(200).json({ 
        mensagem: "Nenhum produto configurado para esta linha de produção.",
        dados: [] 
      });
    }

    res.status(200).json(result.rows);
  } catch (error) {
    console.error("❌ Erro GET /line-products:", error.message);
    res.status(500).json({ erro: "Erro ao recuperar mix de produtos da linha." });
  }
});

// ========================================
// 💰 MÓDULO: ECONOMETRIA INDUSTRIAL - CORRIGIDO ✅
// ========================================

/**
 * ROTA: ANÁLISE DE CUSTO OPERACIONAL (OPEX)
 * Traduz a estrutura de postos e cargos em custo por minuto/hora.
 */
app.get("/api/finance/line/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;

  try {
    // 1. Consolidação de Dados: Linha, Empresa e Calendário
    // ✅ CORREÇÃO 1: 'empresas' (plural) em vez de 'empresa'
    // ✅ CORREÇÃO 2: Removeu 'horas_turno_diario' que não existe
    const queryMaster = `
      SELECT 
        l.id, l.nome, l.empresa_id,
        COALESCE(e.dias_produtivos_mes, 22) as dias_produtivos_mes
      FROM linhas_producao l
      JOIN empresas e ON e.id = l.empresa_id
      WHERE l.id = $1
    `;
    const linhaRes = await pool.query(queryMaster, [linhaId]);

    if (linhaRes.rowCount === 0) return res.status(404).json({ erro: "Linha não localizada." });

    const linha = linhaRes.rows[0];
    const diasMes = linha.dias_produtivos_mes || 22;
    const horasDia = 8; // ✅ FIXO: 8 horas por dia (padrão industrial)

    // 2. Cálculo de Mão de Obra Direta (MOD) com Join de Cargos
    const postosRes = await pool.query(`
      SELECT 
        pt.id, pt.nome as posto_nome,
        pt.tempo_setup_minutos,
        c.nome as cargo_nome,
        COALESCE(c.salario_base, 0) as salario,
        COALESCE(c.encargos_percentual, 70) as encargos
      FROM posto_trabalho pt
      LEFT JOIN cargos c ON c.id = pt.cargo_id
      WHERE pt.linha_id = $1
    `, [linhaId]);

    let totalMensalMOD = 0;
    const minutosDisponiveisMes = diasMes * horasDia * 60;
    
    const detalhamentoPostos = postosRes.rows.map(p => {
      const salario = parseFloat(p.salario) || 0;
      const encargos = parseFloat(p.encargos) || 70;
      const custoMensal = salario * (1 + (encargos / 100));
      totalMensalMOD += custoMensal;
      
      // ✅ NOVO: Calcula custo de setup por dia
      const custoPorMinuto = minutosDisponiveisMes > 0 ? totalMensalMOD / minutosDisponiveisMes : 0;
      const tempoSetupMinutos = parseFloat(p.tempo_setup_minutos) || 0;
      const custoSetupDia = tempoSetupMinutos * custoPorMinuto;
      
      return {
        id: p.id,
        posto: p.posto_nome,
        cargo: p.cargo_nome || "❌ Não definido",
        salario_base: salario,
        encargos_percentual: encargos,
        custo_mensal: Math.round(custoMensal * 100) / 100,
        tempo_setup_minutos: tempoSetupMinutos,
        custo_setup_dia: Math.round(custoSetupDia * 100) / 100
      };
    });

    // 3. Cálculo dos custos agregados
    const custoMinuto = minutosDisponiveisMes > 0 ? totalMensalMOD / minutosDisponiveisMes : 0;

    res.status(200).json({
      meta_dados: {
        linha: linha.nome,
        base_calculo: `${diasMes} dias/mês, ${horasDia}h/dia`
      },
      financeiro: {
        custo_mod_mensal: Math.round(totalMensalMOD * 100) / 100,
        custo_por_hora: Math.round((custoMinuto * 60) * 100) / 100,
        custo_por_minuto: Math.round(custoMinuto * 100) / 100
      },
      detalhamento: detalhamentoPostos
    });

  } catch (error) {
    console.error("❌ Erro no cálculo financeiro:", error.message);
    res.status(500).json({ erro: "Falha ao processar indicadores financeiros da linha." });
  }
});

// ========================================
// 🏛️ MÓDULO: EXECUTIVO / CONSOLIDAÇÃO FINANCEIRA
// ========================================

/**
 * ROTA: DASHBOARD FINANCEIRO CORPORATIVO
 * Consolida o custo de todas as linhas de produção da empresa em uma única chamada.
 */
app.get("/api/finance/corporate/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;

  try {
    const query = `
      WITH custo_por_posto AS (
        SELECT 
          l.id as linha_id,
          l.nome as linha_nome,
          e.dias_produtivos_mes,
          e.horas_turno_diario,
          COALESCE(c.salario_base * (1 + (COALESCE(c.encargos_percentual, 70) / 100)), 0) as custo_posto_mensal
        FROM linhas_producao l
        JOIN empresa e ON e.id = l.empresa_id
        LEFT JOIN posto_trabalho pt ON pt.linha_id = l.id
        LEFT JOIN cargos c ON c.id = pt.cargo_id
        WHERE l.empresa_id = $1
      ),
      consolidado_linhas AS (
        SELECT 
          linha_id,
          linha_nome,
          SUM(custo_posto_mensal) as custo_total_linha,
          MIN(dias_produtivos_mes) as dias,
          MIN(horas_turno_diario) as horas
        FROM custo_por_posto
        GROUP BY linha_id, linha_nome
      )
      SELECT 
        linha_id,
        linha_nome,
        ROUND(custo_total_linha, 2) as custo_mensal,
        ROUND(custo_total_linha / NULLIF(dias * horas * 60, 0), 2) as custo_minuto
      FROM consolidado_linhas;
    `;

    const result = await pool.query(query, [empresaId]);

    const custoTotalGlobal = result.rows.reduce((acc, row) => acc + parseFloat(row.custo_mensal), 0);

    res.status(200).json({
      empresa_id: empresaId,
      indicadores_globais: {
        custo_total_mensal_mod: Math.round(custoTotalGlobal * 100) / 100,
        total_linhas_ativas: result.rowCount
      },
      detalhamento_por_linha: result.rows
    });

  } catch (error) {
    console.error("❌ Erro na consolidação corporativa:", error.message);
    res.status(500).json({ erro: "Falha ao gerar relatório financeiro executivo." });
  }
});

// ========================================
// 👥 MÓDULO: GESTÃO DE EFETIVO (ALOCAÇÃO)
// ========================================

/**
 * ROTA: CRIAR ALOCAÇÃO
 * Garante que um colaborador não esteja em dois lugares ao mesmo tempo.
 */
app.post("/api/allocations", autenticarToken, async (req, res) => {
  const { colaborador_id, posto_id, turno, data_inicio } = req.body;

  if (!colaborador_id || !posto_id || !turno) {
    return res.status(400).json({ erro: "Dados incompletos para alocação." });
  }

  try {
    // 1. Validação de Onipresença: Colaborador já está ocupado?
    const conflict = await pool.query(
      `SELECT id FROM alocacao_colaborador 
       WHERE colaborador_id = $1 AND turno = $2 AND ativo = true`,
      [colaborador_id, turno]
    );

    if (conflict.rowCount > 0) {
      return res.status(409).json({ 
        erro: "Conflito: Este colaborador já está alocado em outro posto neste turno." 
      });
    }

    // 2. Registro da Alocação
    const query = `
      INSERT INTO alocacao_colaborador (colaborador_id, posto_id, turno, data_inicio, ativo)
      VALUES ($1, $2, $3, COALESCE($4, CURRENT_DATE), true)
      RETURNING *
    `;

    const result = await pool.query(query, [colaborador_id, posto_id, turno, data_inicio]);
    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error("❌ Erro ao alocar:", error.message);
    res.status(500).json({ erro: "Falha técnica na alocação." });
  }
});

/**
 * ROTA: LISTAR ALOCAÇÕES POR POSTO
 * Útil para o Supervisor ver quem escalou para o dia.
 */
app.get("/api/allocations/station/:postoId", autenticarToken, async (req, res) => {
  const { postoId } = req.params;
  const { ativo } = req.query;

  try {
    const query = `
      SELECT 
        a.id, a.posto_id, a.turno, a.data_inicio, a.ativo,
        c.nome as colaborador,
        cg.nome as cargo,
        cg.salario_base
      FROM alocacao_colaborador a
      JOIN colaborador c ON c.id = a.colaborador_id
      JOIN cargos cg ON cg.id = c.cargo_id
      WHERE a.posto_id = $1
      ${ativo === 'true' ? 'AND a.ativo = true' : ''}
      ORDER BY a.turno ASC, a.data_inicio DESC
    `;

    const result = await pool.query(query, [postoId]);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("❌ Erro ao buscar alocação:", error.message);
    res.status(500).json({ erro: "Erro ao recuperar escala do posto." });
  }
});

/**
 * ROTA: DESALOCAR COLABORADOR (UPDATE)
 * Remove a alocação de um colaborador (set ativo = false)
 */
app.put("/api/allocations/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { ativo } = req.body;

  try {
    const result = await pool.query(
      `UPDATE alocacao_colaborador 
       SET ativo = COALESCE($1, false),
           data_fim = CASE WHEN COALESCE($1, false) = false THEN CURRENT_DATE ELSE data_fim END,
           atualizado_em = CURRENT_TIMESTAMP
       WHERE id = $2
       RETURNING *`,
      [ativo !== undefined ? ativo : false, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Alocação não encontrada." });
    }

    res.status(200).json({
      mensagem: "Colaborador desalocado com sucesso!",
      alocacao: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro ao desalocar:", error.message);
    res.status(500).json({ erro: "Falha ao desalocar colaborador." });
  }
});

// ========================================
// 🤖 MÓDULO: GERADOR DE DIAGNÓSTICO (REPORTING)
// ========================================

/**
 * ROTA: GERAR RELATÓRIO EXECUTIVO
 * Transforma dados brutos em narrativa de consultoria estratégica.
 */
app.post("/api/reports/generate", autenticarToken, async (req, res) => {
  const { dados, tipo, usar_ia } = req.body;

  if (!dados || !tipo) {
    return res.status(400).json({ erro: "Parâmetros de dados e tipo são obrigatórios." });
  }

  try {
    // 1. Extração de Variáveis Críticas
    const oee = dados.analise?.eficiencia_percentual || 0;
    const perdas = dados.perdasFinanceiras || { setup: 0, micro: 0, refugo: 0, total: 0 };
    const empresa = dados.empresa || "Cliente Hórus";
    
    // 2. Lógica de Classificação Industrial
    const getStatus = (val) => {
      if (val < 40) return { label: "CRÍTICO", cor: "RED" };
      if (val < 65) return { label: "REGULAR", cor: "YELLOW" };
      if (val < 85) return { label: "BOM", cor: "BLUE" };
      return { label: "EXCELENTE (WORLD CLASS)", cor: "GREEN" };
    };

    const status = getStatus(oee);

    // 3. Template Estruturado (Markdown Ready para o Front-end)
    const relatorioBase = `
# 📊 DIAGNÓSTICO ESTRATÉGICO DE PROCESSO
**Empresa:** ${empresa} | **Data:** ${new Date().toLocaleDateString('pt-BR')}

## 1. RESUMO EXECUTIVO
A operação atual apresenta um **OEE de ${oee}%**, classificado como **${status.label}**. 
O impacto financeiro das ineficiências é estimado em **R$ ${perdas.total.toLocaleString('pt-BR', { minimumFractionDigits: 2 })}/mês**.

## 2. DECOMPOSIÇÃO DAS PERDAS (OPEX)
* **Setups/Trocas:** R$ ${perdas.setup.toLocaleString('pt-BR')} (Foco: SMED)
* **Microparadas:** R$ ${perdas.micro.toLocaleString('pt-BR')} (Foco: Manutenção Autônoma)
* **Qualidade (Refugo):** R$ ${perdas.refugo.toLocaleString('pt-BR')} (Foco: Six Sigma)

## 3. PROJEÇÃO DE RECUPERAÇÃO (ROI)
Ao reduzir o desperdício atual, a empresa projeta um ganho de:
* **Cenário Conservador (10%):** + R$ ${(perdas.total * 0.1).toFixed(2)}/mês
* **Cenário Otimista (30%):** + R$ ${(perdas.total * 0.3).toFixed(2)}/mês

## 4. RECOMENDAÇÕES DO CONSULTOR (S.M.A.R.T)
1.  **Imediato:** Atacar o gargalo identificado em "${dados.analise?.gargalo || 'Posto Desconhecido'}".
2.  **Médio Prazo:** Padronização de ciclos para reduzir o desvio padrão (Estabilidade).
3.  **Cultura:** Implementar gestão visual via Dashboard Hórus no chão de fábrica.
    `;

    // Futura Integração: aqui entraria o chamado para a API da Gemini
    // if (usar_ia) { ... }

    res.status(200).json({ 
      relatorio: relatorioBase.trim(),
      metadata: { status: status.label, oee, impacto: perdas.total }
    });

  } catch (error) {
    console.error("❌ Erro ao gerar relatório:", error.message);
    res.status(500).json({ erro: "Falha na motor de geração de relatórios." });
  }
});

// ========================================
// 👔 MÓDULO: IDENTIDADE NEXUS (CONSULTOR)
// ========================================

/**
 * ROTA: SETUP EXECUTIVO
 * Inicializa o perfil do consultor mestre e métricas de carreira.
 */
app.get("/api/consultant/master-setup", async (req, res) => {
  try {
    // 1. Tabela com métricas de Business Intelligence (BI) do próprio consultor
    await pool.query(`
      CREATE TABLE IF NOT EXISTS consultores (
        id SERIAL PRIMARY KEY,
        nome VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        senha_hash VARCHAR(255) NOT NULL,
        cargo VARCHAR(50),
        faturamento_mes DECIMAL(12,2) DEFAULT 0,
        roi_medio_entregue DECIMAL(4,2) DEFAULT 0,
        projetos_ativos INTEGER DEFAULT 0,
        missao TEXT,
        visao TEXT,
        valores TEXT[],
        data_cadastro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 2. Upsert do Perfil Nexus (Limpa e recria para garantir integridade)
    const emailMaster = "henriquelimapaiva@nexus.com.br";
    await pool.query("DELETE FROM consultores WHERE email = $1", [emailMaster]);

    const hash = await bcrypt.hash("Nexus2903.", 10);
    
    const insertQuery = `
      INSERT INTO consultores (nome, email, senha_hash, cargo, missao, visao, valores, faturamento_mes, roi_medio_entregue)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING id;
    `;

    const values = [
      "Henrique de Lima Paiva",
      emailMaster,
      hash,
      "Consultor Sênior & Especialista em Processos",
      "Transformar indústrias através da engenharia aplicada e dados.",
      "Ser referência nacional em otimização industrial até 2030.",
      ["Excelência Técnica", "Transparência", "Resultado"],
      45000.00,
      3.2
    ];

    await pool.query(insertQuery, values);

    res.status(201).json({ 
      status: "Master Profile Ready",
      context: "Nexus Consulting Group",
      auth_check: "Bcrypt Hash Verified"
    });

  } catch (error) {
    console.error("❌ Erro no Setup Nexus:", error.message);
    res.status(500).json({ erro: "Falha ao inicializar perfil mestre." });
  }
});

/**
 * ROTA: LOGIN EXECUTIVO (NEXUS AUTH)
 */
app.post("/api/consultant/login", loginLimiter, async (req, res) => {
  const { email, senha } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM consultores WHERE LOWER(email) = LOWER($1)",
      [email?.trim()]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({ erro: "Acesso negado: Perfil não identificado." });
    }

    const consultor = result.rows[0];
    const valid = await bcrypt.compare(senha, consultor.senha_hash);

    if (!valid) {
      return res.status(401).json({ erro: "Acesso negado: Credenciais inválidas." });
    }

    const token = jwt.sign(
      { id: consultor.id, email: consultor.email, role: "master_consultant" },
      JWT_SECRET,
      { expiresIn: "12h" } // Tempo estendido para jornadas de consultoria em campo
    );

    res.json({
      token,
      profile: {
        nome: consultor.nome,
        cargo: consultor.cargo,
        faturamento_ref: consultor.faturamento_mes
      }
    });
  } catch (error) {
    res.status(500).json({ erro: "Erro crítico na autenticação Nexus." });
  }
});

// ========================================
// 📈 MÓDULO: SALES AUTOMATION (NEXUS)
// ========================================

/**
 * ROTA: GERADOR DE PROPOSTA COMERCIAL
 * Transforma indicadores de desperdício em uma proposta de investimento.
 */
app.post("/api/sales/generate-proposal", autenticarToken, async (req, res) => {
  const { dadosProposta } = req.body;

  if (!dadosProposta) {
    return res.status(400).json({ erro: "Parâmetros da proposta não identificados." });
  }

  try {
    const { diagnostico, investimento, retorno, empresa } = dadosProposta;

    // Formatação de Moeda Brasileira
    const fmt = (val) => 
      new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL' }).format(val || 0);

    const propostaMarkdown = `
# 📄 PROPOSTA COMERCIAL: OTIMIZAÇÃO INDUSTRIAL
**Nexus Engenharia Aplicada** | **Data:** ${new Date().toLocaleDateString('pt-BR')}

---

### 1. OBJETIVO
Apresentamos este plano estratégico para a **${empresa || "sua organização"}**, visando a recuperação de margem operacional através da eliminação de desperdícios e estabilização de processos.

### 2. CENÁRIO ATUAL (OPORTUNIDADE)
Identificamos um potencial latente de faturamento não realizado:
* **OEE Médio:** ${diagnostico?.oeeMedio || 0}%
* **Vulnerabilidade Financeira:** ${fmt(diagnostico?.perdasTotais)} / mês
* **Complexidade:** ${diagnostico?.totalLinhas} Linhas | ${diagnostico?.totalPostos} Postos

### 3. INVESTIMENTO E CONDIÇÕES
Para a execução do projeto Hórus/Nexus, o investimento será de:
* **Valor Global:** ${fmt(investimento?.honorarios)}
* **Condição:** 50% de sinal e saldo em 30 dias após entrega do diagnóstico.

### 4. ROI & PAYBACK (A VIABILIDADE)
Este projeto se autofinancia através da economia gerada:
* **Ganho Mensal Projetado (Cenário 20%):** ${fmt((diagnostico?.perdasTotais || 0) * 0.2)}
* **Payback Estimado:** ${retorno?.payback || "A definir"} meses.
* **ROI Anual:** ${retorno?.roiAnual || 0}%

---

### 5. ESCOPO TÉCNICO
1.  Mapeamento de Fluxo de Valor (VSM);
2.  Cronometragem e Takt Time via Plataforma Hórus;
3.  Treinamento de Equipes (Manutenção Autônoma e 5S);
4.  Implementação de Dashboards de Gestão Visual.

**Atenciosamente,**

**Henrique de Lima Paiva**
*Consultor Sênior - Nexus Engenharia Aplicada*
    `;

    res.status(200).json({ 
      proposta: propostaMarkdown.trim(),
      resumo_venda: {
        ticket_medio: investimento?.honorarios,
        potencial_cliente: diagnostico?.perdasTotais
      }
    });

  } catch (error) {
    console.error("❌ Erro no Sales Engine:", error.message);
    res.status(500).json({ erro: "Falha ao redigir proposta comercial." });
  }
});

// ========================================
// 📜 MÓDULO: LEGAL & CONTRACT AUTOMATION
// ========================================

/**
 * ROTA: GERADOR DE PROPOSTA E MINUTA CONTRATUAL
 * Consolida indicadores técnicos, comerciais e jurídicos em um único output.
 */
app.post("/api/legal/generate-full-contract", autenticarToken, async (req, res) => {
  const dados = req.body;

  if (!dados || !dados.empresa) {
    return res.status(400).json({ erro: "Dados da contratante são obrigatórios para gerar o instrumento." });
  }

  try {
    // 1. Helpers de Formatação
    const moeda = (val) => 
      new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL' }).format(val || 0);
    
    const dataHoje = new Date().toLocaleDateString('pt-BR');

    // 2. Construção do Documento (Markdown Estruturado)
    const documentoFinal = `
# PROPOSTA COMERCIAL E MINUTA CONTRATUAL - NEXUS
**Ref:** Otimização de Processos Industriais | **Data:** ${dataHoje}

---

## I. PROPOSTA TÉCNICA
**Diagnóstico Consolidado para ${dados.empresa}:**
* **OEE Atual:** ${dados.oeeMedio}% (Gap de ${(85 - dados.oeeMedio).toFixed(1)}% p/ World Class)
* **Impacto Financeiro:** ${moeda(dados.perdasTotais)}/mês de desperdício identificado.
* **Complexidade Operacional:** ${dados.totalLinhas} Linhas e ${dados.totalPostos} Postos de Trabalho.

### CRONOGRAMA DE ENTREGA
1. **Fase 1 (Diagnóstico):** 2 Semanas - Mapeamento VSM e Cronoanálise.
2. **Fase 2 (Implantação):** 4 Semanas - SMED, Kaizen e Padronização.
3. **Fase 3 (Sustentação):** ${dados.mesesAcompanhamento || 3} Meses - Monitoramento de KPIs.

---

## II. INVESTIMENTO E ROI
* **Honorários Nexus:** ${moeda(dados.honorarios)}
* **Payback Estimado:** ${dados.payback} meses.
* **Ganho Projetado (Cenário 20%):** ${moeda((dados.perdasTotais || 0) * 0.2)} acumulado mensalmente.

---

## III. MINUTA CONTRATUAL (RESUMO)
**CONTRATANTE:** ${dados.empresa}
**CONTRATADA:** NEXUS ENGENHARIA APLICADA

**CLÁUSULA DE CONFIDENCIALIDADE:** As partes obrigam-se a manter sigilo absoluto por 5 anos, sob multa de R$ 50.000,00 por evento de violação.
**CLÁUSULA DE PROPRIEDADE:** A metodologia Hórus/Nexus é propriedade intelectual exclusiva da CONTRATADA.
**FORO:** Eleito o foro de Diadema/SP para dirimir questões deste instrumento.

---
*Documento gerado automaticamente pela plataforma Hórus em ${dataHoje}.*
    `;

    res.status(200).json({ 
      documento: documentoFinal.trim(),
      metadata: {
        empresa: dados.empresa,
        valor_total: dados.honorarios,
        risco_perda: dados.perdasTotais
      }
    });

  } catch (error) {
    console.error("❌ Erro no Legal Engine:", error.message);
    res.status(500).json({ erro: "Falha ao processar minuta contratual." });
  }
});

// ========================================
// 🧠 MÓDULO: MOTOR DE INSIGHTS INDUSTRIAIS
// ========================================

/**
 * ROTA: DIAGNÓSTICO AUTOMATIZADO
 * Analisa a saúde da fábrica e gera planos de ação baseados em ROI.
 */
app.get("/api/insights/factory-health/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;

  try {
    // 1. Query Única de Alta Performance (Evitando loops de rede)
    const rawData = await pool.query(`
      SELECT 
        l.id as linha_id, l.nome as linha_nome,
        pt.id as posto_id, pt.nome as posto_nome, pt.tempo_ciclo_segundos as ciclo,
        pt.tempo_setup_minutos as setup, pt.disponibilidade_percentual as disp,
        c.salario_base, c.encargos_percentual,
        (SELECT SUM(refugo_pecas) FROM perdas_linha pl 
         JOIN linha_produto lp ON lp.id = pl.linha_produto_id 
         WHERE lp.linha_id = l.id) as refugo_total
      FROM linhas_producao l
      JOIN posto_trabalho pt ON pt.linha_id = l.id
      LEFT JOIN cargos c ON c.id = pt.cargo_id
      WHERE l.empresa_id = $1
    `, [empresaId]);

    if (rawData.rowCount === 0) {
      return res.json({ resumo: "Aguardando dados de postos para análise.", acoes: [] });
    }

    const insights = [];
    let roiGlobalMensal = 0;

    // 2. Processamento da Lógica de Consultoria Nexus
    // Agrupamos por linha para identificar gargalos reais
    const linhasMap = rawData.rows.reduce((acc, row) => {
      if (!acc[row.linha_id]) acc[row.linha_id] = { nome: row.linha_nome, postos: [] };
      acc[row.linha_id].postos.push(row);
      return acc;
    }, {});

    Object.values(linhasMap).forEach(linha => {
      // Identificar Gargalo (Maior Ciclo Real)
      const gargalo = linha.postos.reduce((prev, current) => 
        (current.ciclo / (current.disp / 100)) > (prev.ciclo / (prev.disp / 100)) ? current : prev
      );

      const custoMinuto = (parseFloat(gargalo.salario_base) * (1 + (gargalo.encargos_percentual / 100))) / (22 * 8 * 60);

      // INSIGHT: SMED (Troca Rápida)
      if (gargalo.setup > 15) {
        const ganho = Math.round(gargalo.setup * 0.4 * 22 * custoMinuto);
        roiGlobalMensal += ganho;
        insights.push({
          tipo: 'CRÍTICO',
          titulo: `Redução de Setup: ${gargalo.posto_nome}`,
          descricao: `Setup de ${gargalo.setup}min limita a linha ${linha.nome}. Alvo: ${Math.round(gargalo.setup * 0.6)}min.`,
          ferramenta: 'SMED',
          ganho_estimado: ganho
        });
      }

      // INSIGHT: Balanceamento
      const mediaCiclo = linha.postos.reduce((a, b) => a + b.ciclo, 0) / linha.postos.length;
      if (gargalo.ciclo > mediaCiclo * 1.3) {
        insights.push({
          tipo: 'ESTRUTURAL',
          titulo: `Desbalanceamento em ${linha.nome}`,
          descricao: `O posto ${gargalo.posto_nome} está 30% acima da carga média da linha.`,
          ferramenta: 'Yamazumi / Balanceamento',
          ganho_estimado: 0 // Ganho indireto por capacidade
        });
      }
    });

    res.status(200).json({
      resumo_executivo: `Oportunidade de recuperação de ${new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL' }).format(roiGlobalMensal)}/mês.`,
      plano_de_acao: insights.sort((a, b) => b.ganho_estimado - a.ganho_estimado)
    });

  } catch (error) {
    console.error("❌ Erro no Motor de Insights:", error.message);
    res.status(500).json({ erro: "Falha ao processar inteligência industrial." });
  }
});

// ========================================
// 📋 MÓDULO: GESTÃO DE PROJETOS E CHECKLIST
// ========================================

/**
 * ROTA: INICIALIZAR PROJETO NEXUS
 * Cria a estrutura de fases padrão automaticamente.
 */
app.post("/api/projects/init", autenticarToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { empresa_id, nome, data_inicio, data_previsao } = req.body;

    await client.query('BEGIN');

    // 1. Inserir Projeto
    const projetoRes = await client.query(
      `INSERT INTO projetos_checklist (empresa_id, nome, data_inicio, data_previsao)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [empresa_id, nome, data_inicio, data_previsao]
    );
    const projetoId = projetoRes.rows[0].id;

    // 2. Fases Metodologia Nexus (Execução em Bloco)
    const fases = [
      ['Fase 1 - Diagnóstico & VSM', 1],
      ['Fase 2 - Kaizen & Implantação', 2],
      ['Fase 3 - Sustentação & Auditoria', 3]
    ];

    for (const [faseNome, ordem] of fases) {
      await client.query(
        `INSERT INTO fases_checklist (projeto_id, nome, ordem, status) VALUES ($1, $2, $3, 'Aguardando')`,
        [projetoId, faseNome, ordem]
      );
    }

    await client.query('COMMIT');
    res.status(201).json({ id: projetoId, mensagem: "Projeto Nexus inicializado com sucesso." });

  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ erro: "Falha na transação do projeto." });
  } finally {
    client.release();
  }
});

/**
 * ROTA: PROGRESSO DO PROJETO
 * Retorna o percentual de conclusão baseado nos itens do checklist.
 */
app.get("/api/projects/progress/:projetoId", autenticarToken, async (req, res) => {
  try {
    const { projetoId } = req.params;
    
    const stats = await pool.query(`
      SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE concluido = true) as concluidos
      FROM itens_checklist i
      JOIN fases_checklist f ON i.fase_id = f.id
      WHERE f.projeto_id = $1
    `, [projetoId]);

    const { total, concluidos } = stats.rows[0];
    const percentual = total > 0 ? Math.round((concluidos / total) * 100) : 0;

    res.json({ projetoId, total, concluidos, progresso: `${percentual}%` });
  } catch (error) {
    res.status(500).json({ erro: "Erro ao calcular progresso." });
  }
});

// ========================================
// 🧪 MÓDULO: SEEDER DE DEMONSTRAÇÃO NEXUS
// ========================================

/**
 * ROTA: SETUP DE DEMO (AMBIENTE DE TESTE)
 * Popula o sistema com um cenário industrial completo para validação do Front-end.
 */
app.get("/api/admin/seed-demo", async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Garantir Empresa de Teste (Cenário Realista)
    let empresa = await client.query("SELECT id FROM empresas WHERE nome ILIKE '%Indústria Nexus Demo%' LIMIT 1");
    let empresaId;

    if (empresa.rowCount === 0) {
      const novaEmp = await client.query(
        "INSERT INTO empresas (nome, cnpj, setor) VALUES ($1, $2, $3) RETURNING id",
        ['Indústria Nexus Demo', '00.000.000/0001-00', 'Metalúrgica']
      );
      empresaId = novaEmp.rows[0].id;
    } else {
      empresaId = empresa.rows[0].id;
    }

    // 2. Criar Projeto Estruturado
    const projRes = await client.query(
      `INSERT INTO projetos_checklist (empresa_id, nome, data_inicio, data_previsao, status)
       VALUES ($1, 'Otimização Lean 2026', CURRENT_DATE, CURRENT_DATE + INTERVAL '90 days', 'em_andamento')
       ON CONFLICT DO NOTHING RETURNING id`,
      [empresaId]
    );

    if (projRes.rowCount > 0) {
      const projetoId = projRes.rows[0].id;

      // 3. Fases e Itens (Sincronizados com sua expertise de Engenharia)
      const setupFases = [
        { 
          nome: 'Fase 1 - Diagnóstico (VSM)', 
          itens: ['Mapear Fluxo de Valor', 'Cronoanálise de Gargalos', 'Cálculo de OEE Base'] 
        },
        { 
          nome: 'Fase 2 - Implementação (Kaizen)', 
          itens: ['Setup Rápido (SMED)', 'Padronização 5S', 'Balanceamento de Postos'] 
        }
      ];

      for (let i = 0; i < setupFases.length; i++) {
        const fase = await client.query(
          "INSERT INTO fases_checklist (projeto_id, nome, ordem, status) VALUES ($1, $2, $3, 'em_andamento') RETURNING id",
          [projetoId, setupFases[i].nome, i + 1]
        );
        
        const faseId = fase.rows[0].id;
        for (let j = 0; j < setupFases[i].itens.length; j++) {
          await client.query(
            "INSERT INTO itens_checklist (fase_id, descricao, ordem, concluido) VALUES ($1, $2, $3, $4)",
            [faseId, setupFases[i].itens[j], j + 1, (i === 0 && j === 0)] // Primeiro item da primeira fase já nasce pronto
          );
        }
      }
    }

    await client.query('COMMIT');
    res.json({ status: "Ambiente de demonstração Nexus configurado com sucesso." });

  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ erro: error.message });
  } finally {
    client.release();
  }
});

// ========================================
// 🏢 MÓDULO: MASTER DATA MANAGEMENT (EMPRESAS)
// ========================================

app.put("/api/companies/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const {
    nome, cnpj, segmento, regime_tributario,
    turnos, dias_produtivos_mes, meta_mensal,
    status,
    valor_contrato,
    data_inicio,
    data_previsao_fim
  } = req.body;

  try {
    // 1. Validação de Negócio (Campos Numéricos Não Negativos)
    if (turnos < 0 || dias_produtivos_mes < 0 || meta_mensal < 0) {
      return res.status(400).json({ erro: "Valores operacionais não podem ser negativos." });
    }

    // 2. Sanitização Rigorosa
    const cnpjClean = cnpj?.replace(/\D/g, '');
    
    // 3. Update com COALESCE (Mantém o valor atual se o enviado for null)
    const query = `
      UPDATE empresas SET
        nome = COALESCE($1, nome),
        cnpj = COALESCE($2, cnpj),
        segmento = COALESCE($3, segmento),
        regime_tributario = COALESCE($4, regime_tributario),
        turnos = COALESCE($5, turnos),
        dias_produtivos_mes = COALESCE($6, dias_produtivos_mes),
        meta_mensal = COALESCE($7, meta_mensal),
        status = COALESCE($8, status),
        valor_contrato = COALESCE($9, valor_contrato),
        data_inicio = COALESCE($10, data_inicio),
        data_previsao_fim = COALESCE($11, data_previsao_fim),
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $12
      RETURNING *;
    `;

    const values = [
      nome?.trim(), cnpjClean, segmento, regime_tributario,
      parseInt(turnos) || 0, parseInt(dias_produtivos_mes) || 0,
      parseFloat(meta_mensal) || 0,
      status,
      parseFloat(valor_contrato) || 0,
      data_inicio || null,
      data_previsao_fim || null,
      id
    ];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Empresa não localizada." });
    }

    res.json({
      mensagem: `Dados de ${result.rows[0].nome} atualizados com sucesso.`,
      empresa: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro MDM:", error.message);
    res.status(500).json({ erro: "Falha na persistência dos dados da empresa." });
  }
});

// ========================================
// 🗑️ MÓDULO: EXCLUIR EMPRESA COM TODOS OS VÍNCULOS (CASCATA COMPLETA)
// ========================================

app.delete("/api/companies/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Verificar se a empresa existe
    const empresaCheck = await client.query(
      "SELECT nome FROM empresas WHERE id = $1",
      [id]
    );
    
    if (empresaCheck.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ erro: "Empresa não encontrada." });
    }

    const empresaNome = empresaCheck.rows[0].nome;

    // 1. Remover medições de ciclo (operador_id)
    await client.query(`
      DELETE FROM ciclo_medicao 
      WHERE operador_id IN (SELECT id FROM colaborador WHERE empresa_id = $1)
    `, [id]);

    // 2. Remover medições de ciclo (posto_id)
    await client.query(`
      DELETE FROM ciclo_medicao 
      WHERE posto_id IN (
        SELECT id FROM posto_trabalho 
        WHERE linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1)
      )
    `, [id]);

    // 3. Remover perdas
    await client.query(`
      DELETE FROM perdas_linha 
      WHERE linha_produto_id IN (
        SELECT id FROM linha_produto 
        WHERE linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1)
      )
    `, [id]);

    // 4. Remover vínculos linha_produto
    await client.query(`
      DELETE FROM linha_produto 
      WHERE linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1)
    `, [id]);

    // 5. Remover alocações
    await client.query(`
      DELETE FROM alocacao_colaborador 
      WHERE posto_id IN (
        SELECT id FROM posto_trabalho 
        WHERE linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1)
      )
    `, [id]);

    // 6. Remover postos
    await client.query(`
      DELETE FROM posto_trabalho 
      WHERE linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1)
    `, [id]);

    // 7. Remover colaboradores
    await client.query(`
      DELETE FROM colaborador WHERE empresa_id = $1
    `, [id]);

    // 8. Remover cargos
    await client.query(`
      DELETE FROM cargos WHERE empresa_id = $1
    `, [id]);

    // 9. Remover produtos
    await client.query(`
      DELETE FROM produtos WHERE empresa_id = $1
    `, [id]);

    // 10. Remover linhas
    await client.query(`
      DELETE FROM linhas_producao WHERE empresa_id = $1
    `, [id]);

    // 11. Remover contratos
    await client.query(`
      DELETE FROM contratos_fase1 WHERE empresa_id = $1
    `, [id]);

    // 12. Remover elementos de trabalho
    await client.query(`
      DELETE FROM elementos_trabalho 
      WHERE posto_id IN (
        SELECT id FROM posto_trabalho 
        WHERE linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1)
      )
    `, [id]);

    // 13. Remover leads vinculados à empresa (pelo nome)
    await client.query(`
      DELETE FROM leads WHERE nome = $1
    `, [empresaNome]);

    // 14. Remover interações de leads órfãos
    await client.query(`
      DELETE FROM interacoes_leads 
      WHERE lead_id NOT IN (SELECT id FROM leads)
    `);

    // 15. Remover empresa
    await client.query(`
      DELETE FROM empresas WHERE id = $1
    `, [id]);

    await client.query('COMMIT');

    console.log(`✅ Empresa "${empresaNome}" (ID: ${id}) removida com TODOS os vínculos.`);
    
    res.status(200).json({ 
      mensagem: `Empresa "${empresaNome}" e todos os seus dados foram removidos com sucesso.` 
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("❌ Erro DELETE /companies:", error.message);
    res.status(500).json({ 
      erro: "Erro ao excluir empresa.",
      detalhe: error.message 
    });
  } finally {
    client.release();
  }
});

// ========================================
// 🔑 ROTA DE LOGIN (CONECTADA AO NEON)
// ========================================
//app.post("/api/login", async (req, res) => {
//  const { email, senha } = req.body;

//  try {
    // Buscar usuário no banco
//    const query = "SELECT id, nome, email, senha FROM usuarios WHERE email = $1";
//    const result = await pool.query(query, [email?.toLowerCase().trim()]);
//    const usuario = result.rows[0];

//    if (!usuario) {
//      return res.status(401).json({ erro: "E-mail ou senha inválidos." });
//    }

    // Validar senha (use bcrypt se tiver, senão compare direto)
//    const senhaValida = usuario.senha === senha;
    
//    if (!senhaValida) {
//      return res.status(401).json({ erro: "E-mail ou senha inválidos." });
//    }

    // Gerar token com o ID REAL do banco
//    const token = jwt.sign(
//      { id: usuario.id, email: usuario.email },
//      process.env.JWT_SECRET,
//      { expiresIn: "24h" }
//    );

//    console.log(`✅ Login bem-sucedido: ${usuario.email} (ID: ${usuario.id})`);

//    res.json({
//      status: "sucesso",
//      token,
//      usuario: {
//        id: usuario.id,
//        nome: usuario.nome,
//        email: usuario.email
//      }
//    });

//  } catch (error) {
//    console.error("❌ Erro no login:", error.message);
//    res.status(500).json({ erro: "Erro interno ao fazer login" });
//  }
//});

// ========================================
// 🏢 ROTAS DE NEGÓCIO (SISTEMA HÓRUS)
// ========================================

// 1. Listar todas as empresas
//app.get("/api/empresas", async (req, res) => {
//  try {
//    const result = await pool.query("SELECT * FROM empresas ORDER BY nome");
//    res.json(result.rows);
//  } catch (err) {
//    console.error(err.message);
//    res.status(500).json({ erro: "Erro ao buscar empresas" });
//  }
//});

// 2. Listar linhas de uma empresa específica
//app.get("/api/linhas/:empresaId", async (req, res) => {
//  const { empresaId } = req.params;
//  try {
//    const result = await pool.query("SELECT * FROM linhas WHERE empresa_id = $1", [empresaId]);
//    res.json(result.rows);
//  } catch (err) {
//    res.status(500).json({ erro: "Erro ao buscar linhas" });
//  }
//});

// 3. Listar cargos de uma empresa (para cálculo de custos)
//app.get("/api/cargos/:empresaId", async (req, res) => {
//  const { empresaId } = req.params;
//  try {
//    const result = await pool.query("SELECT * FROM cargos WHERE empresa_id = $1", [empresaId]);
//    res.json(result.rows);
//  } catch (err) {
//    res.status(500).json({ erro: "Erro ao buscar cargos" });
//  }
//});

// 4. Listar postos de uma linha
//app.get("/api/postos/:linhaId", async (req, res) => {
//  const { linhaId } = req.params;
//  try {
//    const result = await pool.query("SELECT * FROM postos WHERE linha_id = $1", [linhaId]);
//    res.json(result.rows);
//  } catch (err) {
//    res.status(500).json({ erro: "Erro ao buscar postos" });
//  }
//});

// 5. Rota de Análise - CORRIGIDA COM DADOS REAIS
app.get("/api/analise-linha/:linhaId", async (req, res) => {
  const { linhaId } = req.params;
  
  try {
    // Buscar dados reais da linha
    const linhaRes = await pool.query(`
      SELECT 
        l.takt_time_segundos,
        l.meta_diaria,
        COALESCE(AVG(pt.tempo_ciclo_segundos), 0) as ciclo_medio,
        MAX(pt.tempo_ciclo_segundos) as ciclo_maximo
      FROM linhas_producao l
      LEFT JOIN posto_trabalho pt ON pt.linha_id = l.id
      WHERE l.id = $1
      GROUP BY l.id
    `, [linhaId]);
    
    if (linhaRes.rows.length > 0 && linhaRes.rows[0].meta_diaria > 0) {
      const linha = linhaRes.rows[0];
      const takt = linha.takt_time_segundos || 0;
      const meta = linha.meta_diaria || 0;
      const cicloGargalo = linha.ciclo_maximo || takt;
      
      // Calcular eficiência: (takt / ciclo_gargalo) * 100
      let eficiencia = 0;
      if (takt > 0 && cicloGargalo > 0) {
        eficiencia = Math.min(100, Math.round((takt / cicloGargalo) * 100));
      }
      
      // Calcular capacidade real
      const capacidadeReal = cicloGargalo > 0 ? Math.floor((meta * takt) / cicloGargalo) : meta;
      
      res.json({
        eficiencia_percentual: eficiencia,
        capacidade_estimada_dia: capacidadeReal,
        takt_time: takt,
        meta_diaria: meta,
        gargalo_ciclo: cicloGargalo
      });
    } else {
      // Fallback quando não há dados
      res.json({
        eficiencia_percentual: 0,
        capacidade_estimada_dia: 0,
        mensagem: "Configure o takt, meta e postos da linha"
      });
    }
    
  } catch (error) {
    console.error("❌ Erro na análise da linha:", error.message);
    res.json({
      eficiencia_percentual: 0,
      capacidade_estimada_dia: 0,
      erro: error.message
    });
  }
});

// 6. Rota de Produtos da Linha - AGORA COM DADOS REAIS
app.get("/api/linha-produto/:linhaId", async (req, res) => {
  const { linhaId } = req.params;
  
  try {
    const result = await pool.query(`
      SELECT 
        p.id,
        p.nome,
        p.valor_unitario,
        lp.takt_time_segundos,
        lp.meta_diaria
      FROM linha_produto lp
      JOIN produtos p ON p.id = lp.produto_id
      WHERE lp.linha_id = $1
    `, [linhaId]);
    
    if (result.rows.length > 0) {
      res.json(result.rows);
    } else {
      // Retorna array vazio se não tiver produtos
      res.json([]);
    }
    
  } catch (error) {
    console.error("❌ Erro ao buscar produtos da linha:", error.message);
    res.json([]);
  }
});

// ========================================
// 📋 MÓDULO: CHECKLIST DE PROJETOS
// ========================================

/**
 * 1️⃣ CRIAR PROJETO
 * Inicializa um novo projeto com as fases padrão
 */
app.post("/api/checklist/projeto", autenticarToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { empresa_id, nome, data_inicio, data_previsao } = req.body;

    // Validação
    if (!empresa_id || !nome || !data_previsao) {
      return res.status(400).json({ erro: "Empresa, nome e previsão são obrigatórios." });
    }

    await client.query('BEGIN');

    // 1. Inserir projeto
    const projetoRes = await client.query(
      `INSERT INTO projetos_checklist 
       (empresa_id, nome, data_inicio, data_previsao, status, progresso) 
       VALUES ($1, $2, $3, $4, 'em_andamento', 0) 
       RETURNING *`,
      [empresa_id, nome, data_inicio || new Date(), data_previsao]
    );
    
    const projeto = projetoRes.rows[0];

    // 2. Criar fases padrão
    const fases = [
      { nome: 'Fase 1 - Diagnóstico', ordem: 1 },
      { nome: 'Fase 2 - Implementação', ordem: 2 },
      { nome: 'Fase 3 - Sustentação', ordem: 3 }
    ];

    for (const fase of fases) {
      await client.query(
        `INSERT INTO fases_checklist (projeto_id, nome, ordem, status, progresso)
         VALUES ($1, $2, $3, 'pendente', 0)`,
        [projeto.id, fase.nome, fase.ordem]
      );
    }

    await client.query('COMMIT');
    
    res.status(201).json({
      mensagem: "Projeto criado com sucesso!",
      projeto
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("❌ Erro ao criar projeto:", error.message);
    res.status(500).json({ erro: "Erro ao criar projeto" });
  } finally {
    client.release();
  }
});

/**
 * 2️⃣ LISTAR PROJETOS POR EMPRESA
 */
app.get("/api/checklist/projetos/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;

  try {
    const result = await pool.query(
      `SELECT * FROM projetos_checklist 
       WHERE empresa_id = $1 
       ORDER BY data_criacao DESC`,
      [empresaId]
    );

    res.status(200).json(result.rows);
  } catch (error) {
    console.error("❌ Erro ao listar projetos:", error.message);
    res.status(500).json({ erro: "Erro ao carregar projetos" });
  }
});

/**
 * 3️⃣ BUSCAR PROJETO COM FASES E ITENS
 */
app.get("/api/checklist/projeto/:projetoId", autenticarToken, async (req, res) => {
  const { projetoId } = req.params;

  try {
    // Buscar projeto
    const projetoRes = await pool.query(
      "SELECT * FROM projetos_checklist WHERE id = $1",
      [projetoId]
    );

    if (projetoRes.rowCount === 0) {
      return res.status(404).json({ erro: "Projeto não encontrado" });
    }

    const projeto = projetoRes.rows[0];

    // Buscar fases com itens
    const fasesRes = await pool.query(
      `SELECT f.*, 
        COALESCE(json_agg(
          json_build_object(
            'id', i.id,
            'descricao', i.descricao,
            'concluido', i.concluido,
            'ordem', i.ordem,
            'data_conclusao', i.data_conclusao
          ) ORDER BY i.ordem
        ) FILTER (WHERE i.id IS NOT NULL), '[]') as itens
       FROM fases_checklist f
       LEFT JOIN itens_checklist i ON i.fase_id = f.id
       WHERE f.projeto_id = $1
       GROUP BY f.id
       ORDER BY f.ordem`,
      [projetoId]
    );

    res.status(200).json({
      projeto,
      fases: fasesRes.rows
    });

  } catch (error) {
    console.error("❌ Erro ao buscar projeto:", error.message);
    res.status(500).json({ erro: "Erro ao carregar projeto" });
  }
});

/**
 * 4️⃣ ADICIONAR ITEM À FASE
 */
app.post("/api/checklist/item", autenticarToken, async (req, res) => {
  const { fase_id, descricao, ordem } = req.body;

  if (!fase_id || !descricao) {
    return res.status(400).json({ erro: "Fase e descrição são obrigatórios." });
  }

  try {
    const result = await pool.query(
      `INSERT INTO itens_checklist (fase_id, descricao, ordem, concluido)
       VALUES ($1, $2, $3, false)
       RETURNING *`,
      [fase_id, descricao, ordem || 1]
    );

    res.status(201).json({
      mensagem: "Item adicionado com sucesso!",
      item: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro ao adicionar item:", error.message);
    res.status(500).json({ erro: "Erro ao adicionar item" });
  }
});

/**
 * 5️⃣ ATUALIZAR ITEM (concluir/editar)
 */
app.put("/api/checklist/item/:itemId", autenticarToken, async (req, res) => {
  const { itemId } = req.params;
  const { concluido, descricao } = req.body;

  try {
    let query, values;

    if (concluido !== undefined) {
      // Atualizar status e data de conclusão
      query = `
        UPDATE itens_checklist 
        SET concluido = $1, 
            data_conclusao = CASE WHEN $1 = true THEN CURRENT_TIMESTAMP ELSE NULL END
        WHERE id = $2
        RETURNING *
      `;
      values = [concluido, itemId];
    } else {
      // Atualizar apenas descrição
      query = `
        UPDATE itens_checklist 
        SET descricao = $1
        WHERE id = $2
        RETURNING *
      `;
      values = [descricao, itemId];
    }

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Item não encontrado" });
    }

    res.status(200).json({
      mensagem: "Item atualizado com sucesso!",
      item: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro ao atualizar item:", error.message);
    res.status(500).json({ erro: "Erro ao atualizar item" });
  }
});

/**
 * 6️⃣ ATUALIZAR FASE (progresso e status)
 */
app.put("/api/checklist/fase/:faseId", autenticarToken, async (req, res) => {
  const { faseId } = req.params;
  const { progresso, status } = req.body;

  try {
    const result = await pool.query(
      `UPDATE fases_checklist 
       SET progresso = COALESCE($1, progresso),
           status = COALESCE($2, status)
       WHERE id = $3
       RETURNING *`,
      [progresso, status, faseId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Fase não encontrada" });
    }

    res.status(200).json({
      mensagem: "Fase atualizada com sucesso!",
      fase: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro ao atualizar fase:", error.message);
    res.status(500).json({ erro: "Erro ao atualizar fase" });
  }
});

// ========================================
// 🤖 MÓDULO: INTELIGÊNCIA ARTIFICIAL (IA)
// ========================================

/**
 * 1️⃣ GERAR PROPOSTA COMERCIAL COM IA
 * Gera um texto de proposta profissional baseado nos dados da empresa
 */
app.post("/api/ia/gerar-proposta", autenticarToken, async (req, res) => {
  try {
    const { dadosProposta } = req.body;

    if (!dadosProposta || !dadosProposta.empresa) {
      return res.status(400).json({ erro: "Dados da proposta são obrigatórios." });
    }

    // Template profissional de proposta
    const proposta = `
# PROPOSTA COMERCIAL - NEXUS ENGENHARIA APLICADA

**Empresa:** ${dadosProposta.empresa}
**Data:** ${new Date().toLocaleDateString('pt-BR')}

---

## 1. DIAGNÓSTICO ATUAL

Após análise preliminar dos dados de sua operação, identificamos:

- **OEE Médio:** ${dadosProposta.oeeMedio || 'N/A'}%
- **Perdas Totais:** R$ ${(dadosProposta.perdasTotais || 0).toLocaleString('pt-BR')}/mês
- **Gargalos Críticos:** ${dadosProposta.gargalosCriticos || 0}
- **Estrutura:** ${dadosProposta.totalLinhas || 0} linhas | ${dadosProposta.totalPostos || 0} postos

## 2. ESCOPO DO TRABALHO

**Fase 1 - Diagnóstico Detalhado (${dadosProposta.escopo?.diagnostico || '2 semanas'}):**
- Mapeamento de Fluxo de Valor (VSM)
- Cronoanálise de todos os postos
- Identificação de gargalos e perdas

**Fase 2 - Implementação (${dadosProposta.escopo?.implementacao || '4 semanas'}):**
- Redução de Setup (SMED)
- Balanceamento de linhas
- Padronização de processos

**Fase 3 - Acompanhamento (${dadosProposta.escopo?.acompanhamento || '3 meses'}):**
- Monitoramento de indicadores
- Ajustes finos
- Transferência de conhecimento

## 3. INVESTIMENTO

- **Honorários totais:** R$ ${(dadosProposta.investimento?.honorarios || 0).toLocaleString('pt-BR')}
- **Entrada (50%):** R$ ${((dadosProposta.investimento?.honorarios || 0) * 0.5).toLocaleString('pt-BR')}
- **Saldo na entrega:** R$ ${((dadosProposta.investimento?.honorarios || 0) * 0.5).toLocaleString('pt-BR')}

## 4. RETORNO SOBRE INVESTIMENTO

- **Ganho mensal projetado:** R$ ${(dadosProposta.retorno?.ganhoMensal || 0).toLocaleString('pt-BR')}
- **ROI Anual:** ${dadosProposta.retorno?.roiAnual || '0'}%
- **Payback:** ${dadosProposta.retorno?.payback || '0'} meses

## 5. PRÓXIMOS PASSOS

1. Assinar proposta
2. Agendar reunião de kick-off
3. Iniciar diagnóstico

---

**Validade da proposta:** 15 dias

Atenciosamente,

**Nexus Engenharia Aplicada**
    `;

    res.status(200).json({
      proposta: proposta.trim(),
      metadata: {
        empresa: dadosProposta.empresa,
        valor: dadosProposta.investimento?.honorarios,
        roi: dadosProposta.retorno?.roiAnual
      }
    });

  } catch (error) {
    console.error("❌ Erro ao gerar proposta IA:", error.message);
    res.status(500).json({ erro: "Falha ao gerar proposta com IA" });
  }
});

/**
 * 2️⃣ GERAR RELATÓRIO EXECUTIVO COM IA
 * Gera uma análise textual detalhada dos dados da empresa
 */
app.post("/api/ia/gerar-relatorio", autenticarToken, async (req, res) => {
  try {
    const { dados, tipo } = req.body;

    if (!dados || !tipo) {
      return res.status(400).json({ erro: "Dados e tipo são obrigatórios." });
    }

    let relatorio = "";

    if (tipo === "geral") {
      relatorio = `
# RELATÓRIO EXECUTIVO - VISÃO GERAL

**Empresa:** ${dados.empresa}
**Data:** ${new Date().toLocaleDateString('pt-BR')}

## ANÁLISE DA OPERAÇÃO

A operação da ${dados.empresa} apresenta um cenário com oportunidades significativas de melhoria. Com ${dados.linhas?.length || 0} linhas de produção ativas, o OEE médio está em ${dados.resumoFinanceiro?.oeeMedio || 0}%, abaixo do benchmark de classe mundial (85%).

### Pontos Críticos Identificados:

1. **${dados.resumoFinanceiro?.gargalosCriticos || 0} linhas com desempenho crítico** (OEE < 60%)
2. **Perdas totais de R$ ${(dados.resumoFinanceiro?.perdasTotais || 0).toLocaleString('pt-BR')}/mês**
3. **Custo de mão de obra:** R$ ${(dados.resumoFinanceiro?.custoMaoObra || 0).toLocaleString('pt-BR')}/mês

### Recomendações Prioritárias:

- **Curto Prazo:** Atacar os gargalos nas linhas críticas com menor investimento
- **Médio Prazo:** Implementar programa SMED nos principais setups
- **Longo Prazo:** Estabelecer cultura de melhoria contínua com gestão visual

### Projeção de Ganhos:

Com investimento de R$ 50.000, estimamos:
- Payback: ${dados.resumoFinanceiro?.roi?.payback || '4.2'} meses
- ROI Anual: ${dados.resumoFinanceiro?.roi?.roiAnual || '286'}%
- Ganho líquido no primeiro ano: R$ ${((dados.resumoFinanceiro?.perdasTotais || 0) * 0.3 * 12).toLocaleString('pt-BR')}
      `;
    } else {
      // Relatório específico por linha
      relatorio = `
# RELATÓRIO TÉCNICO - ${dados.linha}

**Empresa:** ${dados.empresa}
**Data:** ${new Date().toLocaleDateString('pt-BR')}

## ANÁLISE DA LINHA

A linha ${dados.linha} opera com OEE de ${dados.analise?.eficiencia_percentual || 0}%, tendo como principal gargalo o posto "${dados.analise?.gargalo || 'Não identificado'}".

### Postos de Trabalho:

A linha possui ${dados.postos?.length || 0} postos, com tempo médio de ciclo de ${dados.balanceamento?.tempo_medio_segundos || 0}s e índice de balanceamento de ${dados.balanceamento?.indice_balanceamento_percentual || 0}%.

### Perdas Financeiras:

- Setup: R$ ${(dados.perdasFinanceiras?.setup || 0).toLocaleString('pt-BR')}/mês
- Microparadas: R$ ${(dados.perdasFinanceiras?.micro || 0).toLocaleString('pt-BR')}/mês
- Refugo: R$ ${(dados.perdasFinanceiras?.refugo || 0).toLocaleString('pt-BR')}/mês
- **Total:** R$ ${(dados.perdasFinanceiras?.total || 0).toLocaleString('pt-BR')}/mês

### Recomendações Específicas:

1. **Redução de setup no posto gargalo** - Aplicar SMED
2. **Balanceamento da linha** - Redistribuir carga entre postos
3. **Padronização de ciclos** - Reduzir variabilidade

### Retorno do Investimento:

Investimento sugerido: R$ 50.000
Payback estimado: ${dados.roi?.payback || '4.2'} meses
ROI anual: ${dados.roi?.roiAnual || '286'}%
      `;
    }

    res.status(200).json({
      relatorio: relatorio.trim(),
      metadata: {
        empresa: dados.empresa,
        tipo,
        gerado_em: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error("❌ Erro ao gerar relatório IA:", error.message);
    res.status(500).json({ erro: "Falha ao gerar relatório com IA" });
  }
});

// ========================================
// 4️⃣ IA DE PRECIFICAÇÃO PRÉ-CONTRATO (VERSÃO DEFINITIVA - CORRIGIDA)
// ========================================

/**
 * ROTA: CALCULAR PREÇO BASEADO EM ESTIMATIVAS
 * 
 * Entrada (dados que o consultor sabe antes do contrato):
 * - empresa_nome: string
 * - setor: string (automotivo, metalurgico, alimenticio, quimico, farmaceutico, outros)
 * - numero_funcionarios: number
 * - faturamento_anual: number (em R$)
 * - numero_linhas: number
 * - problemas: array ['produtividade', 'qualidade', 'manutencao', 'rh']
 * - urgencia: string ('baixa', 'normal', 'alta')
 * - complexidade: string ('baixa', 'media', 'alta')
 * - gestor_dedicado: string ('sim', 'parcial', 'nao')
 * - acesso_dados: string ('imediato', 'mediado', 'restrito')
 * - projeto_piloto: boolean
 * - tem_viagem: boolean
 */
// ========================================
// 🤖 IA DE PRECIFICAÇÃO - VERSÃO ATUALIZADA (SEM FATURAMENTO)
// ========================================
app.post("/api/ia/precificar", autenticarToken, async (req, res) => {
  try {
    const dados = req.body;
    
    // ========================================
    // VALIDAÇÃO DOS DADOS DE ENTRADA (SEM FATURAMENTO)
    // ========================================
    if (!dados.setor) {
      return res.status(400).json({ 
        erro: "Setor é obrigatório para precificação." 
      });
    }
    
    // Validar número de linhas
    const numeroLinhas = parseInt(dados.numero_linhas) || 1;
    if (numeroLinhas < 1) {
      return res.status(400).json({ 
        erro: "Número de linhas deve ser pelo menos 1." 
      });
    }
    
    // Validar número de postos (opcional, pode ser 0)
    const numeroPostos = parseInt(dados.numero_postos) || 0;
    
    // ========================================
    // CALCULAR PREÇO COM NOVA FÓRMULA (SEM FATURAMENTO)
    // ========================================
    const precos = calcularPrecoProjeto({
      linhas: numeroLinhas,
      postos: numeroPostos,
      complexidade: dados.complexidade || 'media',
      urgencia: dados.urgencia || 'normal',
      projeto_piloto: dados.projeto_piloto || false
    });
    
    // ========================================
    // CALCULAR PARCELAS PARA O DIAGNÓSTICO
    // ========================================
    const parcelas = calcularParcelasDiagnostico(precos.diagnostico);
    
    // ========================================
    // RETORNAR RESULTADO
    // ========================================
    res.status(200).json({
      status: "sucesso",
      versao: "3.0 - sem faturamento",
      empresa: dados.empresa_nome || "Cliente",
      setor: dados.setor,
      data_calculo: new Date().toISOString(),
      
      precos: {
        total_projeto: precos.total,
        diagnostico: precos.diagnostico,
        implementacao: precos.implementacao,
        acompanhamento_total: precos.acompanhamento_total,
        acompanhamento_mensal: precos.acompanhamento_mensal,
        participacao_percentual: precos.participacao_percentual
      },
      
      parcelamento: {
        disponivel: parcelas.tem_parcelamento,
        entrada_percentual: parcelas.entrada_percentual,
        valor_entrada: parcelas.valor_entrada,
        num_parcelas: parcelas.num_parcelas,
        valor_parcela: parcelas.valor_parcela,
        valor_total_parcelado: parcelas.saldo_parcelado
      },
      
      detalhamento: precos.detalhamento,
      
      configuracao: {
        valor_por_linha: 50000,
        valor_por_posto: 3000,
        salario_minimo_atual: CONFIG_SALARIO.getSalarioMinimo(),
        acompanhamento_minimo_mensal: CONFIG_SALARIO.getAcompanhamentoMinimo()
      }
    });
    
  } catch (error) {
    console.error("❌ Erro na IA de Precificação:", error.message);
    res.status(500).json({ 
      erro: "Falha ao processar precificação",
      detalhe: error.message 
    });
  }
});

// ========================================
// 🟢 NOVOS MÓDULOS: OEE, SPC, TPM, RH
// ========================================

// ========================================
// 📊 OEE - REGISTRO DE PRODUÇÃO
// ========================================

/**
 * ROTA: REGISTRAR PRODUÇÃO (OEE)
 */
app.post("/api/producao/registrar", autenticarToken, async (req, res) => {
  const { linha_id, produto_id, turno, data, pecas_produzidas, pecas_boas, tempo_operando_min, paradas, oee, disponibilidade, performance, qualidade } = req.body;

  if (!linha_id || !produto_id || !pecas_produzidas) {
    return res.status(400).json({ erro: "Linha, produto e peças produzidas são obrigatórios." });
  }

  try {
    const query = `
      INSERT INTO producao_oee 
      (linha_id, produto_id, turno, data, pecas_produzidas, pecas_boas, tempo_operando_min, paradas, oee, disponibilidade, performance, qualidade)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *;
    `;

    const values = [
      linha_id, produto_id, turno, data, pecas_produzidas, 
      pecas_boas || pecas_produzidas, tempo_operando_min || null,
      paradas ? JSON.stringify(paradas) : null,
      oee, disponibilidade, performance, qualidade
    ];

    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro POST /producao/registrar:", error.message);
    res.status(500).json({ erro: "Erro ao registrar produção" });
  }
});

/**
 * ROTA: HISTÓRICO OEE POR LINHA
 */
app.get("/api/oee/history/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;
  const { data_inicio, data_fim } = req.query;

  try {
    let query = `
      SELECT p.*, pr.nome as produto_nome
      FROM producao_oee p
      JOIN produtos pr ON pr.id = p.produto_id
      WHERE p.linha_id = $1
    `;
    const values = [linhaId];
    let paramIndex = 2;

    if (data_inicio) {
      query += ` AND p.data >= $${paramIndex}`;
      values.push(data_inicio);
      paramIndex++;
    }
    if (data_fim) {
      query += ` AND p.data <= $${paramIndex}`;
      values.push(data_fim);
      paramIndex++;
    }

    query += ` ORDER BY p.data DESC, p.turno ASC;`;

    const result = await pool.query(query, values);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("❌ Erro GET /oee/history:", error.message);
    res.status(500).json({ erro: "Erro ao buscar histórico OEE" });
  }
});

/**
 * ROTA: HISTÓRICO DA LINHA (para gráficos)
 */
app.get("/api/history/line/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;
  
  try {
    const result = await pool.query(`
      SELECT data, oee, disponibilidade, performance, qualidade
      FROM producao_oee
      WHERE linha_id = $1
      ORDER BY data ASC, turno ASC
    `, [linhaId]);
    
    res.json(result.rows);
  } catch (error) {
    console.error("❌ Erro GET /history/line:", error.message);
    res.status(500).json({ erro: "Erro ao carregar histórico da linha" });
  }
});

/**
 * ROTA: EFICIÊNCIA GLOBAL DA LINHA
 */
app.get("/api/global-efficiency/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;
  
  try {
    const result = await pool.query(`
      SELECT 
        COALESCE(AVG(oee), 0) as oee_medio,
        COALESCE(AVG(disponibilidade), 0) as disponibilidade_media,
        COALESCE(AVG(performance), 0) as performance_media,
        COALESCE(AVG(qualidade), 0) as qualidade_media,
        COUNT(*) as total_registros
      FROM producao_oee
      WHERE linha_id = $1
    `, [linhaId]);
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro GET /global-efficiency:", error.message);
    res.status(500).json({ erro: "Erro ao carregar eficiência global" });
  }
});

/**
 * ROTA: EXCLUIR REGISTRO DE PRODUÇÃO (OEE)
 */
app.delete("/api/producao/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      "DELETE FROM producao_oee WHERE id = $1 RETURNING id, data, turno, produto_id",
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Registro de produção não encontrado." });
    }

    console.log(`🗑️ Produção excluída: ID ${id}`);
    res.status(200).json({ 
      mensagem: "Registro de produção excluído com sucesso.",
      id: result.rows[0].id
    });

  } catch (error) {
    console.error("❌ Erro DELETE /producao/:id:", error.message);
    res.status(500).json({ erro: "Erro ao excluir registro de produção." });
  }
});

// ========================================
// 📊 SPC - QUALIDADE (DEFEITOS E MEDIÇÕES)
// ========================================

/**
 * ROTA: REGISTRAR DEFEITO
 */
app.post("/api/qualidade/defeitos", autenticarToken, async (req, res) => {
  const { posto_id, produto_id, tipo_defeito, quantidade, turno, descricao, acao_imediata, data } = req.body;

  if (!posto_id || !produto_id || !tipo_defeito || !quantidade) {
    return res.status(400).json({ erro: "Posto, produto, tipo e quantidade são obrigatórios." });
  }

  try {
    const query = `
      INSERT INTO defeitos_qualidade 
      (posto_id, produto_id, tipo_defeito, quantidade, turno, descricao, acao_imediata, data)
      VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, CURRENT_DATE))
      RETURNING *;
    `;

    const values = [posto_id, produto_id, tipo_defeito, quantidade, turno || 1, descricao || null, acao_imediata || null, data];
    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro POST /qualidade/defeitos:", error.message);
    res.status(500).json({ erro: "Erro ao registrar defeito" });
  }
});

/**
 * ROTA: LISTAR DEFEITOS POR LINHA
 */
app.get("/api/qualidade/defeitos/linha/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;
  const { data_inicio, data_fim, posto_id, produto_id } = req.query;

  try {
    let query = `
      SELECT d.*, p.nome as posto_nome, pr.nome as produto_nome
      FROM defeitos_qualidade d
      JOIN posto_trabalho p ON p.id = d.posto_id
      JOIN produtos pr ON pr.id = d.produto_id
      WHERE p.linha_id = $1
    `;
    const values = [linhaId];
    let paramIndex = 2;

    if (data_inicio) { query += ` AND d.data >= $${paramIndex}`; values.push(data_inicio); paramIndex++; }
    if (data_fim) { query += ` AND d.data <= $${paramIndex}`; values.push(data_fim); paramIndex++; }
    if (posto_id) { query += ` AND d.posto_id = $${paramIndex}`; values.push(posto_id); paramIndex++; }
    if (produto_id) { query += ` AND d.produto_id = $${paramIndex}`; values.push(produto_id); paramIndex++; }

    query += ` ORDER BY d.data DESC, d.id DESC;`;

    const result = await pool.query(query, values);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("❌ Erro GET /qualidade/defeitos/linha:", error.message);
    res.status(500).json({ erro: "Erro ao listar defeitos" });
  }
});

/**
 * ROTA: REGISTRAR MEDIÇÃO DIMENSIONAL
 */
app.post("/api/qualidade/medicoes", autenticarToken, async (req, res) => {
  const { posto_id, produto_id, caracteristica, valor_medido, limite_inferior, limite_superior, unidade, turno, data } = req.body;

  if (!posto_id || !produto_id || !caracteristica || valor_medido === undefined) {
    return res.status(400).json({ erro: "Posto, produto, característica e valor medido são obrigatórios." });
  }

  try {
    const query = `
      INSERT INTO medicoes_qualidade 
      (posto_id, produto_id, caracteristica, valor_medido, limite_inferior, limite_superior, unidade, turno, data)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9, CURRENT_DATE))
      RETURNING *;
    `;

    const values = [posto_id, produto_id, caracteristica, valor_medido, limite_inferior || null, limite_superior || null, unidade || "mm", turno || 1, data];
    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro POST /qualidade/medicoes:", error.message);
    res.status(500).json({ erro: "Erro ao registrar medição" });
  }
});

/**
 * ROTA: LISTAR MEDIÇÕES POR LINHA
 */
app.get("/api/qualidade/medicoes/linha/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;
  const { data_inicio, data_fim, posto_id, produto_id } = req.query;

  try {
    let query = `
      SELECT m.*, p.nome as posto_nome, pr.nome as produto_nome
      FROM medicoes_qualidade m
      JOIN posto_trabalho p ON p.id = m.posto_id
      JOIN produtos pr ON pr.id = m.produto_id
      WHERE p.linha_id = $1
    `;
    const values = [linhaId];
    let paramIndex = 2;

    if (data_inicio) { query += ` AND m.data >= $${paramIndex}`; values.push(data_inicio); paramIndex++; }
    if (data_fim) { query += ` AND m.data <= $${paramIndex}`; values.push(data_fim); paramIndex++; }
    if (posto_id) { query += ` AND m.posto_id = $${paramIndex}`; values.push(posto_id); paramIndex++; }
    if (produto_id) { query += ` AND m.produto_id = $${paramIndex}`; values.push(produto_id); paramIndex++; }

    query += ` ORDER BY m.data DESC, m.id DESC;`;

    const result = await pool.query(query, values);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("❌ Erro GET /qualidade/medicoes/linha:", error.message);
    res.status(500).json({ erro: "Erro ao listar medições" });
  }
});

/**
 * ROTA: ATUALIZAR DEFEITO
 */
app.put("/api/qualidade/defeitos/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { posto_id, produto_id, tipo_defeito, quantidade, turno, data, descricao, acao_imediata } = req.body;

  try {
    const result = await pool.query(
      `UPDATE defeitos_qualidade SET
        posto_id = COALESCE($1, posto_id),
        produto_id = COALESCE($2, produto_id),
        tipo_defeito = COALESCE($3, tipo_defeito),
        quantidade = COALESCE($4, quantidade),
        turno = COALESCE($5, turno),
        data = COALESCE($6, data),
        descricao = COALESCE($7, descricao),
        acao_imediata = COALESCE($8, acao_imediata)
      WHERE id = $9
      RETURNING *`,
      [posto_id, produto_id, tipo_defeito, quantidade, turno, data, descricao, acao_imediata, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Defeito não encontrado" });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro PUT /qualidade/defeitos/:id:", error.message);
    res.status(500).json({ erro: "Erro ao atualizar defeito" });
  }
});

/**
 * ROTA: EXCLUIR DEFEITO
 */
app.delete("/api/qualidade/defeitos/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      "DELETE FROM defeitos_qualidade WHERE id = $1 RETURNING id",
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Defeito não encontrado" });
    }

    res.status(200).json({ 
      mensagem: "Defeito excluído com sucesso",
      id: result.rows[0].id
    });
  } catch (error) {
    console.error("❌ Erro DELETE /qualidade/defeitos/:id:", error.message);
    res.status(500).json({ erro: "Erro ao excluir defeito" });
  }
});

/**
 * ROTA: ATUALIZAR MEDIÇÃO DIMENSIONAL
 */
app.put("/api/qualidade/medicoes/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { posto_id, produto_id, caracteristica, valor_medido, limite_inferior, limite_superior, unidade, turno, data } = req.body;

  try {
    const result = await pool.query(
      `UPDATE medicoes_qualidade SET
        posto_id = COALESCE($1, posto_id),
        produto_id = COALESCE($2, produto_id),
        caracteristica = COALESCE($3, caracteristica),
        valor_medido = COALESCE($4, valor_medido),
        limite_inferior = COALESCE($5, limite_inferior),
        limite_superior = COALESCE($6, limite_superior),
        unidade = COALESCE($7, unidade),
        turno = COALESCE($8, turno),
        data = COALESCE($9, data)
      WHERE id = $10
      RETURNING *`,
      [posto_id, produto_id, caracteristica, valor_medido, limite_inferior, limite_superior, unidade, turno, data, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Medição não encontrada" });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro PUT /qualidade/medicoes/:id:", error.message);
    res.status(500).json({ erro: "Erro ao atualizar medição" });
  }
});

/**
 * ROTA: EXCLUIR MEDIÇÃO DIMENSIONAL
 */
app.delete("/api/qualidade/medicoes/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      "DELETE FROM medicoes_qualidade WHERE id = $1 RETURNING id",
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Medição não encontrada" });
    }

    res.status(200).json({ 
      mensagem: "Medição excluída com sucesso",
      id: result.rows[0].id
    });
  } catch (error) {
    console.error("❌ Erro DELETE /qualidade/medicoes/:id:", error.message);
    res.status(500).json({ erro: "Erro ao excluir medição" });
  }
});

// ========================================
// 🔧 TPM - MANUTENÇÃO
// ========================================

/**
 * ROTA: REGISTRAR MANUTENÇÃO
 */
app.post("/api/manutencao/registros", autenticarToken, async (req, res) => {
  const { posto_id, tipo, causa, tempo_parada_min, tempo_reparo_min, descricao, peca_substituida, turno, data } = req.body;

  if (!posto_id || !tipo || !tempo_parada_min) {
    return res.status(400).json({ erro: "Posto, tipo e tempo de parada são obrigatórios." });
  }

  try {
    const query = `
      INSERT INTO manutencao_registros 
      (posto_id, tipo, causa, tempo_parada_min, tempo_reparo_min, descricao, peca_substituida, turno, data)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9, CURRENT_DATE))
      RETURNING *;
    `;

    const values = [posto_id, tipo, causa || null, tempo_parada_min, tempo_reparo_min || 0, descricao || null, peca_substituida || null, turno || 1, data];
    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro POST /manutencao/registros:", error.message);
    res.status(500).json({ erro: "Erro ao registrar manutenção" });
  }
});

/**
 * ROTA: LISTAR REGISTROS DE MANUTENÇÃO POR LINHA
 */
app.get("/api/manutencao/registros/linha/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;
  const { data_inicio, data_fim, posto_id } = req.query;

  try {
    let query = `
      SELECT m.*, p.nome as posto_nome
      FROM manutencao_registros m
      JOIN posto_trabalho p ON p.id = m.posto_id
      WHERE p.linha_id = $1
    `;
    const values = [linhaId];
    let paramIndex = 2;

    if (data_inicio) { query += ` AND m.data >= $${paramIndex}`; values.push(data_inicio); paramIndex++; }
    if (data_fim) { query += ` AND m.data <= $${paramIndex}`; values.push(data_fim); paramIndex++; }
    if (posto_id) { query += ` AND m.posto_id = $${paramIndex}`; values.push(posto_id); paramIndex++; }

    query += ` ORDER BY m.data DESC, m.id DESC;`;

    const result = await pool.query(query, values);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("❌ Erro GET /manutencao/registros/linha:", error.message);
    res.status(500).json({ erro: "Erro ao listar manutenções" });
  }
});

/**
 * ROTA: ATUALIZAR REGISTRO DE MANUTENÇÃO
 */
app.put("/api/manutencao/registros/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { posto_id, tipo, causa, tempo_parada_min, tempo_reparo_min, descricao, peca_substituida, turno, data } = req.body;

  try {
    const result = await pool.query(
      `UPDATE manutencao_registros SET
        posto_id = COALESCE($1, posto_id),
        tipo = COALESCE($2, tipo),
        causa = COALESCE($3, causa),
        tempo_parada_min = COALESCE($4, tempo_parada_min),
        tempo_reparo_min = COALESCE($5, tempo_reparo_min),
        descricao = COALESCE($6, descricao),
        peca_substituida = COALESCE($7, peca_substituida),
        turno = COALESCE($8, turno),
        data = COALESCE($9, data),
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $10
      RETURNING *`,
      [posto_id, tipo, causa, tempo_parada_min, tempo_reparo_min, descricao, peca_substituida, turno, data, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Registro de manutenção não encontrado" });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro PUT /manutencao/registros/:id:", error.message);
    res.status(500).json({ erro: "Erro ao atualizar registro de manutenção" });
  }
});

/**
 * ROTA: EXCLUIR REGISTRO DE MANUTENÇÃO
 */
app.delete("/api/manutencao/registros/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      "DELETE FROM manutencao_registros WHERE id = $1 RETURNING id",
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Registro de manutenção não encontrado" });
    }

    res.status(200).json({ 
      mensagem: "Registro de manutenção excluído com sucesso",
      id: result.rows[0].id
    });
  } catch (error) {
    console.error("❌ Erro DELETE /manutencao/registros/:id:", error.message);
    res.status(500).json({ erro: "Erro ao excluir registro de manutenção" });
  }
});

// ========================================
// 📊 MÓDULO: CONFIABILIDADE (MTBF / MTTR)
// ========================================

/**
 * CLASSIFICADORES INTERNOS DE CONFIABILIDADE
 * Limiares baseados em padrões industriais — não variam por cliente
 * MTBF (Mean Time Between Failures): tempo médio entre falhas
 * MTTR (Mean Time To Repair): tempo médio de reparo
 */
const LIMIARES_CONFIABILIDADE = {
  mttr: {
    bom: 30,      // < 30 min = bom
    atencao: 120  // 30–120 min = atenção | > 120 min = crítico
  },
  mtbf: {
    critico: 120, // < 120 min = crítico
    atencao: 480  // 120–480 min = atenção | > 480 min = bom
  }
};

function classificarMTTR(mttr) {
  if (mttr === 0) return { label: 'Sem dados suficientes', slug: 'gray' };
  if (mttr < LIMIARES_CONFIABILIDADE.mttr.bom) {
    return { label: 'Tempo de reparo adequado', slug: 'green' };
  }
  if (mttr < LIMIARES_CONFIABILIDADE.mttr.atencao) {
    return { label: 'Tempo de reparo elevado — revisar processo de manutenção', slug: 'yellow' };
  }
  return { label: 'Tempo de reparo crítico — intervenção necessária', slug: 'red' };
}

function classificarMTBF(mtbf) {
  if (mtbf === 0) return { label: 'Sem dados suficientes', slug: 'gray' };
  if (mtbf < LIMIARES_CONFIABILIDADE.mtbf.critico) {
    return { label: 'Frequência de falhas crítica — equipamento instável', slug: 'red' };
  }
  if (mtbf < LIMIARES_CONFIABILIDADE.mtbf.atencao) {
    return { label: 'Frequência de falhas elevada — plano preventivo recomendado', slug: 'yellow' };
  }
  return { label: 'Frequência de falhas adequada', slug: 'green' };
}

/**
 * FUNÇÃO CENTRAL DE CÁLCULO
 * Recebe array de registros de manutenção e período em horas
 * Retorna todas as métricas de confiabilidade
 */
function calcularConfiabilidade(registros, periodoHoras) {
  const TIPOS_FALHA = ['corretiva', 'quebra', 'corretiva_emergencial'];
  const falhas = registros.filter(r => TIPOS_FALHA.includes(r.tipo));
  const totalFalhas = falhas.length;

  if (totalFalhas === 0) {
    return {
      total_registros: registros.length,
      total_falhas: 0,
      tempo_total_parada_min: 0,
      tempo_total_reparo_min: 0,
      mtbf_minutos: 0,
      mtbf_horas: 0,
      mttr_minutos: 0,
      taxa_falha: 0,
      disponibilidade_calculada: 100
    };
  }

  const tempoTotalReparo = falhas.reduce(
    (acc, r) => acc + (parseFloat(r.tempo_reparo_min) || 0), 0
  );
  const tempoTotalParada = registros.reduce(
    (acc, r) => acc + (parseFloat(r.tempo_parada_min) || 0), 0
  );

  const periodoMinutos = periodoHoras * 60;
  const tempoOperando = Math.max(0, periodoMinutos - tempoTotalParada);
  const mtbf = totalFalhas > 0 ? tempoOperando / totalFalhas : periodoMinutos;
  const mttr = totalFalhas > 0 ? tempoTotalReparo / totalFalhas : 0;
  const taxaFalha = mtbf > 0 ? 1 / mtbf : 0;
  const disponibilidade = periodoMinutos > 0
    ? (tempoOperando / periodoMinutos) * 100
    : 100;

  return {
    total_registros: registros.length,
    total_falhas: totalFalhas,
    tempo_total_parada_min: parseFloat(tempoTotalParada.toFixed(2)),
    tempo_total_reparo_min: parseFloat(tempoTotalReparo.toFixed(2)),
    mtbf_minutos: parseFloat(mtbf.toFixed(2)),
    mtbf_horas: parseFloat((mtbf / 60).toFixed(2)),
    mttr_minutos: parseFloat(mttr.toFixed(2)),
    taxa_falha: parseFloat(taxaFalha.toFixed(6)),
    disponibilidade_calculada: parseFloat(disponibilidade.toFixed(2))
  };
}

/**
 * HELPER: calcula período em horas entre datas
 */
function calcularPeriodoHoras(registros, dataInicio, dataFim, horasDia) {
  if (registros.length === 0) return 0;
  const inicio = new Date(dataInicio || registros[0].data);
  const fim = new Date(dataFim || registros[registros.length - 1].data);
  const dias = Math.max(1, Math.ceil((fim - inicio) / (1000 * 60 * 60 * 24)) + 1);
  return dias * (parseFloat(horasDia) || 8.8);
}

// ----------------------------------------
// 1️⃣ CONFIABILIDADE POR POSTO
// Calcula MTBF e MTTR de um posto específico
// Rota: GET /api/confiabilidade/posto/:postoId
// Query params: data_inicio, data_fim (YYYY-MM-DD)
// ----------------------------------------
app.get("/api/confiabilidade/posto/:postoId", autenticarToken, async (req, res) => {
  const { postoId } = req.params;
  const { data_inicio, data_fim } = req.query;

  try {
    // Buscar dados do posto e horas disponíveis da linha
    const postoRes = await pool.query(`
      SELECT pt.*, l.horas_disponiveis
      FROM posto_trabalho pt
      JOIN linhas_producao l ON l.id = pt.linha_id
      WHERE pt.id = $1
    `, [postoId]);

    if (postoRes.rows.length === 0) {
      return res.status(404).json({ erro: "Posto não encontrado" });
    }

    const posto = postoRes.rows[0];

    // Buscar registros de manutenção com filtro de data opcional
    let query = "SELECT * FROM manutencao_registros WHERE posto_id = $1";
    const values = [postoId];
    let idx = 2;

    if (data_inicio) { query += ` AND data >= $${idx}`; values.push(data_inicio); idx++; }
    if (data_fim)    { query += ` AND data <= $${idx}`; values.push(data_fim);    idx++; }

    query += " ORDER BY data ASC";
    const registrosRes = await pool.query(query, values);
    const registros = registrosRes.rows;

    // Calcular período e métricas
    const periodoHoras = calcularPeriodoHoras(
      registros, data_inicio, data_fim, posto.horas_disponiveis
    );
    const metricas = calcularConfiabilidade(registros, periodoHoras);

    // Classificar
    const classifMTBF = classificarMTBF(metricas.mtbf_minutos);
    const classifMTTR = classificarMTTR(metricas.mttr_minutos);
    const statusGeral = (classifMTBF.slug === 'red' || classifMTTR.slug === 'red') ? 'red' :
                        (classifMTBF.slug === 'yellow' || classifMTTR.slug === 'yellow') ? 'yellow' :
                        metricas.total_falhas === 0 ? 'gray' : 'green';

    // Tipo de falha mais frequente
    const tiposFreq = registros.reduce((acc, r) => {
      acc[r.tipo] = (acc[r.tipo] || 0) + 1;
      return acc;
    }, {});
    const tipoMaisFrequente = Object.entries(tiposFreq)
      .sort((a, b) => b[1] - a[1])[0];

    // Ação recomendada
    let acaoRecomendada = "Manter monitoramento periódico.";
    if (statusGeral === 'red') {
      acaoRecomendada = "Implementar plano de manutenção preventiva urgente e revisar procedimento de reparo.";
    } else if (statusGeral === 'yellow') {
      acaoRecomendada = "Revisar frequência da manutenção preventiva e capacitar equipe de manutenção.";
    }

    res.status(200).json({
      posto_id: parseInt(postoId),
      posto_nome: posto.nome,
      periodo_analisado: {
        data_inicio: data_inicio || "início dos registros",
        data_fim: data_fim || "último registro",
        horas_totais: parseFloat(periodoHoras.toFixed(2))
      },
      metricas,
      classificacao: {
        mtbf: {
          ...classifMTBF,
          referencia: "Bom: MTBF > 480 min | Atenção: 120–480 min | Crítico: < 120 min"
        },
        mttr: {
          ...classifMTTR,
          referencia: "Bom: MTTR < 30 min | Atenção: 30–120 min | Crítico: > 120 min"
        },
        status_geral: statusGeral
      },
      tipo_falha_mais_frequente: tipoMaisFrequente
        ? { tipo: tipoMaisFrequente[0], ocorrencias: tipoMaisFrequente[1] }
        : null,
      acao_recomendada: acaoRecomendada
    });

  } catch (error) {
    console.error("❌ Erro na confiabilidade do posto:", error.message);
    res.status(500).json({ erro: "Falha ao calcular confiabilidade do posto" });
  }
});

// ----------------------------------------
// 2️⃣ CONFIABILIDADE POR LINHA
// Agrega MTBF e MTTR de todos os postos de uma linha
// Rota: GET /api/confiabilidade/linha/:linhaId
// Query params: data_inicio, data_fim (YYYY-MM-DD)
// ----------------------------------------
app.get("/api/confiabilidade/linha/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;
  const { data_inicio, data_fim } = req.query;

  try {
    // Buscar postos da linha
    const postosRes = await pool.query(`
      SELECT pt.*, l.horas_disponiveis
      FROM posto_trabalho pt
      JOIN linhas_producao l ON l.id = pt.linha_id
      WHERE pt.linha_id = $1
      ORDER BY pt.ordem_fluxo ASC
    `, [linhaId]);

    if (postosRes.rows.length === 0) {
      return res.status(404).json({ erro: "Nenhum posto encontrado para esta linha" });
    }

    const horasDia = parseFloat(postosRes.rows[0].horas_disponiveis) || 8.8;

    // Buscar todos os registros de manutenção da linha
    let query = `
      SELECT mr.*
      FROM manutencao_registros mr
      JOIN posto_trabalho pt ON pt.id = mr.posto_id
      WHERE pt.linha_id = $1
    `;
    const values = [linhaId];
    let idx = 2;

    if (data_inicio) { query += ` AND mr.data >= $${idx}`; values.push(data_inicio); idx++; }
    if (data_fim)    { query += ` AND mr.data <= $${idx}`; values.push(data_fim);    idx++; }

    query += " ORDER BY mr.data ASC";
    const registrosRes = await pool.query(query, values);
    const registros = registrosRes.rows;

    // Período e métricas globais
    const periodoHoras = calcularPeriodoHoras(registros, data_inicio, data_fim, horasDia);
    const metricasGlobais = calcularConfiabilidade(registros, periodoHoras);

    // Detalhamento por posto
    const detalhamentoPorPosto = postosRes.rows.map(posto => {
      const registrosPosto = registros.filter(r => r.posto_id === posto.id);
      const metricas = calcularConfiabilidade(registrosPosto, periodoHoras);
      const classifMTBF = classificarMTBF(metricas.mtbf_minutos);
      const classifMTTR = classificarMTTR(metricas.mttr_minutos);
      const statusGeral = metricas.total_falhas === 0 ? 'gray' :
        (classifMTBF.slug === 'red' || classifMTTR.slug === 'red') ? 'red' :
        (classifMTBF.slug === 'yellow' || classifMTTR.slug === 'yellow') ? 'yellow' : 'green';

      return {
        posto_id: posto.id,
        posto_nome: posto.nome,
        ordem_fluxo: posto.ordem_fluxo,
        total_falhas: metricas.total_falhas,
        mtbf_horas: metricas.mtbf_horas,
        mttr_minutos: metricas.mttr_minutos,
        disponibilidade_percentual: metricas.disponibilidade_calculada,
        status_geral: statusGeral,
        classificacao_mtbf: classifMTBF.label,
        classificacao_mttr: classifMTTR.label
      };
    });

    // Posto mais crítico (menor MTBF com pelo menos 1 falha)
    const postoCritico = detalhamentoPorPosto
      .filter(p => p.total_falhas > 0)
      .sort((a, b) => a.mtbf_horas - b.mtbf_horas)[0] || null;

    const classifGeral = classificarMTBF(metricasGlobais.mtbf_minutos);
    const statusGeral = metricasGlobais.total_falhas === 0 ? 'gray' :
      detalhamentoPorPosto.some(p => p.status_geral === 'red') ? 'red' :
      detalhamentoPorPosto.some(p => p.status_geral === 'yellow') ? 'yellow' : 'green';

    res.status(200).json({
      linha_id: parseInt(linhaId),
      periodo_analisado: {
        data_inicio: data_inicio || "início dos registros",
        data_fim: data_fim || "último registro",
        horas_totais: parseFloat(periodoHoras.toFixed(2))
      },
      metricas_globais: metricasGlobais,
      classificacao_geral: {
        ...classifGeral,
        status_geral: statusGeral,
        referencia: "MTBF > 480 min = bom | 120–480 min = atenção | < 120 min = crítico"
      },
      posto_mais_critico: postoCritico,
      detalhamento_por_posto: detalhamentoPorPosto,
      acao_recomendada: postoCritico && statusGeral !== 'green'
        ? `Priorizar manutenção preventiva no posto "${postoCritico.posto_nome}" — maior fonte de falhas da linha.`
        : "Manter frequência de manutenção preventiva atual."
    });

  } catch (error) {
    console.error("❌ Erro na confiabilidade da linha:", error.message);
    res.status(500).json({ erro: "Falha ao calcular confiabilidade da linha" });
  }
});

// ----------------------------------------
// 3️⃣ RANKING DE CONFIABILIDADE POR EMPRESA
// Ordena todos os postos do mais crítico ao mais estável
// Rota: GET /api/confiabilidade/ranking/:empresaId
// Query params: data_inicio, data_fim (YYYY-MM-DD)
// ----------------------------------------
app.get("/api/confiabilidade/ranking/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;
  const { data_inicio, data_fim } = req.query;

  try {
    // Agregar registros de manutenção por posto, já com totais calculados pelo banco
    let query = `
      SELECT
        pt.id                                                          AS posto_id,
        pt.nome                                                        AS posto_nome,
        l.id                                                           AS linha_id,
        l.nome                                                         AS linha_nome,
        l.horas_disponiveis,
        COUNT(mr.id)                                                   AS total_registros,
        COUNT(mr.id) FILTER (WHERE mr.tipo IN (
          'corretiva', 'quebra', 'corretiva_emergencial'))             AS total_falhas,
        COALESCE(SUM(mr.tempo_parada_min), 0)                         AS tempo_total_parada,
        COALESCE(SUM(mr.tempo_reparo_min) FILTER (WHERE mr.tipo IN (
          'corretiva', 'quebra', 'corretiva_emergencial')), 0)         AS tempo_total_reparo,
        MIN(mr.data)                                                   AS primeira_data,
        MAX(mr.data)                                                   AS ultima_data
      FROM posto_trabalho pt
      JOIN linhas_producao l ON l.id = pt.linha_id
      LEFT JOIN manutencao_registros mr ON mr.posto_id = pt.id
    `;

    const values = [empresaId];
    let idx = 2;
    query += " WHERE l.empresa_id = $1";

    if (data_inicio) {
      query += ` AND (mr.data >= $${idx} OR mr.data IS NULL)`;
      values.push(data_inicio); idx++;
    }
    if (data_fim) {
      query += ` AND (mr.data <= $${idx} OR mr.data IS NULL)`;
      values.push(data_fim); idx++;
    }

    query += " GROUP BY pt.id, pt.nome, l.id, l.nome, l.horas_disponiveis ORDER BY total_falhas DESC";

    const result = await pool.query(query, values);

    // Calcular métricas e classificar cada posto
    const ranking = result.rows.map(posto => {
      const totalFalhas    = parseInt(posto.total_falhas)    || 0;
      const tempoParada    = parseFloat(posto.tempo_total_parada)  || 0;
      const tempoReparo    = parseFloat(posto.tempo_total_reparo)  || 0;
      const horasDia       = parseFloat(posto.horas_disponiveis)   || 8.8;

      let periodoMinutos = 0;
      if (posto.primeira_data) {
        const dias = Math.max(1, Math.ceil(
          (new Date(posto.ultima_data) - new Date(posto.primeira_data))
          / (1000 * 60 * 60 * 24)
        ) + 1);
        periodoMinutos = dias * horasDia * 60;
      }

      const tempoOperando  = Math.max(0, periodoMinutos - tempoParada);
      const mtbf           = totalFalhas > 0 && periodoMinutos > 0
                             ? tempoOperando / totalFalhas : 0;
      const mttr           = totalFalhas > 0 ? tempoReparo / totalFalhas : 0;
      const disponibilidade = periodoMinutos > 0
                              ? (tempoOperando / periodoMinutos) * 100 : 100;

      const classifMTBF = classificarMTBF(mtbf);
      const classifMTTR = classificarMTTR(mttr);
      const statusGeral = totalFalhas === 0 ? 'gray' :
        (classifMTBF.slug === 'red' || classifMTTR.slug === 'red') ? 'red' :
        (classifMTBF.slug === 'yellow' || classifMTTR.slug === 'yellow') ? 'yellow' : 'green';

      return {
        posto_id:                   posto.posto_id,
        posto_nome:                 posto.posto_nome,
        linha_id:                   posto.linha_id,
        linha_nome:                 posto.linha_nome,
        total_falhas:               totalFalhas,
        mtbf_horas:                 parseFloat((mtbf / 60).toFixed(2)),
        mttr_minutos:               parseFloat(mttr.toFixed(2)),
        disponibilidade_percentual: parseFloat(disponibilidade.toFixed(2)),
        status_geral:               statusGeral,
        classificacao_mtbf:         classifMTBF.label,
        classificacao_mttr:         classifMTTR.label
      };
    });

    const criticos = ranking.filter(p => p.status_geral === 'red');
    const atencao  = ranking.filter(p => p.status_geral === 'yellow');
    const estaveis = ranking.filter(p => p.status_geral === 'green');

    res.status(200).json({
      empresa_id: parseInt(empresaId),
      total_postos_analisados: ranking.length,
      resumo: {
        criticos: criticos.length,
        atencao:  atencao.length,
        estaveis: estaveis.length
      },
      ranking_completo: ranking,
      postos_criticos:  criticos,
      postos_atencao:   atencao,
      referencias: {
        mtbf_bom:      "MTBF > 8 horas",
        mtbf_atencao:  "MTBF entre 2h e 8h",
        mtbf_critico:  "MTBF < 2 horas",
        mttr_bom:      "MTTR < 30 minutos",
        mttr_atencao:  "MTTR entre 30 e 120 minutos",
        mttr_critico:  "MTTR > 120 minutos"
      }
    });

  } catch (error) {
    console.error("❌ Erro no ranking de confiabilidade:", error.message);
    res.status(500).json({ erro: "Falha ao gerar ranking de confiabilidade" });
  }
});

// ========================================
// 📊 MÓDULO: CAPABILIDADE DE PROCESSO (Cp / Cpk)
// ========================================

/**
 * LIMIARES ISO PARA ÍNDICES DE CAPABILIDADE
 * Baseados na norma ISO 22514 / AIAG — não variam por cliente
 *
 * Cp  = (LSE - LIE) / (6σ)           → mede se o processo CABE na tolerância
 * Cpk = min(CPU, CPL)                 → mede se o processo está CENTRADO
 * CPU = (LSE - média) / (3σ)
 * CPL = (média - LIE) / (3σ)
 */
const LIMIARES_CAPABILIDADE = {
  incapaz:   1.00,   // Cp/Cpk < 1.00 → processo incapaz (gera defeitos)
  marginal:  1.33,   // 1.00 ≤ Cp/Cpk < 1.33 → capaz mas sem margem
  bom:       1.67,   // 1.33 ≤ Cp/Cpk < 1.67 → bom
  excelente: 1.67    // Cp/Cpk ≥ 1.67 → excelente (Six Sigma)
};

function classificarCapabilidade(valor) {
  if (valor === null || isNaN(valor)) {
    return {
      label: 'Sem dados suficientes ou limites não informados',
      slug:  'gray',
      descricao: 'Informe os limites superior e inferior nas medições para calcular o índice.'
    };
  }
  if (valor < LIMIARES_CAPABILIDADE.incapaz) {
    return {
      label:    'Processo INCAPAZ — gerando defeitos fora da tolerância',
      slug:     'red',
      descricao: `Cp/Cpk = ${valor.toFixed(3)} está abaixo de 1.00. O processo não consegue atender a especificação. Ação imediata necessária.`
    };
  }
  if (valor < LIMIARES_CAPABILIDADE.marginal) {
    return {
      label:    'Processo CAPAZ mas sem margem de segurança',
      slug:     'yellow',
      descricao: `Cp/Cpk = ${valor.toFixed(3)} está entre 1.00 e 1.33. O processo atende a especificação, mas qualquer variação pode gerar defeitos.`
    };
  }
  if (valor < LIMIARES_CAPABILIDADE.excelente) {
    return {
      label:    'Processo BOM — dentro da tolerância com margem',
      slug:     'blue',
      descricao: `Cp/Cpk = ${valor.toFixed(3)} está entre 1.33 e 1.67. Processo estável e capaz. Manter monitoramento.`
    };
  }
  return {
    label:    'Processo EXCELENTE — nível Six Sigma',
    slug:     'green',
    descricao: `Cp/Cpk = ${valor.toFixed(3)} está acima de 1.67. Processo altamente capaz e centrado.`
  };
}

/**
 * FUNÇÃO CENTRAL DE CÁLCULO DE CAPABILIDADE
 * Recebe array de valores medidos + LSE + LIE
 * Retorna Cp, Cpk, CPU, CPL, desvio padrão, média e demais estatísticas
 */
function calcularIndicesCapabilidade(valores, lse, lie) {
  const n = valores.length;

  // Mínimo estatístico recomendado: 25 amostras
  if (n < 5) {
    return { valido: false, motivo: `Amostras insuficientes: ${n} medições. Mínimo recomendado: 25.` };
  }

  const toleranciaDefinida = lse !== null && lie !== null &&
                              !isNaN(lse) && !isNaN(lie) &&
                              lse > lie;

  const soma  = valores.reduce((a, b) => a + b, 0);
  const media = soma / n;

  // Desvio padrão amostral (n-1)
  const variancia    = valores.reduce((acc, v) => acc + Math.pow(v - media, 2), 0) / (n - 1);
  const desvioPadrao = Math.sqrt(variancia);

  const resultado = {
    valido:          true,
    n,
    media:           parseFloat(media.toFixed(6)),
    desvio_padrao:   parseFloat(desvioPadrao.toFixed(6)),
    minimo:          parseFloat(Math.min(...valores).toFixed(6)),
    maximo:          parseFloat(Math.max(...valores).toFixed(6)),
    amplitude:       parseFloat((Math.max(...valores) - Math.min(...valores)).toFixed(6)),
    cp:              null,
    cpk:             null,
    cpu:             null,
    cpl:             null,
    lse,
    lie,
    tolerancia_definida: toleranciaDefinida,
    alerta_amostras: n < 25
      ? `⚠️ Resultado indicativo: ${n} amostras. Para confiabilidade estatística, use ≥ 25 medições.`
      : null
  };

  if (!toleranciaDefinida || desvioPadrao === 0) {
    resultado.motivo_sem_indice = desvioPadrao === 0
      ? 'Desvio padrão zero — todas as medições são idênticas.'
      : 'Limites superior e inferior não definidos ou inválidos.';
    return resultado;
  }

  const tol = lse - lie;
  const cp  = tol / (6 * desvioPadrao);
  const cpu = (lse - media) / (3 * desvioPadrao);
  const cpl = (media - lie) / (3 * desvioPadrao);
  const cpk = Math.min(cpu, cpl);

  resultado.cp  = parseFloat(cp.toFixed(4));
  resultado.cpk = parseFloat(cpk.toFixed(4));
  resultado.cpu = parseFloat(cpu.toFixed(4));
  resultado.cpl = parseFloat(cpl.toFixed(4));

  // % do processo dentro da tolerância (estimativa normal)
  const z = Math.min(cpu, cpl) * 3;
  // Usando aproximação da função de distribuição normal cumulativa
  const ppm_estimado = z >= 6 ? 3.4 : null; // só mostra PPM para Six Sigma
  resultado.ppm_estimado = ppm_estimado;

  return resultado;
}

// ----------------------------------------
// 1️⃣ CAPABILIDADE POR CARACTERÍSTICA E POSTO
// Calcula Cp e Cpk de uma característica específica em um posto
// Rota: GET /api/capabilidade/posto/:postoId
// Query params: caracteristica (obrigatório), data_inicio, data_fim, produto_id
// ----------------------------------------
app.get("/api/capabilidade/posto/:postoId", autenticarToken, async (req, res) => {
  const { postoId } = req.params;
  const { caracteristica, data_inicio, data_fim, produto_id } = req.query;

  if (!caracteristica) {
    return res.status(400).json({
      erro: "O parâmetro 'caracteristica' é obrigatório.",
      dica: "Exemplo: ?caracteristica=diametro_furo&data_inicio=2025-01-01"
    });
  }

  try {
    // Verificar se o posto existe
    const postoRes = await pool.query(
      "SELECT pt.*, l.nome as linha_nome FROM posto_trabalho pt JOIN linhas_producao l ON l.id = pt.linha_id WHERE pt.id = $1",
      [postoId]
    );
    if (postoRes.rows.length === 0) {
      return res.status(404).json({ erro: "Posto não encontrado." });
    }
    const posto = postoRes.rows[0];

    // Montar query dinâmica com filtros opcionais
    let query = `
      SELECT valor_medido, limite_superior, limite_inferior, data, unidade
      FROM medicoes_qualidade
      WHERE posto_id = $1 AND LOWER(caracteristica) = LOWER($2)
    `;
    const values = [postoId, caracteristica];
    let idx = 3;

    if (data_inicio)  { query += ` AND data >= $${idx}`; values.push(data_inicio);  idx++; }
    if (data_fim)     { query += ` AND data <= $${idx}`; values.push(data_fim);      idx++; }
    if (produto_id)   { query += ` AND produto_id = $${idx}`; values.push(produto_id); idx++; }

    query += " ORDER BY data ASC";
    const medicoesRes = await pool.query(query, values);

    if (medicoesRes.rows.length === 0) {
      return res.status(404).json({
        erro: "Nenhuma medição encontrada para esta característica neste posto.",
        dica: "Verifique o nome da característica ou o período informado."
      });
    }

    const medições = medicoesRes.rows;
    const valores  = medições.map(m => parseFloat(m.valor_medido));
    const lse      = medições.find(m => m.limite_superior !== null)?.limite_superior ?? null;
    const lie      = medições.find(m => m.limite_inferior !== null)?.limite_inferior ?? null;
    const unidade  = medições[0].unidade || "";

    const indices  = calcularIndicesCapabilidade(
      valores,
      lse !== null ? parseFloat(lse) : null,
      lie !== null ? parseFloat(lie) : null
    );

    if (!indices.valido) {
      return res.status(422).json({ erro: indices.motivo });
    }

    const classifCp  = classificarCapabilidade(indices.cp);
    const classifCpk = classificarCapabilidade(indices.cpk);

    // Ação recomendada baseada no pior índice
    const piorSlug = [classifCp.slug, classifCpk.slug].includes('red') ? 'red' :
                     [classifCp.slug, classifCpk.slug].includes('yellow') ? 'yellow' : classifCp.slug;

    const acaoRecomendada =
      piorSlug === 'red'
        ? "Investigar causa raiz imediatamente. Verificar setup, desgaste de ferramenta e calibração do instrumento de medição."
        : piorSlug === 'yellow'
        ? "Reduzir variabilidade. Verificar padronização do método de operação e condições do processo."
        : "Manter monitoramento periódico. Registrar pelo menos 25 medições por período de análise.";

    res.status(200).json({
      posto_id:     parseInt(postoId),
      posto_nome:   posto.nome,
      linha_nome:   posto.linha_nome,
      caracteristica,
      unidade,
      periodo_analisado: {
        data_inicio: data_inicio || medições[0].data,
        data_fim:    data_fim    || medições[medições.length - 1].data
      },
      estatisticas: {
        n:            indices.n,
        media:        indices.media,
        desvio_padrao:indices.desvio_padrao,
        minimo:       indices.minimo,
        maximo:       indices.maximo,
        amplitude:    indices.amplitude,
        lse:          indices.lse,
        lie:          indices.lie
      },
      indices_capabilidade: {
        cp:  indices.cp,
        cpk: indices.cpk,
        cpu: indices.cpu,
        cpl: indices.cpl
      },
      classificacao: {
        cp:  classifCp,
        cpk: classifCpk,
        status_geral: piorSlug,
        referencia: "Cp/Cpk < 1.00 = incapaz | 1.00–1.33 = marginal | 1.33–1.67 = bom | ≥ 1.67 = excelente (ISO 22514)"
      },
      alertas: [
        indices.alerta_amostras,
        indices.motivo_sem_indice,
        indices.cpk !== null && indices.cp !== null && (indices.cp - indices.cpk) > 0.3
          ? `⚠️ Processo descentrado: diferença entre Cp (${indices.cp}) e Cpk (${indices.cpk}) > 0.3. Verificar ajuste de setup.`
          : null
      ].filter(Boolean),
      acao_recomendada: acaoRecomendada
    });

  } catch (error) {
    console.error("❌ Erro na capabilidade do posto:", error.message);
    res.status(500).json({ erro: "Falha ao calcular índices de capabilidade." });
  }
});

// ----------------------------------------
// 2️⃣ CAPABILIDADE POR LINHA
// Retorna Cp e Cpk de TODAS as características medidas na linha
// Rota: GET /api/capabilidade/linha/:linhaId
// Query params: data_inicio, data_fim
// ----------------------------------------
app.get("/api/capabilidade/linha/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;
  const { data_inicio, data_fim } = req.query;

  try {
    // Buscar todas as medições da linha, agrupadas por posto + característica
    let query = `
      SELECT
        mq.posto_id,
        pt.nome                          AS posto_nome,
        mq.caracteristica,
        mq.unidade,
        ARRAY_AGG(mq.valor_medido::FLOAT ORDER BY mq.data) AS valores,
        MAX(mq.limite_superior::FLOAT)   AS lse,
        MAX(mq.limite_inferior::FLOAT)   AS lie,
        COUNT(*)                         AS n
      FROM medicoes_qualidade mq
      JOIN posto_trabalho pt ON pt.id = mq.posto_id
      WHERE pt.linha_id = $1
    `;
    const values = [linhaId];
    let idx = 2;

    if (data_inicio) { query += ` AND mq.data >= $${idx}`; values.push(data_inicio); idx++; }
    if (data_fim)    { query += ` AND mq.data <= $${idx}`; values.push(data_fim);    idx++; }

    query += " GROUP BY mq.posto_id, pt.nome, mq.caracteristica, mq.unidade ORDER BY pt.nome, mq.caracteristica";

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({
        erro: "Nenhuma medição de qualidade encontrada para esta linha.",
        dica: "Registre medições dimensionais com limites superior e inferior definidos."
      });
    }

    // Calcular índices para cada combinação posto × característica
    const analises = result.rows.map(row => {
      const valores = row.valores.map(v => parseFloat(v));
      const indices = calcularIndicesCapabilidade(
        valores,
        row.lse !== null ? parseFloat(row.lse) : null,
        row.lie !== null ? parseFloat(row.lie) : null
      );

      const classifCpk = classificarCapabilidade(indices.cpk);
      const statusGeral = indices.valido
        ? classifCpk.slug
        : 'gray';

      return {
        posto_id:      row.posto_id,
        posto_nome:    row.posto_nome,
        caracteristica: row.caracteristica,
        unidade:       row.unidade,
        n:             parseInt(row.n),
        cp:            indices.cp,
        cpk:           indices.cpk,
        media:         indices.media,
        desvio_padrao: indices.desvio_padrao,
        lse:           indices.lse,
        lie:           indices.lie,
        status_geral:  statusGeral,
        classificacao: classifCpk.label,
        alerta:        indices.alerta_amostras || indices.motivo_sem_indice || null
      };
    });

    // Resumo por status
    const resumo = {
      total_caracteristicas: analises.length,
      incapazes:  analises.filter(a => a.status_geral === 'red').length,
      marginais:  analises.filter(a => a.status_geral === 'yellow').length,
      boas:       analises.filter(a => a.status_geral === 'blue').length,
      excelentes: analises.filter(a => a.status_geral === 'green').length,
      sem_dados:  analises.filter(a => a.status_geral === 'gray').length
    };

    // Pior característica (menor Cpk válido)
    const comCpk = analises.filter(a => a.cpk !== null);
    const piorCaracteristica = comCpk.sort((a, b) => a.cpk - b.cpk)[0] || null;

    const statusLinhaGeral =
      resumo.incapazes > 0  ? 'red'    :
      resumo.marginais  > 0  ? 'yellow' :
      resumo.boas       > 0  ? 'blue'   :
      resumo.excelentes > 0  ? 'green'  : 'gray';

    res.status(200).json({
      linha_id: parseInt(linhaId),
      periodo_analisado: {
        data_inicio: data_inicio || "início dos registros",
        data_fim:    data_fim    || "último registro"
      },
      resumo,
      status_geral_linha: statusLinhaGeral,
      pior_caracteristica: piorCaracteristica,
      analise_por_caracteristica: analises,
      acao_recomendada:
        statusLinhaGeral === 'red'
          ? `Característica crítica: "${piorCaracteristica?.caracteristica}" no posto "${piorCaracteristica?.posto_nome}". Iniciar análise de causa raiz imediatamente.`
          : statusLinhaGeral === 'yellow'
          ? "Reduzir variabilidade nas características marginais. Revisar padronização de método e condições de processo."
          : "Processo dentro dos padrões de qualidade. Manter frequência de medição.",
      referencia: "ISO 22514 | Cpk < 1.00 = incapaz | 1.00–1.33 = marginal | 1.33–1.67 = bom | ≥ 1.67 = excelente"
    });

  } catch (error) {
    console.error("❌ Erro na capabilidade da linha:", error.message);
    res.status(500).json({ erro: "Falha ao calcular capabilidade da linha." });
  }
});

// ----------------------------------------
// 3️⃣ RANKING DE CAPABILIDADE POR EMPRESA
// Lista todas as características de todas as linhas, do mais crítico ao mais capaz
// Rota: GET /api/capabilidade/ranking/:empresaId
// Query params: data_inicio, data_fim
// ----------------------------------------
app.get("/api/capabilidade/ranking/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;
  const { data_inicio, data_fim } = req.query;

  try {
    let query = `
      SELECT
        mq.posto_id,
        pt.nome                          AS posto_nome,
        l.id                             AS linha_id,
        l.nome                           AS linha_nome,
        mq.caracteristica,
        mq.unidade,
        ARRAY_AGG(mq.valor_medido::FLOAT ORDER BY mq.data) AS valores,
        MAX(mq.limite_superior::FLOAT)   AS lse,
        MAX(mq.limite_inferior::FLOAT)   AS lie,
        COUNT(*)                         AS n
      FROM medicoes_qualidade mq
      JOIN posto_trabalho pt ON pt.id = mq.posto_id
      JOIN linhas_producao l ON l.id = pt.linha_id
      WHERE l.empresa_id = $1
    `;
    const values = [empresaId];
    let idx = 2;

    if (data_inicio) { query += ` AND mq.data >= $${idx}`; values.push(data_inicio); idx++; }
    if (data_fim)    { query += ` AND mq.data <= $${idx}`; values.push(data_fim);    idx++; }

    query += " GROUP BY mq.posto_id, pt.nome, l.id, l.nome, mq.caracteristica, mq.unidade";

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({
        erro: "Nenhuma medição de qualidade encontrada para esta empresa.",
        dica: "Registre medições dimensionais com limites definidos para gerar o ranking."
      });
    }

    // Calcular índices para cada linha do resultado
    const ranking = result.rows
      .map(row => {
        const valores = row.valores.map(v => parseFloat(v));
        const indices = calcularIndicesCapabilidade(
          valores,
          row.lse !== null ? parseFloat(row.lse) : null,
          row.lie !== null ? parseFloat(row.lie) : null
        );
        const classifCpk = classificarCapabilidade(indices.cpk);

        return {
          posto_id:       row.posto_id,
          posto_nome:     row.posto_nome,
          linha_id:       row.linha_id,
          linha_nome:     row.linha_nome,
          caracteristica: row.caracteristica,
          unidade:        row.unidade,
          n:              parseInt(row.n),
          cp:             indices.cp,
          cpk:            indices.cpk,
          media:          indices.media,
          desvio_padrao:  indices.desvio_padrao,
          lse:            indices.lse,
          lie:            indices.lie,
          status_geral:   indices.cpk !== null ? classifCpk.slug : 'gray',
          classificacao:  classifCpk.label
        };
      })
      // Ordenar: incapazes primeiro (Cpk menor), sem índice no final
      .sort((a, b) => {
        if (a.cpk === null && b.cpk === null) return 0;
        if (a.cpk === null) return 1;
        if (b.cpk === null) return -1;
        return a.cpk - b.cpk;
      });

    const resumo = {
      total_caracteristicas: ranking.length,
      incapazes:  ranking.filter(r => r.status_geral === 'red').length,
      marginais:  ranking.filter(r => r.status_geral === 'yellow').length,
      boas:       ranking.filter(r => r.status_geral === 'blue').length,
      excelentes: ranking.filter(r => r.status_geral === 'green').length,
      sem_indice: ranking.filter(r => r.status_geral === 'gray').length
    };

    res.status(200).json({
      empresa_id: parseInt(empresaId),
      periodo_analisado: {
        data_inicio: data_inicio || "início dos registros",
        data_fim:    data_fim    || "último registro"
      },
      resumo,
      ranking_completo:       ranking,
      caracteristicas_criticas: ranking.filter(r => r.status_geral === 'red'),
      referencias: {
        cpk_incapaz:   "Cpk < 1.00 — processo gerando defeitos",
        cpk_marginal:  "Cpk 1.00–1.33 — capaz sem margem de segurança",
        cpk_bom:       "Cpk 1.33–1.67 — bom",
        cpk_excelente: "Cpk ≥ 1.67 — nível Six Sigma",
        norma:         "ISO 22514 / AIAG MSA"
      }
    });

  } catch (error) {
    console.error("❌ Erro no ranking de capabilidade:", error.message);
    res.status(500).json({ erro: "Falha ao gerar ranking de capabilidade." });
  }
});

// ========================================
// 📊 MÓDULO: ANÁLISE COMPARATIVA POR TURNO
// ========================================

/**
 * LIMIARES DE VARIAÇÃO ENTRE TURNOS
 * Se a diferença de OEE entre o melhor e o pior turno superar
 * esses limites, o sistema emite alerta automático.
 * Baseado em benchmarks de manufatura enxuta.
 */
const LIMIARES_TURNO = {
  variacao_oee_atencao:  10,  // diferença > 10 pp entre turnos = atenção
  variacao_oee_critico:  20,  // diferença > 20 pp entre turnos = crítico
  oee_minimo_aceitavel:  65,  // OEE abaixo de 65% em qualquer turno = alerta
  refugo_max_percentual:  3   // refugo acima de 3% da produção = alerta
};

/**
 * HELPER: classifica a variação de OEE entre turnos
 */
function classificarVariacaoTurno(delta) {
  if (delta === null || isNaN(delta)) return { label: 'Sem dados', slug: 'gray' };
  if (delta >= LIMIARES_TURNO.variacao_oee_critico) {
    return {
      label: `Variação crítica de ${delta.toFixed(1)} pp entre turnos — investigar causa raiz`,
      slug: 'red'
    };
  }
  if (delta >= LIMIARES_TURNO.variacao_oee_atencao) {
    return {
      label: `Variação elevada de ${delta.toFixed(1)} pp entre turnos — revisar método e treinamento`,
      slug: 'yellow'
    };
  }
  return {
    label: `Variação de ${delta.toFixed(1)} pp entre turnos — dentro do aceitável`,
    slug: 'green'
  };
}

/**
 * HELPER: identifica o turno problema (menor OEE)
 * e o turno referência (maior OEE)
 */
function identificarTurnosExtremos(dadosPorTurno) {
  const comDados = dadosPorTurno.filter(t => t.registros > 0);
  if (comDados.length === 0) return { turno_problema: null, turno_referencia: null };

  const pior   = comDados.reduce((a, b) => a.oee_medio < b.oee_medio ? a : b);
  const melhor = comDados.reduce((a, b) => a.oee_medio > b.oee_medio ? a : b);

  return {
    turno_referencia: melhor,
    turno_problema:   pior.turno !== melhor.turno ? pior : null
  };
}

/**
 * HELPER: gera alertas automáticos por turno
 */
function gerarAlertas(turno, producaoTotal) {
  const alertas = [];

  if (turno.oee_medio !== null && turno.oee_medio < LIMIARES_TURNO.oee_minimo_aceitavel) {
    alertas.push(`OEE de ${turno.oee_medio.toFixed(1)}% está abaixo do mínimo aceitável de ${LIMIARES_TURNO.oee_minimo_aceitavel}%.`);
  }

  if (producaoTotal > 0 && turno.total_refugo > 0) {
    const pctRefugo = (turno.total_refugo / producaoTotal) * 100;
    if (pctRefugo > LIMIARES_TURNO.refugo_max_percentual) {
      alertas.push(`Refugo de ${pctRefugo.toFixed(2)}% ultrapassa o limite de ${LIMIARES_TURNO.refugo_max_percentual}%.`);
    }
  }

  return alertas;
}

// ----------------------------------------
// 1️⃣ COMPARATIVO POR TURNO — LINHA
// OEE, perdas e refugo agrupados por turno em uma linha
// Rota: GET /api/turnos/linha/:linhaId
// Query params: data_inicio, data_fim (YYYY-MM-DD)
// ----------------------------------------
app.get("/api/turnos/linha/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;
  const { data_inicio, data_fim } = req.query;

  try {
    // Verificar se a linha existe
    const linhaRes = await pool.query(
      "SELECT id, nome FROM linhas_producao WHERE id = $1",
      [linhaId]
    );
    if (linhaRes.rows.length === 0) {
      return res.status(404).json({ erro: "Linha não encontrada." });
    }
    const linha = linhaRes.rows[0];

    // ── OEE POR TURNO ──
    let queryOEE = `
      SELECT
        turno,
        COUNT(*)                              AS registros,
        ROUND(AVG(oee)::NUMERIC, 2)           AS oee_medio,
        ROUND(AVG(disponibilidade)::NUMERIC, 2) AS disponibilidade_media,
        ROUND(AVG(performance)::NUMERIC, 2)   AS performance_media,
        ROUND(AVG(qualidade)::NUMERIC, 2)     AS qualidade_media,
        SUM(pecas_produzidas)                 AS total_pecas_produzidas,
        SUM(pecas_boas)                       AS total_pecas_boas,
        SUM(pecas_produzidas) - SUM(pecas_boas) AS total_refugo,
        ROUND(AVG(tempo_operando_min)::NUMERIC, 2) AS tempo_operando_medio_min
      FROM producao_oee
      WHERE linha_id = $1
    `;
    const valuesOEE = [linhaId];
    let idx = 2;

    if (data_inicio) { queryOEE += ` AND data >= $${idx}`; valuesOEE.push(data_inicio); idx++; }
    if (data_fim)    { queryOEE += ` AND data <= $${idx}`; valuesOEE.push(data_fim);    idx++; }

    queryOEE += " GROUP BY turno ORDER BY turno ASC";
    const oeeRes = await pool.query(queryOEE, valuesOEE);

    // ── DEFEITOS POR TURNO ──
    let queryDefeitos = `
      SELECT
        dq.turno,
        COUNT(*)          AS ocorrencias_defeitos,
        SUM(dq.quantidade) AS total_defeitos,
        MODE() WITHIN GROUP (ORDER BY dq.tipo_defeito) AS tipo_mais_frequente
      FROM defeitos_qualidade dq
      JOIN posto_trabalho pt ON pt.id = dq.posto_id
      WHERE pt.linha_id = $1
    `;
    const valuesDefeitos = [linhaId];
    let idxD = 2;

    if (data_inicio) { queryDefeitos += ` AND dq.data >= $${idxD}`; valuesDefeitos.push(data_inicio); idxD++; }
    if (data_fim)    { queryDefeitos += ` AND dq.data <= $${idxD}`; valuesDefeitos.push(data_fim);    idxD++; }

    queryDefeitos += " GROUP BY dq.turno ORDER BY dq.turno ASC";
    const defeitosRes = await pool.query(queryDefeitos, valuesDefeitos);

    // ── PARADAS DE MANUTENÇÃO POR TURNO ──
    let queryManutencao = `
      SELECT
        mr.turno,
        COUNT(*)                          AS ocorrencias_paradas,
        SUM(mr.tempo_parada_min)          AS total_parada_min,
        ROUND(AVG(mr.tempo_parada_min)::NUMERIC, 2) AS media_parada_min
      FROM manutencao_registros mr
      JOIN posto_trabalho pt ON pt.id = mr.posto_id
      WHERE pt.linha_id = $1
    `;
    const valuesManut = [linhaId];
    let idxM = 2;

    if (data_inicio) { queryManutencao += ` AND mr.data >= $${idxM}`; valuesManut.push(data_inicio); idxM++; }
    if (data_fim)    { queryManutencao += ` AND mr.data <= $${idxM}`; valuesManut.push(data_fim);    idxM++; }

    queryManutencao += " GROUP BY mr.turno ORDER BY mr.turno ASC";
    const manutencaoRes = await pool.query(queryManutencao, valuesManut);

    // ── CONSOLIDAR DADOS POR TURNO (1, 2 e 3) ──
    const TURNOS = [1, 2, 3];
    const totalPecas = oeeRes.rows.reduce(
      (acc, r) => acc + (parseInt(r.total_pecas_produzidas) || 0), 0
    );

    const dadosPorTurno = TURNOS.map(t => {
      const oee      = oeeRes.rows.find(r => parseInt(r.turno) === t);
      const defeitos = defeitosRes.rows.find(r => parseInt(r.turno) === t);
      const manut    = manutencaoRes.rows.find(r => parseInt(r.turno) === t);

      const registros          = parseInt(oee?.registros)              || 0;
      const oee_medio          = oee ? parseFloat(oee.oee_medio)       : null;
      const total_pecas        = parseInt(oee?.total_pecas_produzidas) || 0;
      const total_pecas_boas   = parseInt(oee?.total_pecas_boas)       || 0;
      const total_refugo       = parseInt(oee?.total_refugo)           || 0;

      const turnoObj = {
        turno:                    t,
        registros,
        oee_medio,
        disponibilidade_media:    oee ? parseFloat(oee.disponibilidade_media)   : null,
        performance_media:        oee ? parseFloat(oee.performance_media)       : null,
        qualidade_media:          oee ? parseFloat(oee.qualidade_media)         : null,
        total_pecas_produzidas:   total_pecas,
        total_pecas_boas,
        total_refugo,
        percentual_refugo:        total_pecas > 0
          ? parseFloat(((total_refugo / total_pecas) * 100).toFixed(2))
          : 0,
        tempo_operando_medio_min: oee ? parseFloat(oee.tempo_operando_medio_min) : null,
        defeitos: {
          ocorrencias:       parseInt(defeitos?.ocorrencias_defeitos)  || 0,
          total_defeitos:    parseInt(defeitos?.total_defeitos)        || 0,
          tipo_mais_frequente: defeitos?.tipo_mais_frequente           || null
        },
        manutencao: {
          ocorrencias_paradas: parseInt(manut?.ocorrencias_paradas)  || 0,
          total_parada_min:    parseFloat(manut?.total_parada_min)   || 0,
          media_parada_min:    parseFloat(manut?.media_parada_min)   || 0
        },
        alertas: []
      };

      // Gerar alertas automáticos
      turnoObj.alertas = gerarAlertas(turnoObj, totalPecas);

      return turnoObj;
    });

    // ── ANÁLISE COMPARATIVA ──
    const { turno_referencia, turno_problema } = identificarTurnosExtremos(dadosPorTurno);

    const oeeValidos = dadosPorTurno
      .filter(t => t.oee_medio !== null)
      .map(t => t.oee_medio);

    const deltaOEE = oeeValidos.length >= 2
      ? parseFloat((Math.max(...oeeValidos) - Math.min(...oeeValidos)).toFixed(2))
      : null;

    const classifVariacao = classificarVariacaoTurno(deltaOEE);

    // Ação recomendada
    let acaoRecomendada = "Turnos equilibrados. Manter padronização do método de trabalho.";
    if (turno_problema && classifVariacao.slug === 'red') {
      acaoRecomendada = `Turno ${turno_problema.turno} é significativamente inferior ao Turno ${turno_referencia?.turno}. ` +
        "Investigar: método de trabalho, operadores, condições do equipamento e entrega de turno.";
    } else if (turno_problema && classifVariacao.slug === 'yellow') {
      acaoRecomendada = `Turno ${turno_problema.turno} apresenta queda de performance. ` +
        "Verificar treinamento da equipe e padronização da operação.";
    }

    res.status(200).json({
      linha_id:   parseInt(linhaId),
      linha_nome: linha.nome,
      periodo_analisado: {
        data_inicio: data_inicio || "início dos registros",
        data_fim:    data_fim    || "último registro"
      },
      total_pecas_produzidas: totalPecas,
      analise_comparativa: {
        delta_oee_percentual:  deltaOEE,
        turno_referencia:      turno_referencia
          ? { turno: turno_referencia.turno, oee_medio: turno_referencia.oee_medio }
          : null,
        turno_problema:        turno_problema
          ? { turno: turno_problema.turno, oee_medio: turno_problema.oee_medio }
          : null,
        classificacao:         classifVariacao,
        acao_recomendada:      acaoRecomendada
      },
      dados_por_turno: dadosPorTurno,
      referencias: {
        variacao_atencao:        `Δ OEE > ${LIMIARES_TURNO.variacao_oee_atencao} pp entre turnos`,
        variacao_critica:        `Δ OEE > ${LIMIARES_TURNO.variacao_oee_critico} pp entre turnos`,
        oee_minimo_aceitavel:    `${LIMIARES_TURNO.oee_minimo_aceitavel}% por turno`,
        refugo_max_percentual:   `${LIMIARES_TURNO.refugo_max_percentual}% da produção`
      }
    });

  } catch (error) {
    console.error("❌ Erro na análise por turno da linha:", error.message);
    res.status(500).json({ erro: "Falha ao processar análise por turno." });
  }
});

// ----------------------------------------
// 2️⃣ COMPARATIVO POR TURNO — EMPRESA
// Visão macro: todos os turnos de todas as linhas da empresa
// Rota: GET /api/turnos/empresa/:empresaId
// Query params: data_inicio, data_fim (YYYY-MM-DD)
// ----------------------------------------
app.get("/api/turnos/empresa/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;
  const { data_inicio, data_fim } = req.query;

  try {
    // OEE por linha + turno
    let query = `
      SELECT
        l.id                                    AS linha_id,
        l.nome                                  AS linha_nome,
        po.turno,
        COUNT(*)                                AS registros,
        ROUND(AVG(po.oee)::NUMERIC, 2)          AS oee_medio,
        ROUND(AVG(po.disponibilidade)::NUMERIC, 2) AS disponibilidade_media,
        ROUND(AVG(po.performance)::NUMERIC, 2)  AS performance_media,
        ROUND(AVG(po.qualidade)::NUMERIC, 2)    AS qualidade_media,
        SUM(po.pecas_produzidas)                AS total_pecas,
        SUM(po.pecas_produzidas) - SUM(po.pecas_boas) AS total_refugo
      FROM producao_oee po
      JOIN linhas_producao l ON l.id = po.linha_id
      WHERE l.empresa_id = $1
    `;
    const values = [empresaId];
    let idx = 2;

    if (data_inicio) { query += ` AND po.data >= $${idx}`; values.push(data_inicio); idx++; }
    if (data_fim)    { query += ` AND po.data <= $${idx}`; values.push(data_fim);    idx++; }

    query += " GROUP BY l.id, l.nome, po.turno ORDER BY l.nome, po.turno ASC";
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({
        erro: "Nenhum dado de produção encontrado para esta empresa.",
        dica: "Registre produções em producao_oee com o campo turno preenchido."
      });
    }

    // Agrupar por linha
    const linhasMap = {};
    result.rows.forEach(row => {
      if (!linhasMap[row.linha_id]) {
        linhasMap[row.linha_id] = {
          linha_id:   row.linha_id,
          linha_nome: row.linha_nome,
          turnos:     []
        };
      }
      linhasMap[row.linha_id].turnos.push({
        turno:                parseInt(row.turno),
        registros:            parseInt(row.registros),
        oee_medio:            parseFloat(row.oee_medio),
        disponibilidade_media: parseFloat(row.disponibilidade_media),
        performance_media:    parseFloat(row.performance_media),
        qualidade_media:      parseFloat(row.qualidade_media),
        total_pecas:          parseInt(row.total_pecas)  || 0,
        total_refugo:         parseInt(row.total_refugo) || 0
      });
    });

    // Para cada linha calcular delta e identificar turno problema
    const analisesPorLinha = Object.values(linhasMap).map(linha => {
      const { turno_referencia, turno_problema } = identificarTurnosExtremos(
        linha.turnos.map(t => ({ ...t, oee_medio: t.oee_medio }))
      );

      const oeeValidos = linha.turnos.map(t => t.oee_medio).filter(v => v !== null);
      const deltaOEE   = oeeValidos.length >= 2
        ? parseFloat((Math.max(...oeeValidos) - Math.min(...oeeValidos)).toFixed(2))
        : null;

      const classif = classificarVariacaoTurno(deltaOEE);

      return {
        ...linha,
        delta_oee:         deltaOEE,
        turno_referencia:  turno_referencia
          ? { turno: turno_referencia.turno, oee_medio: turno_referencia.oee_medio }
          : null,
        turno_problema:    turno_problema
          ? { turno: turno_problema.turno, oee_medio: turno_problema.oee_medio }
          : null,
        classificacao:     classif
      };
    });

    // Resumo geral da empresa
    const linhasCriticas  = analisesPorLinha.filter(l => l.classificacao.slug === 'red');
    const linhasAtencao   = analisesPorLinha.filter(l => l.classificacao.slug === 'yellow');
    const linhasEstaveis  = analisesPorLinha.filter(l => l.classificacao.slug === 'green');
    const statusGeral     = linhasCriticas.length > 0  ? 'red'    :
                            linhasAtencao.length  > 0  ? 'yellow' :
                            linhasEstaveis.length > 0  ? 'green'  : 'gray';

    res.status(200).json({
      empresa_id: parseInt(empresaId),
      periodo_analisado: {
        data_inicio: data_inicio || "início dos registros",
        data_fim:    data_fim    || "último registro"
      },
      resumo: {
        total_linhas_analisadas: analisesPorLinha.length,
        linhas_criticas:  linhasCriticas.length,
        linhas_atencao:   linhasAtencao.length,
        linhas_estaveis:  linhasEstaveis.length,
        status_geral:     statusGeral
      },
      linhas_criticas,
      analise_por_linha: analisesPorLinha,
      referencias: {
        variacao_atencao: `Δ OEE > ${LIMIARES_TURNO.variacao_oee_atencao} pp entre turnos`,
        variacao_critica: `Δ OEE > ${LIMIARES_TURNO.variacao_oee_critico} pp entre turnos`
      }
    });

  } catch (error) {
    console.error("❌ Erro na análise por turno da empresa:", error.message);
    res.status(500).json({ erro: "Falha ao processar análise por turno da empresa." });
  }
});

// ----------------------------------------
// 3️⃣ SÉRIE HISTÓRICA DE UM TURNO ESPECÍFICO
// Evolução de OEE de um turno ao longo do tempo em uma linha
// Rota: GET /api/turnos/historico/:linhaId/:turno
// Query params: data_inicio, data_fim (YYYY-MM-DD)
// ----------------------------------------
app.get("/api/turnos/historico/:linhaId/:turno", autenticarToken, async (req, res) => {
  const { linhaId, turno } = req.params;
  const { data_inicio, data_fim } = req.query;

  const turnoNum = parseInt(turno);
  if (![1, 2, 3].includes(turnoNum)) {
    return res.status(400).json({ erro: "Turno inválido. Use 1, 2 ou 3." });
  }

  try {
    let query = `
      SELECT
        data,
        oee,
        disponibilidade,
        performance,
        qualidade,
        pecas_produzidas,
        pecas_boas,
        pecas_produzidas - pecas_boas AS refugo
      FROM producao_oee
      WHERE linha_id = $1 AND turno = $2
    `;
    const values = [linhaId, turnoNum];
    let idx = 3;

    if (data_inicio) { query += ` AND data >= $${idx}`; values.push(data_inicio); idx++; }
    if (data_fim)    { query += ` AND data <= $${idx}`; values.push(data_fim);    idx++; }

    query += " ORDER BY data ASC";
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({
        erro: `Sem registros para o Turno ${turnoNum} nesta linha no período informado.`
      });
    }

    // Calcular tendência (média móvel de 7 pontos)
    const serie = result.rows.map((row, i, arr) => {
      const janela = arr.slice(Math.max(0, i - 3), i + 4);
      const mediaMovel = janela.reduce((a, b) => a + parseFloat(b.oee), 0) / janela.length;
      return {
        data:              row.data,
        oee:               parseFloat(row.oee),
        disponibilidade:   parseFloat(row.disponibilidade),
        performance:       parseFloat(row.performance),
        qualidade:         parseFloat(row.qualidade),
        pecas_produzidas:  parseInt(row.pecas_produzidas) || 0,
        pecas_boas:        parseInt(row.pecas_boas)       || 0,
        refugo:            parseInt(row.refugo)           || 0,
        media_movel_oee:   parseFloat(mediaMovel.toFixed(2))
      };
    });

    // Estatísticas do período
    const oeeValores = serie.map(s => s.oee);
    const oeeMedia   = oeeValores.reduce((a, b) => a + b, 0) / oeeValores.length;
    const oeeMin     = Math.min(...oeeValores);
    const oeeMax     = Math.max(...oeeValores);

    // Tendência: compara primeira metade com segunda metade
    const metade     = Math.floor(serie.length / 2);
    const mediaAntes = serie.slice(0, metade).reduce((a, b) => a + b.oee, 0) / metade;
    const mediaDepois = serie.slice(metade).reduce((a, b) => a + b.oee, 0) / (serie.length - metade);
    const tendencia   = mediaDepois > mediaAntes + 2  ? 'melhora'   :
                        mediaDepois < mediaAntes - 2  ? 'piora'     : 'estavel';

    res.status(200).json({
      linha_id:  parseInt(linhaId),
      turno:     turnoNum,
      periodo_analisado: {
        data_inicio: data_inicio || serie[0].data,
        data_fim:    data_fim    || serie[serie.length - 1].data
      },
      estatisticas_periodo: {
        total_registros: serie.length,
        oee_medio:       parseFloat(oeeMedia.toFixed(2)),
        oee_minimo:      oeeMin,
        oee_maximo:      oeeMax,
        tendencia,
        descricao_tendencia:
          tendencia === 'melhora'  ? "OEE em melhora ao longo do período." :
          tendencia === 'piora'    ? "OEE em queda ao longo do período. Investigar causas." :
                                    "OEE estável ao longo do período."
      },
      serie_historica: serie
    });

  } catch (error) {
    console.error("❌ Erro no histórico por turno:", error.message);
    res.status(500).json({ erro: "Falha ao buscar histórico do turno." });
  }
});

// ========================================
// 🔍 MÓDULO: ANÁLISE DE CAUSA RAIZ
// 5 Porquês + Diagrama de Ishikawa (6M)
// ========================================

/**
 * ⚠️ SQL NECESSÁRIO ANTES DE USAR ESTE MÓDULO
 * Execute no seu banco Neon antes de subir o backend:
 *
 * -- Tabela principal: registro do problema
 * CREATE TABLE IF NOT EXISTS causas_raiz (
 *   id                SERIAL PRIMARY KEY,
 *   empresa_id        INTEGER NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
 *   linha_id          INTEGER REFERENCES linhas_producao(id) ON DELETE SET NULL,
 *   posto_id          INTEGER REFERENCES posto_trabalho(id) ON DELETE SET NULL,
 *   titulo            VARCHAR(200) NOT NULL,
 *   descricao_problema TEXT NOT NULL,
 *   categoria_ishikawa VARCHAR(20) CHECK (categoria_ishikawa IN (
 *     'mao_de_obra','maquina','metodo','material','meio_ambiente','medicao'
 *   )),
 *   causa_raiz_final  TEXT,
 *   acao_corretiva    TEXT,
 *   responsavel       VARCHAR(100),
 *   prazo             DATE,
 *   status            VARCHAR(20) DEFAULT 'aberto'
 *                     CHECK (status IN ('aberto','em_andamento','concluido','cancelado')),
 *   eficacia_verificada BOOLEAN DEFAULT FALSE,
 *   criado_por        INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
 *   criado_em         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 *   atualizado_em     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
 * );
 *
 * -- Tabela dos porquês (cadeia encadeada)
 * CREATE TABLE IF NOT EXISTS cinco_porques (
 *   id             SERIAL PRIMARY KEY,
 *   causa_raiz_id  INTEGER NOT NULL REFERENCES causas_raiz(id) ON DELETE CASCADE,
 *   numero         INTEGER NOT NULL CHECK (numero BETWEEN 1 AND 5),
 *   pergunta       TEXT NOT NULL,
 *   resposta       TEXT,
 *   criado_em      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 *   UNIQUE (causa_raiz_id, numero)
 * );
 *
 * -- Tabela das categorias do Ishikawa (6M)
 * CREATE TABLE IF NOT EXISTS ishikawa_causas (
 *   id             SERIAL PRIMARY KEY,
 *   causa_raiz_id  INTEGER NOT NULL REFERENCES causas_raiz(id) ON DELETE CASCADE,
 *   categoria      VARCHAR(20) NOT NULL CHECK (categoria IN (
 *     'mao_de_obra','maquina','metodo','material','meio_ambiente','medicao'
 *   )),
 *   causa          TEXT NOT NULL,
 *   subcausa       TEXT,
 *   criado_em      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
 * );
 *
 * -- Índices de performance
 * CREATE INDEX IF NOT EXISTS idx_causas_raiz_empresa ON causas_raiz(empresa_id);
 * CREATE INDEX IF NOT EXISTS idx_causas_raiz_linha   ON causas_raiz(linha_id);
 * CREATE INDEX IF NOT EXISTS idx_cinco_porques_cr    ON cinco_porques(causa_raiz_id);
 * CREATE INDEX IF NOT EXISTS idx_ishikawa_cr         ON ishikawa_causas(causa_raiz_id);
 */

/**
 * MAPEAMENTO DOS 6M DO ISHIKAWA
 * Usado para validação e para o frontend gerar o diagrama
 */
const CATEGORIAS_6M = {
  mao_de_obra:    { label: 'Mão de Obra',    descricao: 'Problemas relacionados a pessoas, treinamento, habilidade ou fadiga' },
  maquina:        { label: 'Máquina',        descricao: 'Falhas, desgastes, setup ou manutenção inadequada de equipamentos' },
  metodo:         { label: 'Método',         descricao: 'Procedimentos incorretos, ausência de POP ou método inconsistente' },
  material:       { label: 'Material',       descricao: 'Matéria-prima fora de especificação ou armazenamento incorreto' },
  meio_ambiente:  { label: 'Meio Ambiente',  descricao: 'Temperatura, umidade, vibração, ruído ou limpeza do ambiente' },
  medicao:        { label: 'Medição',        descricao: 'Instrumentos descalibrados, método de medição incorreto ou erro do operador' }
};

const STATUS_VALIDOS = ['aberto', 'em_andamento', 'concluido', 'cancelado'];

// ----------------------------------------
// 1️⃣ CRIAR ANÁLISE DE CAUSA RAIZ
// Abre um novo registro de problema para investigação
// Rota: POST /api/causa-raiz
// ----------------------------------------
app.post("/api/causa-raiz", autenticarToken, async (req, res) => {
  const {
    empresa_id,
    linha_id,
    posto_id,
    titulo,
    descricao_problema,
    categoria_ishikawa,
    responsavel,
    prazo
  } = req.body;

  if (!empresa_id || !titulo || !descricao_problema) {
    return res.status(400).json({
      erro: "Campos obrigatórios: empresa_id, titulo, descricao_problema."
    });
  }

  if (categoria_ishikawa && !Object.keys(CATEGORIAS_6M).includes(categoria_ishikawa)) {
    return res.status(400).json({
      erro: `Categoria inválida. Use: ${Object.keys(CATEGORIAS_6M).join(', ')}`
    });
  }

  try {
    const result = await pool.query(`
      INSERT INTO causas_raiz
        (empresa_id, linha_id, posto_id, titulo, descricao_problema,
         categoria_ishikawa, responsavel, prazo, status, criado_por)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'aberto',$9)
      RETURNING *
    `, [
      empresa_id,
      linha_id    || null,
      posto_id    || null,
      titulo.trim(),
      descricao_problema.trim(),
      categoria_ishikawa || null,
      responsavel || null,
      prazo       || null,
      req.usuario.id
    ]);

    const registro = result.rows[0];

    // Criar automaticamente os 5 slots de porquês
    const porques = [];
    for (let i = 1; i <= 5; i++) {
      const pq = await pool.query(`
        INSERT INTO cinco_porques (causa_raiz_id, numero, pergunta)
        VALUES ($1, $2, $3)
        RETURNING *
      `, [
        registro.id,
        i,
        i === 1
          ? `Por que "${titulo}" aconteceu?`
          : `Por que (resposta ${i - 1}) ocorreu?`
      ]);
      porques.push(pq.rows[0]);
    }

    console.log(`🔍 Análise de causa raiz criada: "${titulo}" (ID: ${registro.id})`);

    res.status(201).json({
      mensagem: "Análise de causa raiz iniciada. Os 5 Porquês foram criados automaticamente.",
      causa_raiz: registro,
      cinco_porques: porques,
      proximos_passos: [
        "1. Preencha as respostas dos 5 Porquês via PUT /api/causa-raiz/:id/porques/:numero",
        "2. Adicione causas ao Ishikawa via POST /api/causa-raiz/:id/ishikawa",
        "3. Registre a causa raiz final e ação corretiva via PUT /api/causa-raiz/:id"
      ]
    });

  } catch (error) {
    console.error("❌ Erro ao criar causa raiz:", error.message);
    res.status(500).json({ erro: "Falha ao criar análise de causa raiz." });
  }
});

// ----------------------------------------
// 2️⃣ LISTAR ANÁLISES DE CAUSA RAIZ
// Rota: GET /api/causa-raiz
// Query params: empresa_id (obrigatório), status, linha_id
// ----------------------------------------
app.get("/api/causa-raiz", autenticarToken, async (req, res) => {
  const { empresa_id, status, linha_id } = req.query;

  if (!empresa_id) {
    return res.status(400).json({ erro: "O parâmetro empresa_id é obrigatório." });
  }

  try {
    let query = `
      SELECT
        cr.*,
        l.nome  AS linha_nome,
        pt.nome AS posto_nome,
        u.nome  AS criado_por_nome,
        (SELECT COUNT(*) FROM cinco_porques cp
         WHERE cp.causa_raiz_id = cr.id AND cp.resposta IS NOT NULL) AS porques_respondidos,
        (SELECT COUNT(*) FROM ishikawa_causas ic
         WHERE ic.causa_raiz_id = cr.id) AS causas_ishikawa
      FROM causas_raiz cr
      LEFT JOIN linhas_producao  l  ON l.id  = cr.linha_id
      LEFT JOIN posto_trabalho   pt ON pt.id = cr.posto_id
      LEFT JOIN usuarios         u  ON u.id  = cr.criado_por
      WHERE cr.empresa_id = $1
    `;
    const values = [empresa_id];
    let idx = 2;

    if (status)   { query += ` AND cr.status = $${idx}`;   values.push(status);   idx++; }
    if (linha_id) { query += ` AND cr.linha_id = $${idx}`; values.push(linha_id); idx++; }

    query += " ORDER BY cr.criado_em DESC";
    const result = await pool.query(query, values);

    // Agrupar por status para facilitar kanban no frontend
    const agrupado = {
      aberto:       result.rows.filter(r => r.status === 'aberto'),
      em_andamento: result.rows.filter(r => r.status === 'em_andamento'),
      concluido:    result.rows.filter(r => r.status === 'concluido'),
      cancelado:    result.rows.filter(r => r.status === 'cancelado')
    };

    res.status(200).json({
      total: result.rows.length,
      agrupado_por_status: agrupado,
      lista: result.rows
    });

  } catch (error) {
    console.error("❌ Erro ao listar causas raiz:", error.message);
    res.status(500).json({ erro: "Falha ao listar análises de causa raiz." });
  }
});

// ----------------------------------------
// 3️⃣ BUSCAR ANÁLISE COMPLETA (COM PORQUÊS E ISHIKAWA)
// Rota: GET /api/causa-raiz/:id
// ----------------------------------------
app.get("/api/causa-raiz/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Buscar registro principal
    const crRes = await pool.query(`
      SELECT
        cr.*,
        l.nome  AS linha_nome,
        pt.nome AS posto_nome,
        u.nome  AS criado_por_nome
      FROM causas_raiz cr
      LEFT JOIN linhas_producao  l  ON l.id  = cr.linha_id
      LEFT JOIN posto_trabalho   pt ON pt.id = cr.posto_id
      LEFT JOIN usuarios         u  ON u.id  = cr.criado_por
      WHERE cr.id = $1
    `, [id]);

    if (crRes.rows.length === 0) {
      return res.status(404).json({ erro: "Análise de causa raiz não encontrada." });
    }

    const cr = crRes.rows[0];

    // Buscar os 5 porquês
    const porquesRes = await pool.query(
      "SELECT * FROM cinco_porques WHERE causa_raiz_id = $1 ORDER BY numero ASC",
      [id]
    );

    // Buscar causas do Ishikawa agrupadas por categoria
    const ishikawaRes = await pool.query(
      "SELECT * FROM ishikawa_causas WHERE causa_raiz_id = $1 ORDER BY categoria, id ASC",
      [id]
    );

    // Montar diagrama Ishikawa por categoria
    const ishikawaPorCategoria = Object.keys(CATEGORIAS_6M).reduce((acc, cat) => {
      acc[cat] = {
        ...CATEGORIAS_6M[cat],
        causas: ishikawaRes.rows
          .filter(r => r.categoria === cat)
          .map(r => ({ id: r.id, causa: r.causa, subcausa: r.subcausa }))
      };
      return acc;
    }, {});

    // Calcular progresso da análise
    const porquesRespondidos = porquesRes.rows.filter(p => p.resposta).length;
    const temCausaRaizFinal  = !!cr.causa_raiz_final;
    const temAcaoCorretiva   = !!cr.acao_corretiva;
    const totalCausasIshikawa = ishikawaRes.rows.length;

    const progresso = {
      porques_respondidos:    porquesRespondidos,
      porques_total:          5,
      tem_causa_raiz_final:   temCausaRaizFinal,
      tem_acao_corretiva:     temAcaoCorretiva,
      total_causas_ishikawa:  totalCausasIshikawa,
      percentual_completo: Math.round(
        ((porquesRespondidos / 5) * 40 +
        (temCausaRaizFinal  ? 30 : 0) +
        (temAcaoCorretiva   ? 30 : 0))
      )
    };

    res.status(200).json({
      causa_raiz:            cr,
      cinco_porques:         porquesRes.rows,
      ishikawa_por_categoria: ishikawaPorCategoria,
      ishikawa_lista:        ishikawaRes.rows,
      progresso,
      categorias_disponiveis: CATEGORIAS_6M
    });

  } catch (error) {
    console.error("❌ Erro ao buscar causa raiz:", error.message);
    res.status(500).json({ erro: "Falha ao buscar análise de causa raiz." });
  }
});

// ----------------------------------------
// 4️⃣ ATUALIZAR ANÁLISE (causa raiz final, ação, status)
// Rota: PUT /api/causa-raiz/:id
// ----------------------------------------
app.put("/api/causa-raiz/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const {
    titulo,
    descricao_problema,
    categoria_ishikawa,
    causa_raiz_final,
    acao_corretiva,
    responsavel,
    prazo,
    status,
    eficacia_verificada
  } = req.body;

  if (status && !STATUS_VALIDOS.includes(status)) {
    return res.status(400).json({
      erro: `Status inválido. Use: ${STATUS_VALIDOS.join(', ')}`
    });
  }

  if (categoria_ishikawa && !Object.keys(CATEGORIAS_6M).includes(categoria_ishikawa)) {
    return res.status(400).json({
      erro: `Categoria inválida. Use: ${Object.keys(CATEGORIAS_6M).join(', ')}`
    });
  }

  try {
    const result = await pool.query(`
      UPDATE causas_raiz SET
        titulo              = COALESCE($1,  titulo),
        descricao_problema  = COALESCE($2,  descricao_problema),
        categoria_ishikawa  = COALESCE($3,  categoria_ishikawa),
        causa_raiz_final    = COALESCE($4,  causa_raiz_final),
        acao_corretiva      = COALESCE($5,  acao_corretiva),
        responsavel         = COALESCE($6,  responsavel),
        prazo               = COALESCE($7,  prazo),
        status              = COALESCE($8,  status),
        eficacia_verificada = COALESCE($9,  eficacia_verificada),
        atualizado_em       = CURRENT_TIMESTAMP
      WHERE id = $10
      RETURNING *
    `, [
      titulo?.trim(),
      descricao_problema?.trim(),
      categoria_ishikawa,
      causa_raiz_final?.trim(),
      acao_corretiva?.trim(),
      responsavel,
      prazo || null,
      status,
      eficacia_verificada !== undefined ? eficacia_verificada : null,
      id
    ]);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Análise não encontrada." });
    }

    res.status(200).json({
      mensagem: "Análise atualizada com sucesso.",
      causa_raiz: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro ao atualizar causa raiz:", error.message);
    res.status(500).json({ erro: "Falha ao atualizar análise de causa raiz." });
  }
});

// ----------------------------------------
// 5️⃣ RESPONDER UM PORQUÊ ESPECÍFICO
// Rota: PUT /api/causa-raiz/:id/porques/:numero
// Body: { resposta: "..." }
// ----------------------------------------
app.put("/api/causa-raiz/:id/porques/:numero", autenticarToken, async (req, res) => {
  const { id, numero } = req.params;
  const { resposta, pergunta } = req.body;
  const num = parseInt(numero);

  if (![1, 2, 3, 4, 5].includes(num)) {
    return res.status(400).json({ erro: "Número do porquê deve ser entre 1 e 5." });
  }

  if (!resposta || !resposta.trim()) {
    return res.status(400).json({ erro: "A resposta não pode estar vazia." });
  }

  try {
    // Verificar se a análise existe
    const crCheck = await pool.query(
      "SELECT id, titulo FROM causas_raiz WHERE id = $1", [id]
    );
    if (crCheck.rows.length === 0) {
      return res.status(404).json({ erro: "Análise de causa raiz não encontrada." });
    }

    // Atualizar o porquê
    const result = await pool.query(`
      UPDATE cinco_porques
      SET
        resposta  = $1,
        pergunta  = COALESCE($2, pergunta)
      WHERE causa_raiz_id = $3 AND numero = $4
      RETURNING *
    `, [resposta.trim(), pergunta?.trim() || null, id, num]);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: `Porquê número ${num} não encontrado.` });
    }

    // Atualizar pergunta do próximo porquê automaticamente (se existir)
    if (num < 5) {
      await pool.query(`
        UPDATE cinco_porques
        SET pergunta = $1
        WHERE causa_raiz_id = $2 AND numero = $3 AND resposta IS NULL
      `, [`Por que "${resposta.trim()}" ocorreu?`, id, num + 1]);
    }

    // Checar se todos os 5 foram respondidos para sugerir status
    const totalRespondidos = await pool.query(
      "SELECT COUNT(*) FROM cinco_porques WHERE causa_raiz_id = $1 AND resposta IS NOT NULL",
      [id]
    );
    const qtd = parseInt(totalRespondidos.rows[0].count);

    res.status(200).json({
      mensagem: `Porquê ${num} salvo com sucesso.`,
      porque:   result.rows[0],
      progresso: {
        respondidos: qtd,
        total: 5,
        completo: qtd === 5
      },
      dica: qtd === 5
        ? "Todos os 5 Porquês foram respondidos. Registre agora a causa raiz final via PUT /api/causa-raiz/:id"
        : `Faltam ${5 - qtd} porquê(s) para completar a análise.`
    });

  } catch (error) {
    console.error("❌ Erro ao responder porquê:", error.message);
    res.status(500).json({ erro: "Falha ao salvar resposta do porquê." });
  }
});

// ----------------------------------------
// 6️⃣ ADICIONAR CAUSA AO DIAGRAMA ISHIKAWA
// Rota: POST /api/causa-raiz/:id/ishikawa
// Body: { categoria, causa, subcausa }
// ----------------------------------------
app.post("/api/causa-raiz/:id/ishikawa", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { categoria, causa, subcausa } = req.body;

  if (!categoria || !causa) {
    return res.status(400).json({
      erro: "Categoria e causa são obrigatórios.",
      categorias_validas: Object.keys(CATEGORIAS_6M)
    });
  }

  if (!Object.keys(CATEGORIAS_6M).includes(categoria)) {
    return res.status(400).json({
      erro: `Categoria inválida. Use: ${Object.keys(CATEGORIAS_6M).join(', ')}`
    });
  }

  try {
    // Verificar se a análise existe
    const crCheck = await pool.query(
      "SELECT id FROM causas_raiz WHERE id = $1", [id]
    );
    if (crCheck.rows.length === 0) {
      return res.status(404).json({ erro: "Análise de causa raiz não encontrada." });
    }

    const result = await pool.query(`
      INSERT INTO ishikawa_causas (causa_raiz_id, categoria, causa, subcausa)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `, [id, categoria, causa.trim(), subcausa?.trim() || null]);

    const catInfo = CATEGORIAS_6M[categoria];

    res.status(201).json({
      mensagem: `Causa adicionada à categoria "${catInfo.label}" do Ishikawa.`,
      ishikawa: result.rows[0],
      categoria_info: catInfo
    });

  } catch (error) {
    console.error("❌ Erro ao adicionar causa ao Ishikawa:", error.message);
    res.status(500).json({ erro: "Falha ao registrar causa no diagrama Ishikawa." });
  }
});

// ----------------------------------------
// 7️⃣ REMOVER CAUSA DO ISHIKAWA
// Rota: DELETE /api/causa-raiz/:id/ishikawa/:ishikawaId
// ----------------------------------------
app.delete("/api/causa-raiz/:id/ishikawa/:ishikawaId", autenticarToken, async (req, res) => {
  const { id, ishikawaId } = req.params;

  try {
    const result = await pool.query(
      "DELETE FROM ishikawa_causas WHERE id = $1 AND causa_raiz_id = $2 RETURNING *",
      [ishikawaId, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Causa não encontrada no Ishikawa." });
    }

    res.status(200).json({
      mensagem: "Causa removida do diagrama Ishikawa.",
      removido: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro ao remover causa do Ishikawa:", error.message);
    res.status(500).json({ erro: "Falha ao remover causa do Ishikawa." });
  }
});

// ----------------------------------------
// 8️⃣ EXCLUIR ANÁLISE COMPLETA
// Rota: DELETE /api/causa-raiz/:id
// ----------------------------------------
app.delete("/api/causa-raiz/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;

  try {
    // O CASCADE no banco remove porquês e ishikawa automaticamente
    const result = await pool.query(
      "DELETE FROM causas_raiz WHERE id = $1 RETURNING titulo",
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Análise não encontrada." });
    }

    res.status(200).json({
      mensagem: `Análise "${result.rows[0].titulo}" removida com sucesso.`
    });

  } catch (error) {
    console.error("❌ Erro ao excluir causa raiz:", error.message);
    res.status(500).json({ erro: "Falha ao excluir análise de causa raiz." });
  }
});

// ----------------------------------------
// 9️⃣ DASHBOARD DE CAUSA RAIZ POR EMPRESA
// Métricas gerais para o painel do consultor
// Rota: GET /api/causa-raiz/dashboard/:empresaId
// ----------------------------------------
app.get("/api/causa-raiz/dashboard/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;

  try {
    // Contagem por status
    const statusRes = await pool.query(`
      SELECT
        COUNT(*)                                           AS total,
        COUNT(*) FILTER (WHERE status = 'aberto')         AS abertos,
        COUNT(*) FILTER (WHERE status = 'em_andamento')   AS em_andamento,
        COUNT(*) FILTER (WHERE status = 'concluido')      AS concluidos,
        COUNT(*) FILTER (WHERE status = 'cancelado')      AS cancelados,
        COUNT(*) FILTER (WHERE eficacia_verificada = true) AS eficacia_confirmada,
        COUNT(*) FILTER (WHERE prazo < CURRENT_DATE
                          AND status NOT IN ('concluido','cancelado')) AS atrasados
      FROM causas_raiz
      WHERE empresa_id = $1
    `, [empresaId]);

    // Categoria mais recorrente no Ishikawa
    const catRes = await pool.query(`
      SELECT ic.categoria, COUNT(*) AS total
      FROM ishikawa_causas ic
      JOIN causas_raiz cr ON cr.id = ic.causa_raiz_id
      WHERE cr.empresa_id = $1
      GROUP BY ic.categoria
      ORDER BY total DESC
      LIMIT 1
    `, [empresaId]);

    // Análises atrasadas (com detalhe)
    const atrasadasRes = await pool.query(`
      SELECT
        cr.id, cr.titulo, cr.prazo, cr.status, cr.responsavel,
        l.nome AS linha_nome
      FROM causas_raiz cr
      LEFT JOIN linhas_producao l ON l.id = cr.linha_id
      WHERE cr.empresa_id = $1
        AND cr.prazo < CURRENT_DATE
        AND cr.status NOT IN ('concluido', 'cancelado')
      ORDER BY cr.prazo ASC
    `, [empresaId]);

    // Últimas análises abertas
    const recentesRes = await pool.query(`
      SELECT
        cr.id, cr.titulo, cr.status, cr.criado_em,
        cr.categoria_ishikawa, l.nome AS linha_nome,
        (SELECT COUNT(*) FROM cinco_porques cp
         WHERE cp.causa_raiz_id = cr.id AND cp.resposta IS NOT NULL) AS porques_respondidos
      FROM causas_raiz cr
      LEFT JOIN linhas_producao l ON l.id = cr.linha_id
      WHERE cr.empresa_id = $1
        AND cr.status IN ('aberto','em_andamento')
      ORDER BY cr.criado_em DESC
      LIMIT 5
    `, [empresaId]);

    const stats       = statusRes.rows[0];
    const catMaisFreq = catRes.rows[0];

    res.status(200).json({
      empresa_id: parseInt(empresaId),
      resumo: {
        total:               parseInt(stats.total),
        abertos:             parseInt(stats.abertos),
        em_andamento:        parseInt(stats.em_andamento),
        concluidos:          parseInt(stats.concluidos),
        cancelados:          parseInt(stats.cancelados),
        eficacia_confirmada: parseInt(stats.eficacia_confirmada),
        atrasados:           parseInt(stats.atrasados),
        taxa_conclusao:      parseInt(stats.total) > 0
          ? parseFloat(((parseInt(stats.concluidos) / parseInt(stats.total)) * 100).toFixed(1))
          : 0
      },
      categoria_mais_recorrente: catMaisFreq
        ? {
            categoria: catMaisFreq.categoria,
            label:     CATEGORIAS_6M[catMaisFreq.categoria]?.label,
            total:     parseInt(catMaisFreq.total)
          }
        : null,
      analises_atrasadas:  atrasadasRes.rows,
      analises_em_aberto:  recentesRes.rows,
      categorias_6m:       CATEGORIAS_6M
    });

  } catch (error) {
    console.error("❌ Erro no dashboard de causa raiz:", error.message);
    res.status(500).json({ erro: "Falha ao gerar dashboard de causa raiz." });
  }
});

// ========================================
// 👥 RH - TREINAMENTO E HABILIDADES
// ========================================

/**
 * ROTA: REGISTRAR TREINAMENTO
 */
app.post("/api/rh/treinamentos", autenticarToken, async (req, res) => {
  const { colaborador_id, nome_curso, carga_horaria, data_realizacao, certificado, observacao } = req.body;

  if (!colaborador_id || !nome_curso) {
    return res.status(400).json({ erro: "Colaborador e nome do curso são obrigatórios." });
  }

  try {
    const query = `
      INSERT INTO treinamentos_colaborador 
      (colaborador_id, nome_curso, carga_horaria, data_realizacao, certificado, observacao)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `;

    const values = [colaborador_id, nome_curso, carga_horaria || null, data_realizacao || CURRENT_DATE, certificado || null, observacao || null];
    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro POST /rh/treinamentos:", error.message);
    res.status(500).json({ erro: "Erro ao registrar treinamento" });
  }
});

/**
 * ROTA: LISTAR TREINAMENTOS POR COLABORADOR
 */
app.get("/api/rh/treinamentos/colaborador/:colaboradorId", autenticarToken, async (req, res) => {
  const { colaboradorId } = req.params;

  try {
    const query = `
      SELECT * FROM treinamentos_colaborador 
      WHERE colaborador_id = $1 
      ORDER BY data_realizacao DESC;
    `;
    const result = await pool.query(query, [colaboradorId]);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("❌ Erro GET /rh/treinamentos/colaborador:", error.message);
    res.status(500).json({ erro: "Erro ao listar treinamentos" });
  }
});

/**
 * ROTA: REGISTRAR HABILIDADE
 */
app.post("/api/rh/habilidades", autenticarToken, async (req, res) => {
  const { colaborador_id, habilidade, nivel } = req.body;

  if (!colaborador_id || !habilidade) {
    return res.status(400).json({ erro: "Colaborador e habilidade são obrigatórios." });
  }

  try {
    const query = `
      INSERT INTO habilidades_colaborador 
      (colaborador_id, habilidade, nivel)
      VALUES ($1, $2, $3)
      ON CONFLICT (colaborador_id, habilidade) 
      DO UPDATE SET nivel = EXCLUDED.nivel
      RETURNING *;
    `;

    const values = [colaborador_id, habilidade, nivel || 3];
    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro POST /rh/habilidades:", error.message);
    res.status(500).json({ erro: "Erro ao registrar habilidade" });
  }
});

/**
 * ROTA: LISTAR HABILIDADES POR COLABORADOR
 */
app.get("/api/rh/habilidades/colaborador/:colaboradorId", autenticarToken, async (req, res) => {
  const { colaboradorId } = req.params;

  try {
    const query = `
      SELECT * FROM habilidades_colaborador 
      WHERE colaborador_id = $1 
      ORDER BY nivel DESC, habilidade ASC;
    `;
    const result = await pool.query(query, [colaboradorId]);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("❌ Erro GET /rh/habilidades/colaborador:", error.message);
    res.status(500).json({ erro: "Erro ao listar habilidades" });
  }
});

// ========================================
// 📊 BUSCAR VALORES DA FASE 1 POR EMPRESA
// ========================================
app.get("/api/projeto/valores/:empresaId", autenticarToken, async (req, res) => {
  try {
    const { empresaId } = req.params;

    const query = `
      SELECT 
        valor_total_projeto,
        valor_fase1_diagnostico,
        data_assinatura,
        status
      FROM contratos_fase1
      WHERE empresa_id = $1
      ORDER BY data_assinatura DESC
      LIMIT 1
    `;

    const result = await pool.query(query, [empresaId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ 
        erro: "Nenhum contrato da Fase 1 encontrado para esta empresa" 
      });
    }

    const contrato = result.rows[0];
    const valorTotalProjeto = parseFloat(contrato.valor_total_projeto);
    const valorFase1 = parseFloat(contrato.valor_fase1_diagnostico);
    const saldoFase2e3 = valorTotalProjeto - valorFase1;
    
    const valorImplementacao = Math.round(valorTotalProjeto * 0.50);
    const valorAcompanhamentoTotal = Math.round(valorTotalProjeto * 0.25);
    const MESES_ACOMPANHAMENTO = 3;
    const valorAcompanhamentoMensal = Math.round(valorAcompanhamentoTotal / MESES_ACOMPANHAMENTO);

    res.json({
      sucesso: true,
      dados: {
        empresa_id: parseInt(empresaId),
        valor_total_projeto: valorTotalProjeto,
        valor_fase1: valorFase1,
        saldo_fase2e3: saldoFase2e3,
        valor_implementacao: valorImplementacao,
        valor_acompanhamento_mensal: valorAcompanhamentoMensal,
        data_contrato_fase1: contrato.data_assinatura,
        status_fase1: contrato.status
      }
    });

  } catch (error) {
    console.error("❌ Erro ao buscar valores da Fase 1:", error.message);
    res.status(500).json({ 
      erro: "Falha ao buscar valores do projeto",
      detalhe: error.message 
    });
  }
});

// ========================================
// 📄 CONTRATO PRÉ-DIAGNÓSTICO (FASE 1)
// ========================================

app.post("/api/ia/gerar-contrato-pre-diagnostico", autenticarToken, async (req, res) => {
  try {
    const dados = req.body;

    if (!dados.empresa || !dados.empresa.nome) {
      return res.status(400).json({ erro: "Dados da empresa são obrigatórios" });
    }

    if (!dados.valor_negociado || dados.valor_negociado <= 0) {
      return res.status(400).json({ erro: "Valor negociado é obrigatório" });
    }

    const empresa = {
      nome: dados.empresa.nome || "[NOME DA EMPRESA]",
      cnpj: dados.empresa.cnpj || "[CNPJ]",
      endereco: dados.empresa.endereco || "[ENDEREÇO COMPLETO]",
      cidade: dados.empresa.cidade || "[CIDADE]",
      estado: dados.empresa.estado || "[UF]"
    };

    const representante = {
      nome: dados.representante?.nome || "[NOME DO REPRESENTANTE]",
      cargo: dados.representante?.cargo || "[CARGO]",
      nacionalidade: dados.representante?.nacionalidade || "[NACIONALIDADE]",
      estado_civil: dados.representante?.estado_civil || "[ESTADO CIVIL]",
      profissao: dados.representante?.profissao || "[PROFISSÃO]",
      rg: dados.representante?.rg || "[RG]",
      cpf: dados.representante?.cpf || "[CPF]",
      endereco: dados.representante?.endereco || "[ENDEREÇO]"
    };

    const prazos = {
      semanas_diagnostico: dados.prazos?.semanas_diagnostico || 4,
      meses_vigencia: dados.prazos?.meses_vigencia || 2,
      prazo_entrega_semanas: dados.prazos?.prazo_entrega_semanas || 6
    };

    const contato = {
      email_contratante: dados.contato?.email_contratante || "[E-MAIL DA CONTRATANTE]",
      email_contratada: dados.contato?.email_contratada || "[SEU E-MAIL]"
    };

    const dataAssinatura = dados.data_assinatura || new Date().toLocaleDateString('pt-BR');
    const valorNegociado = dados.valor_negociado;
    const valorOriginalIA = dados.valor_original_ia || null;

    const formatarMoeda = (valor) => {
      return new Intl.NumberFormat('pt-BR', {
        style: 'currency',
        currency: 'BRL',
        minimumFractionDigits: 2
      }).format(valor);
    };

    // ========================================
    // FUNÇÃO PARA GERAR CLÁUSULA DE PAGAMENTO DINÂMICA (ATUALIZADA)
    // ========================================
    function gerarClausulaPagamento(valorNegociado, forma_pagamento, valor_entrada, num_parcelas, valor_parcela, motivo_negociacao, desconto, motivo_desconto, valor_base_negociacao) {
      let textoNegociacao = '';
      let textoPagamento = '';

      // Se houver motivo de negociação ou desconto
      if (motivo_negociacao || (desconto && desconto > 0)) {
        textoNegociacao = `4.1.1. `;
        
        if (desconto && desconto > 0) {
          textoNegociacao += `O valor originalmente proposto era de ${formatarMoeda(valor_base_negociacao)}. Foi concedido um desconto de ${formatarMoeda(desconto)} (${motivo_desconto || "negociação comercial"}). `;
        }
        
        if (motivo_negociacao) {
          textoNegociacao += `Motivo da negociação: ${motivo_negociacao}. `;
        }
        
        textoNegociacao += `O valor final acordado é de ${formatarMoeda(valorNegociado)}.\n`;
      }

      // À vista
      if (forma_pagamento === 'a_vista') {
        textoPagamento = `
4.2. O pagamento será efetuado em parcela única, conforme abaixo:
   a) 100% (cem por cento) na data de assinatura deste contrato: ${formatarMoeda(valorNegociado)}.

4.2.1. O pagamento à vista confere à CONTRATANTE o desconto já aplicado sobre o valor total, conforme condições comerciais acordadas entre as partes.
`;
      }
      // 50/50 para Diagnóstico
      else if (forma_pagamento === 'cinquenta_cinquenta') {
        const valorEntrada = valorNegociado * 0.5;
        const valorFinal = valorNegociado * 0.5;
        
        textoPagamento = `
4.2. O pagamento da Fase 1 (Diagnóstico) será efetuado da seguinte forma:
   a) 50% (cinquenta por cento) na data de assinatura deste contrato: ${formatarMoeda(valorEntrada)};
   b) 50% (cinquenta por cento) na data de entrega e aceitação do relatório de diagnóstico: ${formatarMoeda(valorFinal)}.

4.2.1. A segunda parcela deverá ser paga em até 5 (cinco) dias úteis após a entrega e aceitação do relatório.
`;
      }
      // Parcelado com entrada de 50%
      else if (forma_pagamento === 'parcelado') {
        const entrada = valor_entrada || (valorNegociado * 0.5);
        const parcelas = num_parcelas || 3;
        const valorParcelaCalculado = valor_parcela || ((valorNegociado - entrada) / parcelas);
        
        textoPagamento = `
4.2. O pagamento será efetuado da seguinte forma:
   a) Entrada de ${formatarMoeda(entrada)} (${Math.round((entrada/valorNegociado)*100)}% do valor total) na data de assinatura deste contrato;
   b) Saldo de ${formatarMoeda(valorNegociado - entrada)} em ${parcelas} parcelas mensais, consecutivas e sucessivas, no valor de ${formatarMoeda(valorParcelaCalculado)} cada uma, vencendo a primeira em 30 (trinta) dias após a assinatura.

4.2.1. As parcelas serão corrigidas monetariamente pelo índice IPCA a partir da data de vencimento de cada uma.
`;
      }
      // Condições Especiais (Negociação personalizada)
      else {
        const entrada = valor_entrada || 0;
        const parcelas = num_parcelas || 0;
        const valorParcelaCalculado = valor_parcela || (parcelas > 0 ? (valorNegociado - entrada) / parcelas : 0);
        const percentualEntrada = entrada > 0 ? Math.round((entrada / valorNegociado) * 100) : 0;
        
        textoPagamento = `
4.2. O pagamento será efetuado da seguinte forma (condições especiais negociadas):
   a) Entrada de ${formatarMoeda(entrada)} (${percentualEntrada}% do valor total) na data de assinatura deste contrato;
   b) Saldo de ${formatarMoeda(valorNegociado - entrada)} em ${parcelas} parcelas mensais, consecutivas e sucessivas, no valor de ${formatarMoeda(valorParcelaCalculado)} cada uma, vencendo a primeira em 30 (trinta) dias após a assinatura.

4.2.1. As parcelas serão corrigidas monetariamente pelo índice IPCA a partir da data de vencimento de cada uma.
4.2.2. Esta condição especial foi negociada conforme necessidade da CONTRATANTE e será detalhada no boleto/fatura.
`;
      }

      return textoNegociacao + textoPagamento;
    }

    // TEXTO PURO COM FORMATAÇÃO LIMPA
    const contrato = `
CONTRATO DE PRESTAÇÃO DE SERVIÇOS DE CONSULTORIA - FASE 1 (DIAGNÓSTICO)

CONTRATANTE: ${empresa.nome}, pessoa jurídica de direito privado, inscrita no CNPJ sob o nº ${empresa.cnpj}, com sede na ${empresa.endereco}, neste ato representada por ${representante.nome}, ${representante.nacionalidade}, ${representante.estado_civil}, ${representante.profissao}, portador do RG nº ${representante.rg} e CPF nº ${representante.cpf}, residente e domiciliado na ${representante.endereco}.

CONTRATADA: NEXUS ENGENHARIA APLICADA, pessoa jurídica de direito privado, inscrita no CNPJ sob o nº [CNPJ DA NEXUS], com sede na [ENDEREÇO DA NEXUS], neste ato representada por [SEU NOME], [NACIONALIDADE], [ESTADO CIVIL], [PROFISSÃO], portador do RG nº [RG] e CPF nº [CPF], residente e domiciliado na [ENDEREÇO].

As partes, acima identificadas, têm entre si justo e contratado o seguinte:

CLÁUSULA 1 – OBJETO

1.1. O presente contrato tem por objeto a prestação de serviços de consultoria em engenharia de produção, limitados à Fase 1 – Diagnóstico, com foco na identificação de oportunidades de ganho de produtividade, eficiência operacional e redução de custos industriais, conforme descrito no Anexo I, que passa a fazer parte integrante deste instrumento.

1.2. A Fase 1 compreende exclusivamente:
   a) Mapeamento do fluxo de valor (VSM) das áreas produtivas indicadas pela CONTRATANTE;
   b) Coleta e análise de dados operacionais (tempos de ciclo, disponibilidade, qualidade);
   c) Identificação de gargalos e oportunidades de melhoria;
   d) Elaboração e entrega de relatório técnico contendo diagnóstico e recomendações.

1.3. Não fazem parte do objeto deste contrato:
   a) Implementação de qualquer melhoria identificada;
   b) Acompanhamento pós-diagnóstico;
   c) Qualquer serviço ou atividade não expressamente previsto no Anexo I.

1.4. Após a entrega e aprovação do relatório de diagnóstico, as partes poderão, mediante aditivo contratual ou novo contrato, estabelecer o escopo, os prazos e os valores para a Fase 2 – Implementação e Fase 3 – Acompanhamento, com base nos dados reais coletados e nas oportunidades identificadas.

CLÁUSULA 2 – OBRIGAÇÕES DA CONTRATADA

A CONTRATANTE reconhece que a CONTRATADA possui metodologia própria e especializada para execução dos serviços, não cabendo interferência direta na condução técnica das atividades.

2.1. Executar os serviços com diligência, empregando as melhores práticas e técnicas de engenharia disponíveis, observando os padrões éticos e técnicos da profissão.

2.2. Fornecer equipe técnica qualificada e compatível com a natureza dos serviços, sendo a CONTRATADA a única responsável pela sua seleção, supervisão e remuneração.

2.3. Entregar o relatório de diagnóstico no prazo estipulado na Cláusula 5.

2.4. Manter absoluto sigilo sobre todas as informações da CONTRATANTE a que tiver acesso, conforme Cláusula 7.

2.5. Informar à CONTRATANTE, por escrito, qualquer fato ou circunstância que possa comprometer a execução dos serviços ou os resultados esperados.

2.6. A responsabilidade da CONTRATADA é de MEIO, não de resultado, não respondendo por resultados específicos que dependam de fatores alheios ao seu controle, tais como:
   a) Falta de engajamento ou disponibilidade da equipe da CONTRATANTE;
   b) Recusa da CONTRATANTE em implementar as recomendações;
   c) Condições operacionais não informadas previamente.

CLÁUSULA 3 – OBRIGAÇÕES DA CONTRATANTE

3.1. Fornecer acesso irrestrito às áreas produtivas, instalações, equipamentos e informações necessárias à execução dos serviços, durante o horário de trabalho normal da CONTRATANTE ou conforme acordado entre as partes.

3.2. Indicar, por escrito, um responsável técnico que atuará como contato oficial durante a vigência do contrato, devendo este ser autorizado a tomar decisões e fornecer informações em nome da CONTRATANTE.

3.3. Disponibilizar, no prazo de 5 (cinco) dias úteis a contar da solicitação da CONTRATADA, todos os dados históricos de produção, manutenção, qualidade e quaisquer outros documentos ou informações que se façam necessários à execução dos serviços.

3.4. Efetuar os pagamentos nas datas e condições estipuladas na Cláusula 4.

3.5. Fornecer, às suas expensas, os equipamentos de proteção individual (EPIs) necessários para que a equipe da CONTRATADA acesse as áreas produtivas, em conformidade com as normas de segurança aplicáveis.

3.6. Comunicar imediatamente à CONTRATADA qualquer alteração nas condições operacionais ou estruturais que possa impactar a execução dos serviços.

3.7. A CONTRATANTE declara estar ciente de que os resultados do diagnóstico dependem diretamente da qualidade e veracidade das informações fornecidas, assumindo integral responsabilidade por eventuais imprecisões ou omissões.

CLÁUSULA 3-A – AUTORIDADE TÉCNICA DA CONTRATADA

3-A.1. A CONTRATANTE reconhece que a CONTRATADA atua como especialista técnico independente, sendo responsável apenas pela análise, diagnóstico e recomendação técnica, cabendo exclusivamente à CONTRATANTE a decisão exclusiva e de sua inteira responsabilidade sobre a implementação ou não das ações sugeridas.

3-A.2. A CONTRATADA não se responsabiliza por decisões tomadas pela CONTRATANTE com base no diagnóstico, bem como pelos resultados ou consequências decorrentes da não implementação total ou parcial das recomendações apresentadas.

CLÁUSULA 4 – VALOR E CONDIÇÕES DE PAGAMENTO

4.1. O valor total dos serviços objeto deste contrato é de ${formatarMoeda(valorNegociado)} (${valorNegociado.toLocaleString('pt-BR')} reais), assim discriminado:

   a) Fase 1 (Diagnóstico): ${formatarMoeda(valorNegociado * 0.25)} (25% do valor total)
   b) Fase 2 (Implementação): ${formatarMoeda(valorNegociado * 0.50)} (50% do valor total)
   c) Fase 3 (Acompanhamento - 3 meses): ${formatarMoeda(valorNegociado * 0.25)} (25% do valor total)

4.2. O pagamento será efetuado da seguinte forma:

   **FASE 1 - DIAGNÓSTICO:**
   a) 50% (cinquenta por cento) na data de assinatura deste contrato;
   b) 50% (cinquenta por cento) na data de entrega e aceitação do relatório de diagnóstico.

   **FASE 2 - IMPLEMENTAÇÃO:**
   a) 40% (quarenta por cento) na data de início da implementação;
   b) 30% (trinta por cento) 30 (trinta) dias após o início;
   c) 30% (trinta por cento) na data de conclusão e aceitação da implementação.

   **FASE 3 - ACOMPANHAMENTO (3 meses):**
   a) Parcela mensal de ${formatarMoeda((valorNegociado * 0.25) / 3)} durante 3 (três) meses consecutivos, vencendo a primeira 30 (trinta) dias após a conclusão da implementação.

4.2.1. As parcelas serão corrigidas monetariamente pelo índice IPCA a partir da data de vencimento de cada uma.

4.3. O pagamento deverá ser efetuado mediante depósito/transferência bancária para a conta:
   Banco: [BANCO]
   Agência: [AGÊNCIA]
   Conta: [CONTA]
   Titular: NEXUS ENGENHARIA APLICADA

4.4. O comprovante de pagamento deverá ser enviado à CONTRATADA por e-mail em até 24 (vinte e quatro) horas após a efetivação, sob pena de suspensão dos serviços até a regularização.

4.5. O atraso no pagamento sujeitará a CONTRATANTE a:
   a) Multa moratória de 2% (dois por cento) sobre o valor da parcela em atraso;
   b) Juros de mora de 1% (um por cento) ao mês, calculados pro rata die;
   c) Correção monetária pelo índice IPCA (Índice de Preços ao Consumidor Amplo), ou outro índice oficial que venha a substituí-lo, contada da data do vencimento até a data do efetivo pagamento.

4.6. Em caso de inadimplemento, a CONTRATADA poderá suspender imediatamente a execução dos serviços até a regularização do pagamento, sem prejuízo da cobrança dos encargos previstos.

4.7. A ausência de pagamento na data acordada implica no não início dos serviços, não sendo reservada agenda, cronograma ou equipe técnica pela CONTRATADA, ficando a CONTRATANTE sujeita à realocação da disponibilidade da CONTRATADA em sua agenda.

CLÁUSULA 5 – PRAZO E VIGÊNCIA

5.1. O presente contrato terá vigência de ${prazos.meses_vigencia === 1 ? '1 (um) mês' : prazos.meses_vigencia + ' meses'}, contados da data de assinatura, podendo ser automaticamente estendido até a conclusão integral dos serviços previstos neste contrato.

5.2. O início dos serviços está condicionado ao pagamento da parcela prevista na Cláusula 4.2 e à disponibilização das informações e acessos previstos na Cláusula 3.

5.3. O prazo para entrega do relatório de diagnóstico é de 3 (três) semanas, contadas da data de início efetivo dos serviços.

CLÁUSULA 6 – PROPRIEDADE INTELECTUAL

A execução dos serviços poderá envolver o uso da plataforma proprietária Hórus, desenvolvida pela CONTRATADA, a qual constitui diferencial competitivo e ativo estratégico exclusivo, sendo vedado qualquer tipo de acesso, reprodução ou tentativa de engenharia reversa.

6.1. Toda a metodologia, know-how, softwares, sistemas (incluindo, mas não se limitando, à plataforma Hórus), técnicas, ferramentas, modelos, planilhas, procedimentos, materiais de treinamento e quaisquer outros ativos intelectuais desenvolvidos ou utilizados pela CONTRATADA na execução dos serviços são de sua propriedade exclusiva, constituindo segredo de negócio.

6.2. A CONTRATANTE não adquire, por força deste contrato, qualquer direito de propriedade sobre a metodologia, softwares ou ferramentas da CONTRATADA, incluindo, expressamente, a plataforma Hórus.

6.3. É expressamente proibido à CONTRATANTE:
   a) Copiar, reproduzir, modificar, descompilar ou realizar engenharia reversa da plataforma Hórus ou de qualquer ferramenta da CONTRATADA;
   b) Utilizar a metodologia da CONTRATADA para prestar serviços a terceiros;
   c) Reproduzir, no todo ou em parte, os relatórios ou documentos entregues para finalidade diversa daquela para a qual foram elaborados.

6.4. Os relatórios e documentos entregues à CONTRATANTE destinam-se ao seu uso exclusivo no âmbito do objeto contratado, sendo vedada sua divulgação a terceiros sem a prévia e expressa autorização por escrito da CONTRATADA.

6.5. A violação desta cláusula sujeitará a parte infratora ao pagamento de multa equivalente a 10 (dez) vezes o valor total deste contrato, sem prejuízo das perdas e danos e demais sanções cabíveis.

CLÁUSULA 7 – CONFIDENCIALIDADE

7.1. As partes obrigam-se a manter absoluto sigilo sobre todas as informações confidenciais a que tiverem acesso em razão deste contrato, considerando-se como tais:
   a) Dados operacionais, financeiros, estratégicos, de produção, qualidade, manutenção, custos e quaisquer informações de negócio da CONTRATANTE;
   b) Metodologia, softwares, ferramentas, técnicas e know-how da CONTRATADA;
   c) Qualquer informação expressamente identificada como confidencial.

7.2. A obrigação de confidencialidade estende-se pelo prazo de 5 (cinco) anos após o término deste contrato.

7.3. A violação desta cláusula sujeitará a parte infratora ao pagamento de multa equivalente a 3 (três) vezes o valor total deste contrato, sem prejuízo das perdas e danos e demais sanções cabíveis.

7.4. Não se considera violação da confidencialidade a divulgação de informações:
   a) Exigidas por determinação judicial ou legal;
   b) Já em domínio público;
   c) Autorizadas previamente por escrito pela parte titular.

CLÁUSULA 8 – RESCISÃO

8.1. O presente contrato poderá ser rescindido por qualquer das partes, mediante notificação por escrito, nas seguintes hipóteses:
   a) Descumprimento de qualquer cláusula contratual, não sanado no prazo de 15 (quinze) dias úteis após o recebimento da notificação;
   b) Por interesse exclusivo de qualquer das partes, mediante aviso prévio de 30 (trinta) dias, sem justa causa;
   c) Por caso fortuito ou força maior que impeça a execução do objeto, assim reconhecido judicialmente.

8.2. Em caso de rescisão unilateral sem justa causa pela CONTRATANTE, será devida multa de 20% (vinte por cento) sobre o saldo remanescente do contrato, calculado com base no valor total previsto na Cláusula 4.1. Caso a rescisão ocorra após o início dos serviços, serão devidos os valores proporcionais às atividades já executadas, não sendo cabível reembolso integral dos valores pagos.

8.3. Em caso de rescisão por descumprimento da CONTRATADA, esta restituirá à CONTRATANTE os valores já pagos, atualizados monetariamente, e pagará multa de 20% (vinte por cento) sobre o valor total do contrato.

8.4. Em caso de rescisão por descumprimento da CONTRATANTE, esta pagará à CONTRATADA os serviços já prestados, atualizados monetariamente, e multa de 20% (vinte por cento) sobre o valor total do contrato.

8.5. A rescisão não exonera as partes das obrigações de confidencialidade previstas na Cláusula 7 e das penalidades eventualmente já incorridas.

CLÁUSULA 9 – PENALIDADES

9.1. Pelo descumprimento de qualquer obrigação contratual não especificamente penalizada em outras cláusulas, será aplicada multa de 10% (dez por cento) sobre o valor total do contrato, sem prejuízo da obrigação principal.

9.2. As multas previstas neste contrato são independentes e acumuláveis, podendo ser exigidas cumulativamente quando configuradas as respectivas hipóteses.

9.3. A mora de qualquer das partes no cumprimento de suas obrigações sujeitará o infrator à incidência dos encargos previstos na Cláusula 4.5.

CLÁUSULA 10 – DISPOSIÇÕES GERAIS

10.1. Este contrato é celebrado em caráter intuitu personae em relação à CONTRATADA, não podendo a CONTRATANTE ceder ou transferir seus direitos e obrigações sem prévia e expressa anuência por escrito da CONTRATADA.

10.2. As comunicações entre as partes serão consideradas válidas quando enviadas por e-mail para os endereços abaixo, ou por correspondência com aviso de recebimento (AR):
   CONTRATANTE: ${contato.email_contratante}
   CONTRATADA: ${contato.email_contratada}

10.3. A tolerância quanto ao descumprimento de qualquer cláusula não constituirá novação, renúncia de direitos ou precedente, mantendo-se a exigibilidade das obrigações.

10.4. Qualquer modificação ou aditivo a este contrato deverá ser formalizado por escrito, com anuência de ambas as partes.

10.5. Os títulos das cláusulas são meramente descritivos e não vinculam a interpretação do contrato.

CLÁUSULA 11 – LIMITAÇÃO DE RESPONSABILIDADE

11.1. A responsabilidade total da CONTRATADA, independentemente da natureza da reclamação ou da teoria jurídica aplicável, fica limitada ao valor total pago pela CONTRATANTE nos últimos 12 (doze) meses, nunca excedendo o valor total deste contrato.

11.2. Em nenhuma hipótese a CONTRATADA será responsável por danos indiretos, lucros cessantes, perda de faturamento, perda de clientes, perda de oportunidades de negócio, danos à imagem ou reputação, ou qualquer outro dano consequencial.

CLÁUSULA 12 – FORO

12.1. Fica eleito o foro da Comarca de [SUA CIDADE/ESTADO] para dirimir quaisquer questões decorrentes deste contrato, com renúncia expressa a qualquer outro, por mais privilegiado que seja.

ANEXO I – ESCOPO DETALHADO DA FASE 1 (DIAGNÓSTICO)

1. ATIVIDADES

1.1. Reunião de abertura com a liderança da CONTRATANTE para alinhamento de expectativas, cronograma e definição do contato técnico.

1.2. Mapeamento do fluxo de valor (VSM) das áreas produtivas indicadas pela CONTRATANTE, incluindo:
   a) Identificação de todos os postos de trabalho;
   b) Levantamento de tempos de ciclo, setup e disponibilidade;
   c) Mapeamento de fluxo de materiais e informações.

1.3. Coleta e análise de dados operacionais, compreendendo:
   a) Levantamento de dados históricos de produção (mínimo 30 dias);
   b) Cronoanálise dos postos de trabalho (mínimo 30 medições por posto);
   c) Levantamento de perdas (setup, microparadas, refugo, retrabalho);
   d) Análise de indicadores de qualidade e manutenção.

1.4. Identificação de gargalos e oportunidades de melhoria.

1.5. Elaboração e entrega de relatório técnico contendo:
   a) Diagnóstico detalhado da situação atual;
   b) Quantificação das perdas identificadas (em tempo e valor financeiro);
   c) Identificação de gargalos e pontos críticos;
   d) Oportunidades de melhoria priorizadas;
   e) Recomendações técnicas para as Fases 2 e 3 (Implementação e Acompanhamento).

2. ENTREGAS

2.1. Relatório técnico de diagnóstico (formato PDF, mínimo 30 páginas).

2.2. Planilha consolidada de dados coletados (formato Excel).

2.3. Matriz de oportunidades priorizadas.

3. PRAZOS

3.1. O prazo para execução da Fase 1 é de 3 (três) semanas, contadas da data de início efetivo dos serviços, conforme Cláusula 5.3.

3.2. O cronograma detalhado será apresentado na reunião de abertura e poderá ser ajustado por acordo entre as partes.

ASSINATURAS

E, por estarem assim justas e contratadas, as partes assinam o presente instrumento em 2 (duas) vias de igual teor e forma.

${empresa.cidade || '[CIDADE]'}, ${dataAssinatura}.

<div style="display: flex; justify-content: space-between; gap: 40px; margin-top: 30px;">
  <div style="flex: 1; text-align: center;">
    <div style="border-top: 1px solid #000; margin: 15px 0 8px 0;"></div>
    <strong>CONTRATANTE</strong><br/>
    ${empresa.nome}<br/>
    ${representante.nome}<br/>
    ${representante.cargo}
  </div>

  <div style="flex: 1; text-align: center;">
    <div style="border-top: 1px solid #000; margin: 15px 0 8px 0;"></div>
    <strong>CONTRATADA</strong><br/>
    NEXUS ENGENHARIA APLICADA<br/>
    [SEU NOME]<br/>
    [SEU CARGO]
  </div>
</div>

<div style="margin-top: 40px;">
  <p><strong>TESTEMUNHAS:</strong></p>
  
  <div style="display: flex; gap: 40px; margin-top: 15px;">
    <div style="flex: 1;">
      <div style="border-top: 1px solid #000; margin-bottom: 8px;"></div>
      <p style="margin: 5px 0;">Nome: __________________________</p>
      <p style="margin: 5px 0;">RG: _____________________________</p>
      <p style="margin: 5px 0;">CPF: ____________________________</p>
    </div>

    <div style="flex: 1;">
      <div style="border-top: 1px solid #000; margin-bottom: 8px;"></div>
      <p style="margin: 5px 0;">Nome: __________________________</p>
      <p style="margin: 5px 0;">RG: _____________________________</p>
      <p style="margin: 5px 0;">CPF: ____________________________</p>
    </div>
  </div>
</div>
`;

    res.status(200).json({
      status: "sucesso",
      contrato: contrato,
      metadata: {
        empresa: empresa.nome,
        valor_negociado: valorNegociado,
        valor_original_ia: valorOriginalIA,
        data_geracao: new Date().toISOString(),
        tipo: "pre-diagnostico"
      }
    });

  } catch (error) {
    console.error("❌ Erro ao gerar contrato pré-diagnóstico:", error.message);
    res.status(500).json({ 
      erro: "Falha ao gerar contrato",
      detalhe: error.message 
    });
  }
});

// ========================================
// 📄 CONTRATO FASE 2+3 (IMPLEMENTAÇÃO + ACOMPANHAMENTO)
// ========================================

app.post("/api/ia/gerar-contrato-implementacao", autenticarToken, async (req, res) => {
  try {
    const dados = req.body;

    if (!dados.empresa_id) {
      return res.status(400).json({ erro: "ID da empresa é obrigatório" });
    }

    // ========================================
    // 1️⃣ BUSCAR DADOS DA EMPRESA
    // ========================================
    const empresaRes = await pool.query(
      "SELECT * FROM empresas WHERE id = $1",
      [dados.empresa_id]
    );

    if (empresaRes.rows.length === 0) {
      return res.status(404).json({ erro: "Empresa não encontrada" });
    }

    const empresa = empresaRes.rows[0];

    // ========================================
    // 2️⃣ BUSCAR CONTRATO DA FASE 1
    // ========================================
    const contratoFase1Res = await pool.query(`
      SELECT 
        valor_total_projeto,
        valor_fase1_diagnostico
      FROM contratos_fase1
      WHERE empresa_id = $1
      ORDER BY data_assinatura DESC
      LIMIT 1
    `, [dados.empresa_id]);

    if (contratoFase1Res.rows.length === 0) {
      return res.status(404).json({ 
        erro: "Nenhum contrato da Fase 1 encontrado para esta empresa",
        mensagem: "É necessário ter o contrato de Diagnóstico (Fase 1) assinado antes de prosseguir."
      });
    }

    const contratoFase1 = contratoFase1Res.rows[0];
    const valorTotalProjeto = parseFloat(contratoFase1.valor_total_projeto);
    const valorFase1 = parseFloat(contratoFase1.valor_fase1_diagnostico);
    
    // ========================================
    // 3️⃣ CALCULAR VALORES DA FASE 2+3
    // ========================================
    const saldoFase2e3 = valorTotalProjeto - valorFase1;
    
    // Distribuição: 80% para Implementação, 20% para Acompanhamento
    const valorImplementacao = Math.round(valorTotalProjeto * 0.50);
    const valorAcompanhamentoTotal = Math.round(valorTotalProjeto * 0.25);
    const MESES_ACOMPANHAMENTO = 3; // padrão
    const valorAcompanhamentoMensal = Math.round(valorAcompanhamentoTotal / MESES_ACOMPANHAMENTO);
    
    // ========================================
    // 4️⃣ PRAZOS E CONFIGURAÇÕES
    // ========================================
    const prazoImplementacao = dados.prazo_implementacao_semanas || 6;
    const dataAssinatura = dados.data_assinatura || new Date().toLocaleDateString('pt-BR');
    
    // ========================================
    // 5️⃣ DADOS DO REPRESENTANTE E CONTATO
    // ========================================
    const representante = {
      nome: dados.representante?.nome || "[NOME DO REPRESENTANTE]",
      cargo: dados.representante?.cargo || "[CARGO]",
      nacionalidade: dados.representante?.nacionalidade || "[NACIONALIDADE]",
      estado_civil: dados.representante?.estado_civil || "[ESTADO CIVIL]",
      profissao: dados.representante?.profissao || "[PROFISSÃO]",
      rg: dados.representante?.rg || "[RG]",
      cpf: dados.representante?.cpf || "[CPF]",
      endereco: dados.representante?.endereco || "[ENDEREÇO]"
    };

    const contato = {
      email_contratante: dados.contato?.email_contratante || "[E-MAIL DA CONTRATANTE]",
      email_contratada: dados.contato?.email_contratada || "[SEU E-MAIL]"
    };

    const formatarMoeda = (valor) => {
      return new Intl.NumberFormat('pt-BR', {
        style: 'currency',
        currency: 'BRL',
        minimumFractionDigits: 2
      }).format(valor);
    };

    // ========================================
    // 6️⃣ FUNÇÃO PARA GERAR CLÁUSULA DE PAGAMENTO DINÂMICA (ATUALIZADA)
    // ========================================
    function gerarClausulaPagamentoFase2e3(valorImplementacao, valorAcompanhamentoTotal, mesesAcompanhamento, valorAcompanhamentoMensal, forma_pagamento, valor_entrada, num_parcelas, valor_parcela, motivo_negociacao) {
      let textoNegociacao = '';
      let textoPagamento = '';

      if (motivo_negociacao) {
        textoNegociacao = `5.1.1. Motivo da negociação: ${motivo_negociacao}.\n`;
      }

      // À vista
      if (forma_pagamento === 'a_vista') {
        const valorTotal = valorImplementacao + valorAcompanhamentoTotal;
        textoPagamento = `
5.2. O pagamento será efetuado em parcela única, conforme abaixo:
   a) 100% (cem por cento) na data de assinatura deste contrato: ${formatarMoeda(valorTotal)}.
`;
      }
      // 50/50 para Implementação
      else if (forma_pagamento === 'cinquenta_cinquenta') {
        const valorEntrada = valorImplementacao * 0.5;
        const valorFinal = valorImplementacao * 0.5;
        
        textoPagamento = `
5.2. O pagamento será efetuado da seguinte forma:

   **FASE 2 - IMPLEMENTAÇÃO:**
   a) 50% (cinquenta por cento) na data de assinatura deste contrato: ${formatarMoeda(valorEntrada)};
   b) 50% (cinquenta por cento) na data de conclusão e aceitação da implementação: ${formatarMoeda(valorFinal)}.

   **FASE 3 - ACOMPANHAMENTO (${mesesAcompanhamento} meses):**
   a) Parcela mensal de ${formatarMoeda(valorAcompanhamentoMensal)} durante ${mesesAcompanhamento} meses consecutivos, vencendo a primeira 30 (trinta) dias após a conclusão da implementação.

5.2.1. A segunda parcela da implementação deverá ser paga em até 5 (cinco) dias úteis após a conclusão e aceitação.
`;
      }
      // Parcelado para Implementação (40/30/30)
      else if (forma_pagamento === 'parcelado') {
        const entrada = valor_entrada || (valorImplementacao * 0.4);
        const segundaParcela = valorImplementacao * 0.3;
        const terceiraParcela = valorImplementacao * 0.3;
        
        textoPagamento = `
5.2. O pagamento será efetuado da seguinte forma:

   **FASE 2 - IMPLEMENTAÇÃO:**
   a) 40% (quarenta por cento) na data de início da implementação: ${formatarMoeda(entrada)};
   b) 30% (trinta por cento) 30 (trinta) dias após o início: ${formatarMoeda(segundaParcela)};
   c) 30% (trinta por cento) na data de conclusão e aceitação da implementação: ${formatarMoeda(terceiraParcela)}.

   **FASE 3 - ACOMPANHAMENTO (${mesesAcompanhamento} meses):**
   a) Parcela mensal de ${formatarMoeda(valorAcompanhamentoMensal)} durante ${mesesAcompanhamento} meses consecutivos, vencendo a primeira 30 (trinta) dias após a conclusão da implementação.

5.2.1. As parcelas da implementação serão corrigidas monetariamente pelo índice IPCA a partir da data de vencimento de cada uma.
5.2.2. O valor da parcela de acompanhamento é fixo durante o período contratado.
`;
      }
      // Condições Especiais (Negociação personalizada)
      else if (forma_pagamento === 'especial') {
        const entrada = valor_entrada || 0;
        const parcelas = num_parcelas || 0;
        const valorParcelaCalculado = valor_parcela || (parcelas > 0 ? (valorImplementacao - entrada) / parcelas : 0);
        const percentualEntrada = entrada > 0 ? Math.round((entrada / valorImplementacao) * 100) : 0;
        
        textoPagamento = `
5.2. O pagamento será efetuado da seguinte forma (condições especiais negociadas):

   **FASE 2 - IMPLEMENTAÇÃO:**
   a) Entrada de ${formatarMoeda(entrada)} (${percentualEntrada}% do valor da implementação) na data de assinatura deste contrato;
   b) Saldo de ${formatarMoeda(valorImplementacao - entrada)} em ${parcelas} parcelas mensais, consecutivas e sucessivas, no valor de ${formatarMoeda(valorParcelaCalculado)} cada uma, vencendo a primeira em 30 (trinta) dias após a assinatura.

   **FASE 3 - ACOMPANHAMENTO (${mesesAcompanhamento} meses):**
   a) Parcela mensal de ${formatarMoeda(valorAcompanhamentoMensal)} durante ${mesesAcompanhamento} meses consecutivos, vencendo a primeira 30 (trinta) dias após a conclusão da implementação.

5.2.1. As parcelas serão corrigidas monetariamente pelo índice IPCA a partir da data de vencimento de cada uma.
5.2.2. Esta condição especial foi negociada conforme necessidade da CONTRATANTE e será detalhada no boleto/fatura.
`;
      }
      // Fallback
      else {
        const valorTotal = valorImplementacao + valorAcompanhamentoTotal;
        textoPagamento = `
5.2. O pagamento será efetuado em parcela única de ${formatarMoeda(valorTotal)} na data de assinatura deste contrato.
`;
      }

      return textoNegociacao + textoPagamento;
    }

    // ========================================
    // 7️⃣ TEMPLATE DO CONTRATO
    // ========================================
    const contrato = `
CONTRATO DE PRESTAÇÃO DE SERVIÇOS DE CONSULTORIA - FASE 2 (IMPLEMENTAÇÃO) E FASE 3 (ACOMPANHAMENTO)

CONTRATANTE: ${empresa.nome}, pessoa jurídica de direito privado, inscrita no CNPJ sob o nº ${empresa.cnpj || '[CNPJ]'}, com sede na ${empresa.endereco || '[ENDEREÇO]'}, neste ato representada por ${representante.nome}, ${representante.nacionalidade}, ${representante.estado_civil}, ${representante.profissao}, portador do RG nº ${representante.rg} e CPF nº ${representante.cpf}, residente e domiciliado na ${representante.endereco}.

CONTRATADA: NEXUS ENGENHARIA APLICADA, pessoa jurídica de direito privado, inscrita no CNPJ sob o nº [CNPJ DA NEXUS], com sede na [ENDEREÇO DA NEXUS], neste ato representada por [SEU NOME], [NACIONALIDADE], [ESTADO CIVIL], [PROFISSÃO], portador do RG nº [RG] e CPF nº [CPF], residente e domiciliado na [ENDEREÇO].

As partes, acima identificadas, têm entre si justo e contratado o seguinte:


CLÁUSULA 1 – OBJETO

1.1. O presente contrato tem por objeto a prestação de serviços de consultoria em engenharia de produzione, compreendendo as Fases 2 e 3, com base nos resultados da Fase 1 (Diagnóstico) previamente concluída.

1.2. FASE 2 – IMPLEMENTAÇÃO (${prazoImplementacao} semanas)

   a) SMED (Troca Rápida de Ferramentas): Implementação nos postos gargalo identificados no diagnóstico, visando redução mínima de 50% no tempo de setup;

   b) Balanceamento de Linha: Redistribuição das atividades entre os postos para equalizar a carga de trabalho e eliminar gargalos;

   c) Padronização de Processos: Elaboração e implementação de Procedimentos Operacionais Padrão (POPs) para as atividades críticas;

   d) Treinamento da Equipe: Capacitação dos operadores e lideranças em ferramentas de Manufatura Enxuta (20 horas presenciais);

   e) Gestão Visual: Implantação de quadros de indicadores no chão de fábrica para acompanhamento em tempo real;

   f) 5S: Implementação da metodologia nos postos de trabalho prioritários.

1.3. FASE 3 – ACOMPANHAMENTO (${MESES_ACOMPANHAMENTO} meses)

   a) Monitoramento Semanal: Acompanhamento dos indicadores (OEE, produtividade, qualidade) com análise de tendências;

   b) Reuniões de Acompanhamento: 1 hora semanal com a liderança para análise de resultados e definição de ações corretivas;

   c) Ajustes Finos: Correções e otimizações nos processos implementados;

   d) Transferência de Conhecimento: Capacitação da equipe interna para sustentar os resultados;

   e) Relatórios Mensais: Documentação da evolução dos indicadores e resultados alcançados;

   f) Plano de Sustentação: Metodologia para manutenção dos ganhos após o término do contrato.


CLÁUSULA 2 – RESULTADOS ESPERADOS

2.1. Com base no diagnóstico realizado na Fase 1, estimamos os seguintes resultados:

   OEE:
   - Situação atual: A ser confirmado no diagnóstico
   - Meta após implementação: Mínimo de 85%
   - Ganho projetado: A ser quantificado no diagnóstico

   Setup (postos gargalo):
   - Situação atual: A ser confirmado no diagnóstico
   - Meta após implementação: Redução mínima de 50%
   - Redução projetada: 50%

   Perdas Totais:
   - Situação atual: A ser confirmado no diagnóstico
   - Meta após implementação: Redução de 30%
   - Economia projetada: A ser quantificada no diagnóstico

2.2. Os resultados acima são estimativas baseadas no diagnóstico e nas melhores práticas do setor. Os resultados finais serão medidos e documentados ao longo da execução.

2.3. A CONTRATADA não garante percentuais específicos de melhoria, comprometendo-se a empregar as melhores técnicas e esforços para atingir os objetivos.


CLÁUSULA 3 – OBRIGAÇÕES DA CONTRATADA

3.1. Executar os serviços com diligência, empregando as melhores práticas e técnicas de engenharia disponíveis, observando os padrões éticos e técnicos da profissão.

3.2. Fornecer equipe técnica qualificada e compatível com a natureza dos serviços, sendo a CONTRATADA a única responsável pela sua seleção, supervisão e remuneração.

3.3. Entregar os seguintes documentos:
   a) Relatório de implementação (ao final da Fase 2);
   b) Procedimentos Operacionais Padrão (POPs) elaborados;
   c) Relatórios mensais de acompanhamento (durante a Fase 3);
   d) Plano de sustentação (ao final da Fase 3).

3.4. Manter absoluto sigilo sobre todas as informações da CONTRATANTE a que tiver acesso, conforme Cláusula 8.

3.5. Informar à CONTRATANTE, por escrito, qualquer fato ou circunstância que possa comprometer a execução dos serviços ou os resultados esperados.

3.6. A responsabilidade da CONTRATADA é de MEIO, não de resultado, não respondendo por resultados específicos que dependam de fatores alheios ao seu controle, tais como:
   a) Falta de engajamento ou disponibilidade da equipe da CONTRATANTE;
   b) Recusa da CONTRATANTE em implementar as recomendações;
   c) Condições operacionais não informadas previamente;
   d) Fatores externos não previstos.


CLÁUSULA 3-A – AUTORIDADE TÉCNICA DA CONTRATADA

3-A.1. A CONTRATANTE reconhece que a CONTRATADA atua como especialista técnico independente, sendo responsável apenas pela análise, diagnóstico e recomendação técnica, cabendo exclusivamente à CONTRATANTE a decisão exclusiva e de sua inteira responsabilidade sobre a implementação ou não das ações sugeridas.

3-A.2. A CONTRATADA não se responsabiliza por decisões tomadas pela CONTRATANTE com base no diagnóstico, bem como pelos resultados ou consequências decorrentes da não implementação total ou parcial das recomendações apresentadas.


CLÁUSULA 4 – OBRIGAÇÕES DA CONTRATANTE

4.1. Fornecer acesso irrestrito às áreas produtivas, instalações, equipamentos e informações necessárias à execução dos serviços, durante o horário de trabalho normal da CONTRATANTE ou conforme acordado entre as partes.

4.2. Indicar, por escrito, um responsável técnico que atuará como contato oficial durante a vigência do contrato, devendo este ser autorizado a tomar decisões e fornecer informações em nome da CONTRATANTE.

4.3. Disponibilizar, no prazo de 5 (cinco) dias úteis a contar da solicitação da CONTRATADA, todos os dados históricos de produção, manutenção, qualidade e quaisquer outros documentos ou informações que se façam necessários à execução dos serviços.

4.4. Efetuar os pagamentos nas datas e condições estipuladas na Cláusula 5.

4.5. Fornecer, às suas expensas, os equipamentos de proteção individual (EPIs) necessários para que a equipe da CONTRATADA acesse as áreas produtivas, em conformidade com as normas de segurança aplicáveis.

4.6. Comunicar imediatamente à CONTRATADA qualquer alteração nas condições operacionais ou estruturais que possa impactar a execução dos serviços.

4.7. Implementar as recomendações acordadas, sendo de sua inteira responsabilidade os resultados decorrentes da não implementação.

4.8. A CONTRATANTE declara estar ciente de que os resultados da implementação dependem diretamente da qualidade e veracidade das informações fornecidas, assumindo integral responsabilidade por eventuais imprecisões ou omissões.


CLÁUSULA 5 – VALOR E CONDIÇÕES DE PAGAMENTO

5.1. O valor total dos serviços objeto deste contrato é de ${formatarMoeda(saldoFase2e3)} (${saldoFase2e3.toLocaleString('pt-BR')} reais), assim discriminados:

   a) Implementação (Fase 2): ${formatarMoeda(valorImplementacao)} (${Math.round((valorImplementacao/saldoFase2e3)*100)}% do valor total)
   b) Acompanhamento (Fase 3): ${formatarMoeda(valorAcompanhamentoTotal)} (${Math.round((valorAcompanhamentoTotal/saldoFase2e3)*100)}% do valor total)
      └─ ${MESES_ACOMPANHAMENTO} (seis) meses × ${formatarMoeda(valorAcompanhamentoMensal)}/mês

${gerarClausulaPagamentoFase2e3(
  valorImplementacao,
  valorAcompanhamentoTotal,
  MESES_ACOMPANHAMENTO,
  valorAcompanhamentoMensal,
  dados.forma_pagamento || 'parcelado',
  dados.valor_entrada,
  dados.num_parcelas,
  dados.valor_parcela,
  dados.motivo_negociacao
)}

5.3. Os valores mensais referentes à Fase 3 (Acompanhamento) estão incluídos nas parcelas e serão discriminados mensalmente na fatura/cobrança.

5.4. O pagamento deverá ser efetuado mediante depósito/transferência bancária para a conta:
   Banco: [BANCO]
   Agência: [AGÊNCIA]
   Conta: [CONTA]
   Titular: NEXUS ENGENHARIA APLICADA

5.5. O comprovante de pagamento deverá ser enviado à CONTRATADA por e-mail em até 24 (vinte e quatro) horas após a efetivação, sob pena de suspensão dos serviços até a regularização.

5.6. O atraso no pagamento sujeitará a CONTRATANTE a:
   a) Multa moratória de 2% (dois por cento) sobre o valor da parcela em atraso;
   b) Juros de mora de 1% (um por cento) ao mês, calculados pro rata die;
   c) Correção monetária pelo índice IPCA (Índice de Preços ao Consumidor Amplo), ou outro índice oficial que venha a substituí-lo, contada da data do vencimento até a data do efetivo pagamento.

5.7. Em caso de inadimplemento, a CONTRATADA poderá suspender imediatamente a execução dos serviços até a regularização do pagamento, sem prejuízo da cobrança dos encargos previstos.

5.8. A ausência de pagamento na data acordada implica no não início dos serviços, não sendo reservada agenda, cronograma ou equipe técnica pela CONTRATADA, ficando a CONTRATANTE sujeita à realocação da disponibilidade da CONTRATADA em sua agenda.


CLÁUSULA 6 – PRAZO E VIGÊNCIA

6.1. O presente contrato terá vigência de ${prazoImplementacao} semanas para a Fase 2, acrescidas de ${MESES_ACOMPANHAMENTO} meses para a Fase 3, contados da data de assinatura, podendo ser automaticamente estendido até a conclusão integral dos serviços previstos neste contrato.

6.2. O início dos serviços está condicionado ao pagamento da parcela prevista na Cláusula 5.2 e à disponibilização das informações e acessos previstos na Cláusula 4.

6.3. Os prazos poderão ser ajustados por acordo entre as partes, mediante aditivo contratual. Após o término do prazo padrão de ${MESES_ACOMPANHAMENTO} meses, a Fase 3 poderá ser estendida por meio de aditivo contratual específico.


CLÁUSULA 7 – PROPRIEDADE INTELECTUAL

A execução dos serviços poderá envolver o uso da plataforma proprietária Hórus, desenvolvida pela CONTRATADA, a qual constitui diferencial competitivo e ativo estratégico exclusivo, sendo vedado qualquer tipo de acesso, reprodução ou tentativa de engenharia reversa.

7.1. Toda a metodologia, know-how, softwares, sistemas (incluindo, mas não se limitando, à plataforma Hórus), técnicas, ferramentas, modelos, planilhas, procedimentos, materiais de treinamento e quaisquer outros ativos intelectuais desenvolvidos ou utilizados pela CONTRATADA na execução dos serviços são de sua propriedade exclusiva, constituindo segredo de negócio.

7.2. A CONTRATANTE não adquire, por força deste contrato, qualquer direito de propriedade sobre a metodologia, softwares ou ferramentas da CONTRATADA, incluindo, expressamente, a plataforma Hórus.

7.3. É expressamente proibido à CONTRATANTE:
   a) Copiar, reproduzir, modificar, descompilar ou realizar engenharia reversa da plataforma Hórus ou de qualquer ferramenta da CONTRATADA;
   b) Utilizar a metodologia da CONTRATADA para prestar serviços a terceiros;
   c) Reproduzir, no todo ou em parte, os relatórios ou documentos entregues para finalidade diversa daquela para a qual foram elaborados.

7.4. Os relatórios e documentos entregues à CONTRATANTE destinam-se ao seu uso exclusivo no âmbito do objeto contratado, sendo vedada sua divulgação a terceiros sem a prévia e expressa autorização por escrito da CONTRATADA.

7.5. A violação desta cláusula sujeitará a parte infratora ao pagamento de multa equivalente a 10 (dez) vezes o valor total deste contrato, sem prejuízo das perdas e danos e demais sanções cabíveis.


CLÁUSULA 8 – CONFIDENCIALIDADE

8.1. As partes obrigam-se a manter absoluto sigilo sobre todas as informações confidenciais a que tiverem acesso em razão deste contrato, considerando-se como tais:
   a) Dados operacionais, financeiros, estratégicos, de produção, qualidade, manutenção, custos e quaisquer informações de negócio da CONTRATANTE;
   b) Metodologia, softwares, ferramentas, técnicas e know-how da CONTRATADA;
   c) Qualquer informação expressamente identificada como confidencial.

8.2. A obrigação de confidencialidade estende-se pelo prazo de 5 (cinco) anos após o término deste contrato.

8.3. A violação desta cláusula sujeitará a parte infratora ao pagamento de multa equivalente a 3 (três) vezes o valor total deste contrato, sem prejuízo das perdas e danos e demais sanções cabíveis.

8.4. Não se considera violação da confidencialidade a divulgação de informações:
   a) Exigidas por determinação judicial ou legal;
   b) Já em domínio público;
   c) Autorizadas previamente por escrito pela parte titular.


CLÁUSULA 9 – RESCISÃO

9.1. O presente contrato poderá ser rescindido por qualquer das partes, mediante notificação por escrito, nas seguintes hipóteses:
   a) Descumprimento de qualquer cláusula contratual, não sanado no prazo de 15 (quinze) dias úteis após o recebimento da notificação;
   b) Por interesse exclusivo de qualquer das partes, mediante aviso prévio de 30 (trinta) dias, sem justa causa;
   c) Por caso fortuito ou força maior que impeça a execução do objeto, assim reconhecido judicialmente.

9.2. Em caso de rescisão unilateral sem justa causa pela CONTRATANTE, será devida multa de 20% (vinte por cento) sobre o saldo remanescente do contrato, calculado com base no valor total previsto na Cláusula 5.1. Caso a rescisão ocorra após o início dos serviços, serão devidos os valores proporcionais às atividades já executadas, não sendo cabível reembolso integral dos valores pagos.

9.3. Em caso de rescisão por descumprimento da CONTRATADA, esta restituirá à CONTRATANTE os valores já pagos, atualizados monetariamente, e pagará multa de 20% (vinte por cento) sobre o valor total do contrato.

9.4. Em caso de rescisão por descumprimento da CONTRATANTE, esta pagará à CONTRATADA os serviços já prestados, atualizados monetariamente, e multa de 20% (vinte por cento) sobre o valor total do contrato.

9.5. A rescisão não exonera as partes das obrigações de confidencialidade previstas na Cláusula 8 e das penalidades eventualmente já incorridas.


CLÁUSULA 10 – PENALIDADES

10.1. Pelo descumprimento de qualquer obrigação contratual não especificamente penalizada em outras cláusulas, será aplicada multa de 10% (dez por cento) sobre o valor total do contrato, sem prejuízo da obrigação principal.

10.2. As multas previstas neste contrato são independentes e acumuláveis, podendo ser exigidas cumulativamente quando configuradas as respectivas hipóteses.

10.3. A mora de qualquer das partes no cumprimento de suas obrigações sujeitará o infrator à incidência dos encargos previstos na Cláusula 5.6.


CLÁUSULA 11 – DISPOSIÇÕES GERAIS

11.1. Este contrato é celebrado em caráter intuitu personae em relação à CONTRATADA, não podendo a CONTRATANTE ceder ou transferir seus direitos e obrigações sem prévia e expressa anuência por escrito da CONTRATADA.

11.2. As comunicações entre as partes serão consideradas válidas quando enviadas por e-mail para os endereços abaixo, ou por correspondência com aviso de recebimento (AR):
   CONTRATANTE: ${contato.email_contratante}
   CONTRATADA: ${contato.email_contratada}

11.3. A tolerância quanto ao descumprimento de qualquer cláusula não constituirá novação, renúncia de direitos ou precedente, mantendo-se a exigibilidade das obrigações.

11.4. Qualquer modificação ou aditivo a este contrato deverá ser formalizado por escrito, com anuência de ambas as partes.

11.5. Os títulos das cláusulas são meramente descritivos e não vinculam a interpretação do contrato.


CLÁUSULA 12 – LIMITAÇÃO DE RESPONSABILIDADE

12.1. A responsabilidade total da CONTRATADA, independentemente da natureza da reclamação ou da teoria jurídica aplicável, fica limitada ao valor total pago pela CONTRATANTE nos últimos 12 (doze) meses, nunca excedendo o valor total deste contrato.

12.2. Em nenhuma hipótese a CONTRATADA será responsável por danos indiretos, lucros cessantes, perda de faturamento, perda de clientes, perda de oportunidades de negócio, danos à imagem ou reputação, ou qualquer outro dano consequencial.


CLÁUSULA 13 – FORO

13.1. Fica eleito o foro da Comarca de [SUA CIDADE/ESTADO] para dirimir quaisquer questões decorrentes deste contrato, com renúncia expressa a qualquer outro, por mais privilegiado que seja.


ASSINATURAS

E, por estarem assim justas e contratadas, as partes assinam o presente instrumento em 2 (duas) vias de igual teor e forma.

${empresa.cidade || '[CIDADE]'}, ${dataAssinatura}.

<div class="grid-assinaturas-print">
  <div class="campo-assinatura">
    <div class="linha-assinatura"></div>
    <strong>CONTRATANTE</strong><br/>
    ${empresa.nome}<br/>
    ${representante.nome}<br/>
    ${representante.cargo}
  </div>

  <div class="campo-assinatura">
    <div class="linha-assinatura"></div>
    <strong>CONTRATADA</strong><br/>
    NEXUS ENGENHARIA APLICADA<br/>
    [SEU NOME]<br/>
    [SEU CARGO]
  </div>
</div>

<div class="testemunhas-print" style="margin-top: 40px; page-break-inside: avoid;">
  <p style="margin-bottom: 30px;"><strong>TESTEMUNHAS:</strong></p>
  
  <div style="display: flex; gap: 60px;">
    <div style="flex: 1;">
      <div style="border-top: 1px solid #000; margin-bottom: 8px; width: 100%;"></div>
      <p style="margin: 0; font-size: 9pt; color: #444;">Assinatura da Testemunha 1</p>
      <p style="margin: 10px 0 0 0; font-size: 10pt;">Nome: __________________________</p>
      <p style="margin: 5px 0 0 0; font-size: 10pt;">RG: _____________________________</p>
      <p style="margin: 5px 0 0 0; font-size: 10pt;">CPF: ____________________________</p>
    </div>

    <div style="flex: 1;">
      <div style="border-top: 1px solid #000; margin-bottom: 8px; width: 100%;"></div>
      <p style="margin: 0; font-size: 9pt; color: #444;">Assinatura da Testemunha 2</p>
      <p style="margin: 10px 0 0 0; font-size: 10pt;">Nome: __________________________</p>
      <p style="margin: 5px 0 0 0; font-size: 10pt;">RG: _____________________________</p>
      <p style="margin: 5px 0 0 0; font-size: 10pt;">CPF: ____________________________</p>
    </div>
  </div>
</div>
`;

    res.status(200).json({
      status: "sucesso",
      contrato: contrato,
      metadata: {
        empresa: empresa.nome,
        valor_total: saldoFase2e3,
        valor_implementacao: valorImplementacao,
        valor_acompanhamento_total: valorAcompanhamentoTotal,
        valor_acompanhamento_mensal: valorAcompanhamentoMensal,
        meses_acompanhamento: MESES_ACOMPANHAMENTO,
        data_geracao: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error("❌ Erro ao gerar contrato de implementação:", error.message);
    res.status(500).json({ 
      erro: "Falha ao gerar contrato",
      detalhe: error.message 
    });
  }
});

// ========================================
// 📦 EXPORTAR DADOS DA EMPRESA
// ========================================

app.get("/api/companies/:id/export", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;

    // 1. Buscar dados da empresa
    const empresaRes = await pool.query("SELECT * FROM empresas WHERE id = $1", [id]);
    if (empresaRes.rows.length === 0) {
      return res.status(404).json({ erro: "Empresa não encontrada" });
    }

    // 2. Buscar linhas
    const linhasRes = await pool.query("SELECT * FROM linhas_producao WHERE empresa_id = $1", [id]);

    // 3. Buscar postos (de todas as linhas da empresa)
    const postosRes = await pool.query(`
      SELECT p.* FROM posto_trabalho p
      JOIN linhas_producao l ON l.id = p.linha_id
      WHERE l.empresa_id = $1
    `, [id]);

    // 4. Buscar cargos
    const cargosRes = await pool.query("SELECT * FROM cargos WHERE empresa_id = $1", [id]);

    // 5. Buscar colaboradores
    const colaboradoresRes = await pool.query("SELECT * FROM colaborador WHERE empresa_id = $1", [id]);

    // 6. Buscar perdas
    const perdasRes = await pool.query(`
      SELECT pl.*, lp.linha_id FROM perdas_linha pl
      JOIN linha_produto lp ON lp.id = pl.linha_produto_id
      WHERE lp.linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1)
    `, [id]);

    // 7. Buscar medições de ciclo
    const medicoesRes = await pool.query(`
      SELECT cm.* FROM ciclo_medicao cm
      JOIN posto_trabalho p ON p.id = cm.posto_id
      JOIN linhas_producao l ON l.id = p.linha_id
      WHERE l.empresa_id = $1
    `, [id]);

    // Montar objeto com todos os dados
    const dados = {
      metadata: {
        exportado_em: new Date().toISOString(),
        empresa_id: parseInt(id),
        empresa_nome: empresaRes.rows[0].nome,
        versao: "1.0"
      },
      empresa: empresaRes.rows[0],
      linhas: linhasRes.rows,
      postos: postosRes.rows,
      cargos: cargosRes.rows,
      colaboradores: colaboradoresRes.rows,
      perdas: perdasRes.rows,
      medicoes: medicoesRes.rows
    };

    // Enviar como arquivo para download
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=backup_empresa_${id}_${Date.now()}.json`);
    res.json(dados);

    console.log(`📦 Backup exportado: Empresa ${empresaRes.rows[0].nome} (ID: ${id})`);

  } catch (error) {
    console.error("❌ Erro ao exportar dados:", error.message);
    res.status(500).json({ erro: "Erro ao exportar dados", detalhe: error.message });
  }
});

// ========================================
// 🗑️ LIMPAR DADOS DA EMPRESA (mantém cadastro)
// ========================================

app.delete("/api/companies/:id/clean", autenticarToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;

    // Verificar se empresa existe
    const empresaRes = await pool.query("SELECT nome FROM empresas WHERE id = $1", [id]);
    if (empresaRes.rows.length === 0) {
      return res.status(404).json({ erro: "Empresa não encontrada" });
    }

    const empresaNome = empresaRes.rows[0].nome;

    await client.query('BEGIN');

    // 1. Remover perdas
    await client.query(`
      DELETE FROM perdas_linha WHERE linha_produto_id IN (
        SELECT id FROM linha_produto WHERE linha_id IN (
          SELECT id FROM linhas_producao WHERE empresa_id = $1
        )
      )
    `, [id]);

    // 2. Remover medições de ciclo
    await client.query(`
      DELETE FROM ciclo_medicao WHERE posto_id IN (
        SELECT id FROM posto_trabalho WHERE linha_id IN (
          SELECT id FROM linhas_producao WHERE empresa_id = $1
        )
      )
    `, [id]);

    // 3. Remover análises de linha
    await client.query(`
      DELETE FROM analise_linha WHERE linha_id IN (
        SELECT id FROM linhas_producao WHERE empresa_id = $1
      )
    `, [id]);

    // 4. Remover postos
    await client.query(`
      DELETE FROM posto_trabalho WHERE linha_id IN (
        SELECT id FROM linhas_producao WHERE empresa_id = $1
      )
    `, [id]);

    // 5. Remover vínculos linha-produto
    await client.query(`
      DELETE FROM linha_produto WHERE linha_id IN (
        SELECT id FROM linhas_producao WHERE empresa_id = $1
      )
    `, [id]);

    // 6. Remover linhas
    await client.query("DELETE FROM linhas_producao WHERE empresa_id = $1", [id]);

    // 7. Remover colaboradores
    await client.query("DELETE FROM colaborador WHERE empresa_id = $1", [id]);

    // 8. Remover cargos
    await client.query("DELETE FROM cargos WHERE empresa_id = $1", [id]);

    await client.query('COMMIT');

    res.json({
      mensagem: `Dados da empresa "${empresaNome}" removidos com sucesso. O cadastro da empresa foi mantido.`
    });

    console.log(`🗑️ Dados limpos: Empresa ${empresaNome} (ID: ${id})`);

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("❌ Erro ao limpar dados:", error.message);
    res.status(500).json({ erro: "Erro ao limpar dados", detalhe: error.message });
  } finally {
    client.release();
  }
});

// ========================================
// 💾 FAZER BACKUP DA EMPRESA (salva no banco)
// ========================================

app.post("/api/companies/:id/backup", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { motivo } = req.body;

    // Verificar se empresa existe
    const empresaRes = await pool.query("SELECT nome FROM empresas WHERE id = $1", [id]);
    if (empresaRes.rows.length === 0) {
      return res.status(404).json({ erro: "Empresa não encontrada" });
    }

    // Buscar todos os dados (mesmo da exportação)
    const linhas = await pool.query("SELECT * FROM linhas_producao WHERE empresa_id = $1", [id]);
    const postos = await pool.query(`
      SELECT p.* FROM posto_trabalho p
      JOIN linhas_producao l ON l.id = p.linha_id
      WHERE l.empresa_id = $1
    `, [id]);
    const cargos = await pool.query("SELECT * FROM cargos WHERE empresa_id = $1", [id]);
    const colaboradores = await pool.query("SELECT * FROM colaborador WHERE empresa_id = $1", [id]);
    const perdas = await pool.query(`
      SELECT pl.* FROM perdas_linha pl
      JOIN linha_produto lp ON lp.id = pl.linha_produto_id
      WHERE lp.linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1)
    `, [id]);
    const medicoes = await pool.query(`
      SELECT cm.* FROM ciclo_medicao cm
      JOIN posto_trabalho p ON p.id = cm.posto_id
      JOIN linhas_producao l ON l.id = p.linha_id
      WHERE l.empresa_id = $1
    `, [id]);

    const dados = {
      metadata: {
        backup_em: new Date().toISOString(),
        empresa_id: parseInt(id),
        empresa_nome: empresaRes.rows[0].nome,
        motivo: motivo || "Backup manual",
        versao: "1.0"
      },
      empresa: { id: parseInt(id), nome: empresaRes.rows[0].nome },
      linhas: linhas.rows,
      postos: postos.rows,
      cargos: cargos.rows,
      colaboradores: colaboradores.rows,
      perdas: perdas.rows,
      medicoes: medicoes.rows
    };

    // Criar tabela de backups se não existir
    await pool.query(`
      CREATE TABLE IF NOT EXISTS backups_empresas (
        id SERIAL PRIMARY KEY,
        empresa_id INTEGER NOT NULL,
        dados JSONB NOT NULL,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        motivo TEXT
      )
    `);

    // Inserir backup
    const result = await pool.query(
      "INSERT INTO backups_empresas (empresa_id, dados, motivo) VALUES ($1, $2, $3) RETURNING id",
      [id, JSON.stringify(dados), motivo || "Backup manual"]
    );

    res.json({
      mensagem: "Backup realizado com sucesso!",
      backup_id: result.rows[0].id,
      data: new Date().toISOString()
    });

    console.log(`💾 Backup criado: Empresa ${empresaRes.rows[0].nome} (ID: ${id}) - Backup ID: ${result.rows[0].id}`);

  } catch (error) {
    console.error("❌ Erro ao fazer backup:", error.message);
    res.status(500).json({ erro: "Erro ao fazer backup", detalhe: error.message });
  }
});

// ========================================
// 📋 LISTAR BACKUPS DE UMA EMPRESA
// ========================================

app.get("/api/companies/:id/backups", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(`
      SELECT id, criado_em, motivo FROM backups_empresas
      WHERE empresa_id = $1
      ORDER BY criado_em DESC
    `, [id]);

    res.json(result.rows);

  } catch (error) {
    console.error("❌ Erro ao listar backups:", error.message);
    res.status(500).json({ erro: "Erro ao listar backups" });
  }
});

// ========================================
// 🔄 RESTAURAR BACKUP
// ========================================

app.post("/api/companies/:id/restore/:backupId", autenticarToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id, backupId } = req.params;

    // Buscar backup
    const backupRes = await pool.query(
      "SELECT dados FROM backups_empresas WHERE id = $1 AND empresa_id = $2",
      [backupId, id]
    );

    if (backupRes.rows.length === 0) {
      return res.status(404).json({ erro: "Backup não encontrado" });
    }

    const dados = backupRes.rows[0].dados;

    await client.query('BEGIN');

    // Limpar dados atuais (mantém empresa)
    await client.query("DELETE FROM perdas_linha WHERE linha_produto_id IN (SELECT id FROM linha_produto WHERE linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1))", [id]);
    await client.query("DELETE FROM ciclo_medicao WHERE posto_id IN (SELECT id FROM posto_trabalho WHERE linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1))", [id]);
    await client.query("DELETE FROM analise_linha WHERE linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1)", [id]);
    await client.query("DELETE FROM posto_trabalho WHERE linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1)", [id]);
    await client.query("DELETE FROM linha_produto WHERE linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1)", [id]);
    await client.query("DELETE FROM linhas_producao WHERE empresa_id = $1", [id]);
    await client.query("DELETE FROM colaborador WHERE empresa_id = $1", [id]);
    await client.query("DELETE FROM cargos WHERE empresa_id = $1", [id]);

    // Restaurar cargos
    for (const cargo of dados.cargos) {
      await client.query(
        "INSERT INTO cargos (id, empresa_id, nome, salario_base, encargos_percentual) VALUES ($1, $2, $3, $4, $5)",
        [cargo.id, id, cargo.nome, cargo.salario_base, cargo.encargos_percentual]
      );
    }

    // Restaurar linhas
    for (const linha of dados.linhas) {
      await client.query(
        "INSERT INTO linhas_producao (id, empresa_id, nome, takt_time_segundos, meta_diaria, horas_disponiveis) VALUES ($1, $2, $3, $4, $5, $6)",
        [linha.id, id, linha.nome, linha.takt_time_segundos, linha.meta_diaria, linha.horas_disponiveis || 8.8]
      );
    }

    // Restaurar postos
    for (const posto of dados.postos) {
      await client.query(
        "INSERT INTO posto_trabalho (id, linha_id, nome, tempo_ciclo_segundos, tempo_setup_minutos, cargo_id, disponibilidade_percentual, ordem_fluxo) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        [posto.id, posto.linha_id, posto.nome, posto.tempo_ciclo_segundos, posto.tempo_setup_minutos, posto.cargo_id, posto.disponibilidade_percentual, posto.ordem_fluxo]
      );
    }

    // Restaurar colaboradores
    for (const colab of dados.colaboradores) {
      await client.query(
        "INSERT INTO colaborador (id, empresa_id, cargo_id, nome) VALUES ($1, $2, $3, $4)",
        [colab.id, id, colab.cargo_id, colab.nome]
      );
    }

    // Restaurar perdas
    for (const perda of dados.perdas) {
      // Buscar linha_produto_id correspondente
      const lpRes = await client.query(
        "SELECT id FROM linha_produto WHERE linha_id = $1",
        [perda.linha_id]
      );
      if (lpRes.rows.length > 0) {
        await client.query(
          "INSERT INTO perdas_linha (id, linha_produto_id, microparadas_minutos, retrabalho_pecas, refugo_pecas, data_perda) VALUES ($1, $2, $3, $4, $5, $6)",
          [perda.id, lpRes.rows[0].id, perda.microparadas_minutos, perda.retrabalho_pecas, perda.refugo_pecas, perda.data_perda]
        );
      }
    }

    // Restaurar medições
    for (const med of dados.medicoes) {
      await client.query(
        "INSERT INTO ciclo_medicao (id, posto_id, tempo_ciclo_segundos, data_medicao) VALUES ($1, $2, $3, $4)",
        [med.id, med.posto_id, med.tempo_ciclo_segundos, med.data_medicao]
      );
    }

    await client.query('COMMIT');

    res.json({ mensagem: "Backup restaurado com sucesso!" });

    console.log(`🔄 Backup restaurado: Empresa ID ${id}, Backup ID ${backupId}`);

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("❌ Erro ao restaurar backup:", error.message);
    res.status(500).json({ erro: "Erro ao restaurar backup", detalhe: error.message });
  } finally {
    client.release();
  }
});

// ========================================
// ⏱️ REGISTRO DE HORAS TRABALHADAS
// ========================================

// Listar horas do mês atual
app.get("/api/horas", autenticarToken, async (req, res) => {
  try {
    const { ano, mes } = req.query;
    const anoAtual = ano || new Date().getFullYear();
    const mesAtual = mes || (new Date().getMonth() + 1);
    
    const result = await pool.query(`
      SELECT * FROM registro_horas 
      WHERE EXTRACT(YEAR FROM data) = $1 
      AND EXTRACT(MONTH FROM data) = $2
      ORDER BY data DESC
    `, [anoAtual, mesAtual]);
    
    res.json(result.rows);
  } catch (error) {
    console.error("❌ Erro ao buscar horas:", error.message);
    res.status(500).json({ erro: "Erro ao buscar horas" });
  }
});

// Registrar horas trabalhadas
app.post("/api/horas", autenticarToken, async (req, res) => {
  const { data, horas, tipo, descricao, projeto_id } = req.body;
  
  if (!horas || horas <= 0) {
    return res.status(400).json({ erro: "Horas é obrigatório e deve ser maior que zero" });
  }
  
  try {
    const result = await pool.query(`
      INSERT INTO registro_horas (data, horas, tipo, descricao, projeto_id)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `, [data, horas, tipo || 'faturável', descricao || null, projeto_id || null]);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro ao registrar horas:", error.message);
    res.status(500).json({ erro: "Erro ao registrar horas" });
  }
});

// Resumo de horas do mês
app.get("/api/horas/resumo", autenticarToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        COALESCE(SUM(horas), 0) as total_horas,
        COALESCE(SUM(CASE WHEN tipo = 'faturável' THEN horas ELSE 0 END), 0) as horas_faturaveis,
        COALESCE(SUM(CASE WHEN tipo = 'administrativo' THEN horas ELSE 0 END), 0) as horas_administrativas,
        COUNT(*) as total_registros
      FROM registro_horas 
      WHERE EXTRACT(YEAR FROM data) = EXTRACT(YEAR FROM CURRENT_DATE)
      AND EXTRACT(MONTH FROM data) = EXTRACT(MONTH FROM CURRENT_DATE)
    `);
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro ao buscar resumo de horas:", error.message);
    res.status(500).json({ erro: "Erro ao buscar resumo" });
  }
});

// ========================================
// 🎯 MÓDULO: GESTÃO DE LEADS (PROSPECÇÃO) - CORRIGIDO
// ========================================

/**
 * 1️⃣ LISTAR TODOS OS LEADS
 */
app.get("/api/leads", autenticarToken, async (req, res) => {
  try {
    const { status, consultor_id, data_inicio, data_fim } = req.query;
    
    let query = `
      SELECT l.*, u.nome as consultor_nome,
        (SELECT COUNT(*) FROM interacoes_leads WHERE lead_id = l.id) as total_interacoes
      FROM leads l
      LEFT JOIN usuarios u ON u.id = l.consultor_id
      WHERE 1=1
    `;
    
    const values = [];
    let paramIndex = 1;
    
    if (status) {
      query += ` AND l.status = $${paramIndex}`;
      values.push(status);
      paramIndex++;
    }
    
    if (consultor_id) {
      query += ` AND l.consultor_id = $${paramIndex}`;
      values.push(consultor_id);
      paramIndex++;
    }
    
    if (data_inicio) {
      query += ` AND l.data_criacao >= $${paramIndex}`;
      values.push(data_inicio);
      paramIndex++;
    }
    
    if (data_fim) {
      query += ` AND l.data_criacao <= $${paramIndex}`;
      values.push(data_fim);
      paramIndex++;
    }
    
    query += ` ORDER BY l.ultimo_contato DESC NULLS LAST, l.data_criacao DESC`;
    
    const result = await pool.query(query, values);
    res.json(result.rows);
    
  } catch (error) {
    console.error("❌ Erro ao buscar leads:", error.message);
    res.status(500).json({ erro: "Erro ao buscar leads" });
  }
});

/**
 * 2️⃣ BUSCAR LEAD POR ID
 */
app.get("/api/leads/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  
  try {
    const leadResult = await pool.query(`
      SELECT l.*, u.nome as consultor_nome
      FROM leads l
      LEFT JOIN usuarios u ON u.id = l.consultor_id
      WHERE l.id = $1
    `, [id]);
    
    if (leadResult.rows.length === 0) {
      return res.status(404).json({ erro: "Lead não encontrado" });
    }
    
    const interacoesResult = await pool.query(`
      SELECT i.*, u.nome as criado_por_nome
      FROM interacoes_leads i
      LEFT JOIN usuarios u ON u.id = i.criado_por
      WHERE i.lead_id = $1
      ORDER BY i.data DESC, i.hora DESC
    `, [id]);
    
    res.json({
      ...leadResult.rows[0],
      interacoes: interacoesResult.rows
    });
    
  } catch (error) {
    console.error("❌ Erro ao buscar lead:", error.message);
    res.status(500).json({ erro: "Erro ao buscar lead" });
  }
});

/**
 * 3️⃣ CRIAR NOVO LEAD
 */
app.post("/api/leads", autenticarToken, async (req, res) => {
  const {
    nome, cnpj, contato_nome, contato_email, contato_telefone,
    fonte, status, potencial_faturamento,
    ultimo_contato, proximo_contato, observacoes
  } = req.body;
  
  if (!nome) {
    return res.status(400).json({ erro: "Nome do lead é obrigatório" });
  }
  
  try {
    const potencial = parseFloat(potencial_faturamento) || 0;
    
    const result = await pool.query(`
      INSERT INTO leads (
        nome, cnpj, contato_nome, contato_email, contato_telefone,
        fonte, status, potencial_faturamento,
        ultimo_contato, proximo_contato, observacoes, consultor_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *
    `, [
      nome, 
      cnpj || null, 
      contato_nome || null, 
      contato_email || null, 
      contato_telefone || null,
      fonte || 'indicação', 
      status || 'prospecção',
      potencial,
      ultimo_contato || null, 
      proximo_contato || null,
      observacoes || null,
      req.usuario.id
    ]);
    
    res.status(201).json(result.rows[0]);
    
  } catch (error) {
    console.error("❌ Erro ao criar lead:", error.message);
    res.status(500).json({ erro: "Erro ao criar lead", detalhe: error.message });
  }
});

/**
 * 4️⃣ ATUALIZAR LEAD
 */
app.put("/api/leads/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const {
    nome, cnpj, contato_nome, contato_email, contato_telefone,
    fonte, status, potencial_faturamento,
    ultimo_contato, proximo_contato, observacoes, consultor_id
  } = req.body;
  
  try {
    const result = await pool.query(`
      UPDATE leads SET
        nome = COALESCE($1, nome),
        cnpj = COALESCE($2, cnpj),
        contato_nome = COALESCE($3, contato_nome),
        contato_email = COALESCE($4, contato_email),
        contato_telefone = COALESCE($5, contato_telefone),
        fonte = COALESCE($6, fonte),
        status = COALESCE($7, status),
        potencial_faturamento = COALESCE($8, potencial_faturamento),
        ultimo_contato = COALESCE($9, ultimo_contato),
        proximo_contato = COALESCE($10, proximo_contato),
        observacoes = COALESCE($11, observacoes),
        consultor_id = COALESCE($12, consultor_id),
        data_atualizacao = CURRENT_TIMESTAMP
      WHERE id = $13
      RETURNING *
    `, [
      nome, cnpj, contato_nome, contato_email, contato_telefone,
      fonte, status, potencial_faturamento,
      ultimo_contato, proximo_contato, observacoes, consultor_id, id
    ]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Lead não encontrado" });
    }
    
    res.json(result.rows[0]);
    
  } catch (error) {
    console.error("❌ Erro ao atualizar lead:", error.message);
    res.status(500).json({ erro: "Erro ao atualizar lead" });
  }
});

/**
 * 5️⃣ REGISTRAR INTERAÇÃO COM LEAD
 */
app.post("/api/leads/:id/interacoes", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { tipo, descricao, data, hora } = req.body;
  
  if (!tipo) {
    return res.status(400).json({ erro: "Tipo de interação é obrigatório" });
  }
  
  const criado_por = req.usuario?.id;
  
  if (!criado_por) {
    return res.status(401).json({ erro: "Usuário não identificado" });
  }
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const userCheck = await client.query(
      "SELECT id FROM usuarios WHERE id = $1",
      [criado_por]
    );
    
    if (userCheck.rows.length === 0) {
      throw new Error(`Usuário ID ${criado_por} não existe no banco de dados`);
    }
    
    const leadCheck = await client.query(
      "SELECT id FROM leads WHERE id = $1",
      [id]
    );
    
    if (leadCheck.rows.length === 0) {
      throw new Error(`Lead ID ${id} não existe`);
    }
    
    // 🔥 CORREÇÃO DEFINITIVA: SEM timezone, SEM ISO
    let dataFormatada;

    if (data) {
      dataFormatada = data.split('T')[0];
    } else {
      const hoje = new Date();
      const ano = hoje.getFullYear();
      const mes = String(hoje.getMonth() + 1).padStart(2, '0');
      const dia = String(hoje.getDate()).padStart(2, '0');

      dataFormatada = `${ano}-${mes}-${dia}`;
    }
    
    const query = `
      INSERT INTO interacoes_leads (lead_id, tipo, descricao, data, hora, criado_por, criado_em)
      VALUES ($1, $2, $3, $4::date, $5, $6, CURRENT_TIMESTAMP)
      RETURNING *
    `;
    
    const values = [
      id, 
      tipo, 
      descricao || null, 
      dataFormatada,
      hora || new Date().toLocaleTimeString('pt-BR', { hour12: false }), 
      criado_por
    ];
    
    const result = await client.query(query, values);
    
    await client.query(
      `UPDATE leads SET 
        ultimo_contato = $1::date,
        data_atualizacao = CURRENT_TIMESTAMP
      WHERE id = $2`,
      [dataFormatada, id]
    );
    
    await client.query('COMMIT');
    
    console.log(`✅ Interação registrada - Lead: ${id}, Data: ${dataFormatada}`);
    res.status(201).json(result.rows[0]);
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error("❌ Erro ao registrar interação:", error.message);
    res.status(500).json({ 
      erro: "Erro ao registrar interação", 
      detalhes: error.message 
    });
  } finally {
    client.release();
  }
});

/**
 * 6️⃣ DELETAR LEAD
 */
app.delete("/api/leads/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query(
      "DELETE FROM leads WHERE id = $1 RETURNING nome",
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Lead não encontrado" });
    }
    
    res.json({ mensagem: `Lead "${result.rows[0].nome}" removido com sucesso` });
    
  } catch (error) {
    console.error("❌ Erro ao deletar lead:", error.message);
    res.status(500).json({ erro: "Erro ao deletar lead" });
  }
});

/**
 * 7️⃣ DASHBOARD DE LEADS (MÉTRICAS) - CORRIGIDO
 */
app.get("/api/leads/dashboard/metrics", autenticarToken, async (req, res) => {
  try {
    const metrics = await pool.query(`
      SELECT 
        COUNT(*) as total_leads,
        COUNT(*) FILTER (WHERE status = 'prospecção') as em_prospeccao,
        COUNT(*) FILTER (WHERE status = 'diagnostico_autorizado') as diagnostico_autorizado,
        COUNT(*) FILTER (WHERE status = 'diagnostico_entregue') as diagnostico_entregue,
        COUNT(*) FILTER (WHERE status = 'negociacao') as negociacao,
        COUNT(*) FILTER (WHERE status = 'contrato_assinado') as contrato_assinado,
        COUNT(*) FILTER (WHERE status = 'perdido') as perdidos,
        COALESCE(SUM(potencial_faturamento) FILTER (WHERE status NOT IN ('perdido', 'contrato_assinado')), 0) as pipeline_total
      FROM leads
    `);
    
    const proximosContatos = await pool.query(`
      SELECT id, nome, proximo_contato, contato_nome, contato_telefone
      FROM leads
      WHERE proximo_contato BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '7 days'
      AND status NOT IN ('contrato_assinado', 'perdido')
      ORDER BY proximo_contato ASC
      LIMIT 10
    `);
    
    res.json({
      ...metrics.rows[0],
      proximos_contatos: proximosContatos.rows
    });
    
  } catch (error) {
    console.error("❌ Erro ao buscar métricas de leads:", error.message);
    res.status(500).json({ erro: "Erro ao buscar métricas" });
  }
});

/**
 * EDITAR INTERAÇÃO
 */
app.put("/api/leads/interacoes/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { tipo, descricao, data, hora } = req.body;
  
  if (!tipo) {
    return res.status(400).json({ erro: "Tipo de interação é obrigatório" });
  }
  
  try {
    const result = await pool.query(
      `UPDATE interacoes_leads 
       SET tipo = $1, 
           descricao = $2, 
           data = $3::date, 
           hora = $4
       WHERE id = $5
       RETURNING *`,
      [tipo, descricao, data, hora, id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Interação não encontrada" });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro ao editar interação:", error.message);
    res.status(500).json({ erro: "Erro ao editar interação" });
  }
});

/**
 * EXCLUIR INTERAÇÃO
 */
app.delete("/api/leads/interacoes/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query(
      "DELETE FROM interacoes_leads WHERE id = $1 RETURNING id",
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Interação não encontrada" });
    }
    
    res.json({ mensagem: "Interação excluída com sucesso" });
  } catch (error) {
    console.error("❌ Erro ao excluir interação:", error.message);
    res.status(500).json({ erro: "Erro ao excluir interação" });
  }
});

// ========================================
// ✅ MÓDULO: TAREFAS EDITÁVEIS (DASHBOARD)
// ========================================

/**
 * 1️⃣ LISTAR TAREFAS DO CONSULTOR
 */
app.get("/api/tarefas", autenticarToken, async (req, res) => {
  try {
    const { status, prioridade, categoria, cliente_id, data_inicio, data_fim } = req.query;
    const usuario_id = req.usuario.id;
    
    let query = `
      SELECT t.*, e.nome as cliente_nome
      FROM tarefas_consultor t
      LEFT JOIN empresas e ON e.id = t.cliente_id
      WHERE t.usuario_id = $1
    `;
    
    const values = [usuario_id];
    let paramIndex = 2;
    
    if (status) {
      query += ` AND t.status = $${paramIndex}`;
      values.push(status);
      paramIndex++;
    }
    
    if (prioridade) {
      query += ` AND t.prioridade = $${paramIndex}`;
      values.push(prioridade);
      paramIndex++;
    }
    
    if (categoria) {
      query += ` AND t.categoria = $${paramIndex}`;
      values.push(categoria);
      paramIndex++;
    }
    
    if (cliente_id) {
      query += ` AND t.cliente_id = $${paramIndex}`;
      values.push(cliente_id);
      paramIndex++;
    }
    
    if (data_inicio) {
      query += ` AND t.data_limite >= $${paramIndex}`;
      values.push(data_inicio);
      paramIndex++;
    }
    
    if (data_fim) {
      query += ` AND t.data_limite <= $${paramIndex}`;
      values.push(data_fim);
      paramIndex++;
    }
    
    query += ` ORDER BY 
      CASE t.prioridade 
        WHEN 'alta' THEN 1 
        WHEN 'media' THEN 2 
        WHEN 'baixa' THEN 3 
      END ASC,
      t.data_limite ASC NULLS LAST,
      t.created_at DESC`;
    
    const result = await pool.query(query, values);
    res.json(result.rows);
    
  } catch (error) {
    console.error("❌ Erro ao buscar tarefas:", error.message);
    res.status(500).json({ erro: "Erro ao buscar tarefas" });
  }
});

/**
 * 2️⃣ CRIAR NOVA TAREFA
 */
app.post("/api/tarefas", autenticarToken, async (req, res) => {
  const { titulo, descricao, prioridade, status, data_limite, categoria, cliente_id } = req.body;
  const usuario_id = req.usuario.id;
  
  if (!titulo) {
    return res.status(400).json({ erro: "Título da tarefa é obrigatório" });
  }
  
  try {
    const result = await pool.query(`
      INSERT INTO tarefas_consultor 
      (usuario_id, titulo, descricao, prioridade, status, data_limite, categoria, cliente_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `, [
      usuario_id, titulo, descricao || null,
      prioridade || 'media', status || 'pendente',
      data_limite || null, categoria || 'geral', cliente_id || null
    ]);
    
    res.status(201).json(result.rows[0]);
    
  } catch (error) {
    console.error("❌ Erro ao criar tarefa:", error.message);
    res.status(500).json({ erro: "Erro ao criar tarefa" });
  }
});

/**
 * 3️⃣ ATUALIZAR TAREFA
 */
app.put("/api/tarefas/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { titulo, descricao, prioridade, status, data_limite, categoria, cliente_id } = req.body;
  const usuario_id = req.usuario.id;
  
  try {
    const checkResult = await pool.query(
      "SELECT id FROM tarefas_consultor WHERE id = $1 AND usuario_id = $2",
      [id, usuario_id]
    );
    
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ erro: "Tarefa não encontrada" });
    }
    
    let dataConclusao = null;
    if (status === 'concluida') {
      dataConclusao = new Date().toISOString().split('T')[0];
    }
    
    const result = await pool.query(`
      UPDATE tarefas_consultor SET
        titulo = COALESCE($1, titulo),
        descricao = COALESCE($2, descricao),
        prioridade = COALESCE($3, prioridade),
        status = COALESCE($4, status),
        data_limite = COALESCE($5, data_limite),
        categoria = COALESCE($6, categoria),
        cliente_id = COALESCE($7, cliente_id),
        data_conclusao = COALESCE($8, data_conclusao),
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $9 AND usuario_id = $10
      RETURNING *
    `, [
      titulo, descricao, prioridade, status,
      data_limite, categoria, cliente_id, dataConclusao, id, usuario_id
    ]);
    
    res.json(result.rows[0]);
    
  } catch (error) {
    console.error("❌ Erro ao atualizar tarefa:", error.message);
    res.status(500).json({ erro: "Erro ao atualizar tarefa" });
  }
});

/**
 * 4️⃣ ALTERNAR STATUS DA TAREFA
 */
app.patch("/api/tarefas/:id/toggle", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const usuario_id = req.usuario.id;
  
  try {
    const tarefa = await pool.query(
      "SELECT status FROM tarefas_consultor WHERE id = $1 AND usuario_id = $2",
      [id, usuario_id]
    );
    
    if (tarefa.rows.length === 0) {
      return res.status(404).json({ erro: "Tarefa não encontrada" });
    }
    
    const novoStatus = tarefa.rows[0].status === 'concluida' ? 'pendente' : 'concluida';
    const dataConclusao = novoStatus === 'concluida' ? new Date().toISOString().split('T')[0] : null;
    
    const result = await pool.query(`
      UPDATE tarefas_consultor SET
        status = $1,
        data_conclusao = $2,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $3 AND usuario_id = $4
      RETURNING *
    `, [novoStatus, dataConclusao, id, usuario_id]);
    
    res.json(result.rows[0]);
    
  } catch (error) {
    console.error("❌ Erro ao alternar status:", error.message);
    res.status(500).json({ erro: "Erro ao alternar status" });
  }
});

/**
 * 5️⃣ DELETAR TAREFA
 */
app.delete("/api/tarefas/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const usuario_id = req.usuario.id;
  
  try {
    const result = await pool.query(
      "DELETE FROM tarefas_consultor WHERE id = $1 AND usuario_id = $2 RETURNING titulo",
      [id, usuario_id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Tarefa não encontrada" });
    }
    
    res.json({ mensagem: `Tarefa "${result.rows[0].titulo}" removida com sucesso` });
    
  } catch (error) {
    console.error("❌ Erro ao deletar tarefa:", error.message);
    res.status(500).json({ erro: "Erro ao deletar tarefa" });
  }
});

/**
 * 6️⃣ RESUMO DE TAREFAS
 */
app.get("/api/tarefas/resumo", autenticarToken, async (req, res) => {
  const usuario_id = req.usuario.id;
  
  try {
    const result = await pool.query(`
      SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE status = 'pendente') as pendentes,
        COUNT(*) FILTER (WHERE status = 'em_andamento') as em_andamento,
        COUNT(*) FILTER (WHERE status = 'concluida') as concluidas,
        COUNT(*) FILTER (WHERE prioridade = 'alta' AND status != 'concluida') as alta_prioridade,
        COUNT(*) FILTER (WHERE data_limite < CURRENT_DATE AND status != 'concluida') as atrasadas
      FROM tarefas_consultor
      WHERE usuario_id = $1
    `, [usuario_id]);
    
    const proximas = await pool.query(`
      SELECT id, titulo, data_limite, prioridade
      FROM tarefas_consultor
      WHERE usuario_id = $1 
        AND status != 'concluida'
        AND data_limite BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '7 days'
      ORDER BY data_limite ASC, prioridade ASC
      LIMIT 5
    `, [usuario_id]);
    
    res.json({
      ...result.rows[0],
      proximas_tarefas: proximas.rows
    });
    
  } catch (error) {
    console.error("❌ Erro ao buscar resumo de tarefas:", error.message);
    res.status(500).json({ erro: "Erro ao buscar resumo" });
  }
});

// ========================================
// 📋 MÓDULO: CHECKLIST DE PROJETOS
// ========================================

/**
 * 1️⃣ BUSCAR PROJETO COM FASES E ITENS
 */
app.get("/api/checklist/projeto/:projetoId", autenticarToken, async (req, res) => {
  const { projetoId } = req.params;

  try {
    const projetoRes = await pool.query(
      "SELECT * FROM projetos_checklist WHERE id = $1",
      [projetoId]
    );

    if (projetoRes.rowCount === 0) {
      return res.status(404).json({ erro: "Projeto não encontrado" });
    }

    const projeto = projetoRes.rows[0];

    const fasesRes = await pool.query(
      `SELECT f.*, 
        COALESCE(
          json_agg(
            json_build_object(
              'id', i.id,
              'descricao', i.descricao,
              'concluido', i.concluido,
              'ordem', i.ordem,
              'data_conclusao', i.data_conclusao,
              'observacao', i.observacao
            ) ORDER BY i.ordem
          ) FILTER (WHERE i.id IS NOT NULL), 
          '[]'
        ) as itens
       FROM fases_checklist f
       LEFT JOIN itens_checklist i ON i.fase_id = f.id
       WHERE f.projeto_id = $1
       GROUP BY f.id
       ORDER BY f.ordem`,
      [projetoId]
    );

    res.status(200).json({
      projeto,
      fases: fasesRes.rows
    });

  } catch (error) {
    console.error("❌ Erro ao buscar projeto:", error.message);
    res.status(500).json({ erro: "Erro ao carregar projeto" });
  }
});

/**
 * 2️⃣ CRIAR PROJETO
 */
app.post("/api/checklist/projeto", autenticarToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { empresa_id, nome, data_inicio, data_previsao } = req.body;

    if (!empresa_id || !nome || !data_previsao) {
      return res.status(400).json({ erro: "Empresa, nome e previsão são obrigatórios." });
    }

    await client.query('BEGIN');

    const projetoRes = await client.query(
      `INSERT INTO projetos_checklist 
       (empresa_id, nome, data_inicio, data_previsao, status, progresso) 
       VALUES ($1, $2, $3, $4, 'em_andamento', 0) 
       RETURNING *`,
      [empresa_id, nome, data_inicio || new Date(), data_previsao]
    );
    
    const projeto = projetoRes.rows[0];

    const fases = [
      { nome: 'Fase 1 - Diagnóstico', ordem: 1 },
      { nome: 'Fase 2 - Implementação', ordem: 2 },
      { nome: 'Fase 3 - Sustentação', ordem: 3 }
    ];

    for (const fase of fases) {
      await client.query(
        `INSERT INTO fases_checklist (projeto_id, nome, ordem, status, progresso)
         VALUES ($1, $2, $3, 'pendente', 0)`,
        [projeto.id, fase.nome, fase.ordem]
      );
    }

    await client.query('COMMIT');
    
    res.status(201).json({
      mensagem: "Projeto criado com sucesso!",
      projeto
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("❌ Erro ao criar projeto:", error.message);
    res.status(500).json({ erro: "Erro ao criar projeto" });
  } finally {
    client.release();
  }
});

/**
 * 3️⃣ ADICIONAR ITEM À FASE
 */
app.post("/api/checklist/item", autenticarToken, async (req, res) => {
  const { fase_id, descricao, ordem } = req.body;

  if (!fase_id || !descricao) {
    return res.status(400).json({ erro: "Fase e descrição são obrigatórios." });
  }

  try {
    const result = await pool.query(
      `INSERT INTO itens_checklist (fase_id, descricao, ordem, concluido)
       VALUES ($1, $2, $3, false)
       RETURNING *`,
      [fase_id, descricao, ordem || 1]
    );

    res.status(201).json({
      mensagem: "Item adicionado com sucesso!",
      item: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro ao adicionar item:", error.message);
    res.status(500).json({ erro: "Erro ao adicionar item" });
  }
});

/**
 * 4️⃣ ATUALIZAR ITEM
 */
app.put("/api/checklist/item/:itemId", autenticarToken, async (req, res) => {
  const { itemId } = req.params;
  const { concluido, descricao } = req.body;

  try {
    let query, values;

    if (concluido !== undefined) {
      query = `
        UPDATE itens_checklist 
        SET concluido = $1, 
            data_conclusao = CASE WHEN $1 = true THEN CURRENT_DATE ELSE NULL END
        WHERE id = $2
        RETURNING *
      `;
      values = [concluido, itemId];
    } else {
      query = `
        UPDATE itens_checklist 
        SET descricao = $1
        WHERE id = $2
        RETURNING *
      `;
      values = [descricao, itemId];
    }

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Item não encontrado" });
    }

    res.status(200).json({
      mensagem: "Item atualizado com sucesso!",
      item: result.rows[0]
    });

  } catch (error) {
    console.error("❌ Erro ao atualizar item:", error.message);
    res.status(500).json({ erro: "Erro ao atualizar item" });
  }
});

/**
 * 6️⃣ DELETAR PROJETO
 */
app.delete("/api/checklist/projeto/:projetoId", autenticarToken, async (req, res) => {
  const { projetoId } = req.params;

  try {
    const result = await pool.query(
      "DELETE FROM projetos_checklist WHERE id = $1 RETURNING nome",
      [projetoId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Projeto não encontrado" });
    }

    res.status(200).json({
      mensagem: `Projeto "${result.rows[0].nome}" removido com sucesso!`
    });

  } catch (error) {
    console.error("❌ Erro ao deletar projeto:", error.message);
    res.status(500).json({ erro: "Erro ao deletar projeto" });
  }
});

// ========================================
// 📋 MÓDULO: ELEMENTOS DE TRABALHO (CRONOANÁLISE DETALHADA)
// ========================================

// Listar elementos por posto
app.get("/api/elementos/:postoId", autenticarToken, async (req, res) => {
  try {
    const { postoId } = req.params;
    const result = await pool.query(
      "SELECT * FROM elementos_trabalho WHERE posto_id = $1 ORDER BY ordem ASC",
      [postoId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error("❌ Erro ao buscar elementos:", error.message);
    res.status(500).json({ erro: "Erro ao buscar elementos" });
  }
});

// Criar elemento
app.post("/api/elementos", autenticarToken, async (req, res) => {
  const { posto_id, nome, descricao, tempo_padrao_segundos, ordem, tipo } = req.body;
  
  if (!posto_id || !nome) {
    return res.status(400).json({ erro: "Posto e nome são obrigatórios" });
  }
  
  try {
    const result = await pool.query(
      `INSERT INTO elementos_trabalho 
       (posto_id, nome, descricao, tempo_padrao_segundos, ordem, tipo)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [posto_id, nome, descricao || null, tempo_padrao_segundos || 0, ordem || 1, tipo || 'manual']
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro ao criar elemento:", error.message);
    res.status(500).json({ erro: "Erro ao criar elemento" });
  }
});

// Atualizar elemento
app.put("/api/elementos/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { nome, descricao, tempo_padrao_segundos, ordem, tipo } = req.body;
  
  try {
    const result = await pool.query(
      `UPDATE elementos_trabalho SET
        nome = COALESCE($1, nome),
        descricao = COALESCE($2, descricao),
        tempo_padrao_segundos = COALESCE($3, tempo_padrao_segundos),
        ordem = COALESCE($4, ordem),
        tipo = COALESCE($5, tipo),
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $6
      RETURNING *`,
      [nome, descricao, tempo_padrao_segundos, ordem, tipo, id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Elemento não encontrado" });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error("❌ Erro ao atualizar elemento:", error.message);
    res.status(500).json({ erro: "Erro ao atualizar elemento" });
  }
});

// Deletar elemento
app.delete("/api/elementos/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query(
      "DELETE FROM elementos_trabalho WHERE id = $1 RETURNING nome",
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Elemento não encontrado" });
    }
    
    res.json({ mensagem: `Elemento "${result.rows[0].nome}" removido` });
  } catch (error) {
    console.error("❌ Erro ao deletar elemento:", error.message);
    res.status(500).json({ erro: "Erro ao deletar elemento" });
  }
});

// ========================================
// 📊 MÓDULO: EFICIÊNCIA DO POSTO (para gargalo)
// ========================================

/**
 * ROTA: CALCULAR EFICIÊNCIA DE UM POSTO
 */
app.get("/api/station-efficiency/:postoId", autenticarToken, async (req, res) => {
  try {
    const { postoId } = req.params;

    const postoRes = await pool.query(`
      SELECT pt.*, l.takt_time_segundos, l.meta_diaria
      FROM posto_trabalho pt
      JOIN linhas_producao l ON l.id = pt.linha_id
      WHERE pt.id = $1
    `, [postoId]);

    if (postoRes.rows.length === 0) {
      return res.status(404).json({ erro: "Posto não encontrado" });
    }

    const posto = postoRes.rows[0];
    const taktAlvo = parseFloat(posto.takt_time_segundos) || 0;
    const tempoCiclo = parseFloat(posto.tempo_ciclo_segundos) || 0;
    const disponibilidade = (parseFloat(posto.disponibilidade_percentual) || 100) / 100;

    let eficiencia = 0;
    let classificacao = "Sem dados";

    if (taktAlvo > 0 && tempoCiclo > 0) {
      const cicloReal = tempoCiclo / disponibilidade;
      eficiencia = Math.min(100, Math.round((taktAlvo / cicloReal) * 100));

      if (eficiencia >= 90) classificacao = "Excelente";
      else if (eficiencia >= 75) classificacao = "Bom";
      else if (eficiencia >= 60) classificacao = "Regular";
      else classificacao = "Crítico";
    }

    const medicoesRes = await pool.query(`
      SELECT tempo_ciclo_segundos, data_medicao
      FROM ciclo_medicao
      WHERE posto_id = $1
        AND data_medicao >= CURRENT_DATE - INTERVAL '30 days'
      ORDER BY data_medicao DESC
      LIMIT 50
    `, [postoId]);

    let estabilidade = "Estável";
    if (medicoesRes.rows.length >= 10) {
      const tempos = medicoesRes.rows.map(m => parseFloat(m.tempo_ciclo_segundos));
      const media = tempos.reduce((a, b) => a + b, 0) / tempos.length;
      const desvio = Math.sqrt(tempos.reduce((a, b) => a + Math.pow(b - media, 2), 0) / tempos.length);
      const cv = media > 0 ? (desvio / media) * 100 : 0;
      
      if (cv > 20) estabilidade = "Instável";
      else if (cv > 10) estabilidade = "Estabilidade moderada";
    }

    const perdasRes = await pool.query(`
      SELECT 
        COALESCE(SUM(pl.microparadas_minutos), 0) as microparadas,
        COALESCE(SUM(pl.refugo_pecas), 0) as refugo
      FROM perdas_linha pl
      JOIN linha_produto lp ON lp.id = pl.linha_produto_id
      JOIN posto_trabalho pt ON pt.linha_id = lp.linha_id
      WHERE pt.id = $1
        AND pl.data_perda >= CURRENT_DATE - INTERVAL '30 days'
    `, [postoId]);

    const perdas = perdasRes.rows[0];

    res.status(200).json({
      posto_id: parseInt(postoId),
      posto_nome: posto.nome,
      eficiencia_percentual: eficiencia,
      classificacao: classificacao,
      estabilidade: estabilidade,
      tempo_ciclo_segundos: tempoCiclo,
      disponibilidade_percentual: posto.disponibilidade_percentual || 100,
      takt_alvo_segundos: taktAlvo,
      ultimas_medicoes: medicoesRes.rows.length,
      perdas_30dias: {
        microparadas_minutos: parseFloat(perdas.microparadas) || 0,
        refugo_pecas: parseInt(perdas.refugo) || 0
      },
      recomendacao: eficiencia < 60 ? "Intervenção urgente necessária" :
                     eficiencia < 75 ? "Otimização recomendada" :
                     eficiencia < 90 ? "Monitoramento periódico" :
                     "Manter padrão atual"
    });

  } catch (error) {
    console.error("❌ Erro ao calcular eficiência do posto:", error.message);
    res.status(500).json({ 
      erro: "Erro ao calcular eficiência do posto",
      detalhe: error.message 
    });
  }
});

// ========================================
// 🚀 ROTA UNIFICADA: TODOS OS DADOS DA EMPRESA (CORRIGIDA)
// ========================================

app.get("/api/company/:empresaId/dashboard", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;

  try {
    const empresaRes = await pool.query(
      "SELECT id, nome, cnpj, segmento, dias_produtivos_mes FROM empresas WHERE id = $1",
      [empresaId]
    );
    
    if (empresaRes.rows.length === 0) {
      return res.status(404).json({ erro: "Empresa não encontrada" });
    }
    
    const empresa = empresaRes.rows[0];
    const diasMes = empresa.dias_produtivos_mes || 22;
    const horasDia = 8;

    const linhasRes = await pool.query(
      "SELECT * FROM linhas_producao WHERE empresa_id = $1 ORDER BY nome",
      [empresaId]
    );
    const linhas = linhasRes.rows;

    if (linhas.length === 0) {
      return res.json({
        empresa,
        linhas: [],
        resumo: {
          totalLinhas: 0,
          totalColaboradores: 0,
          totalAlocacoesAtivas: 0,
          custoMaoObra: 0,
          faturamento: 0,
          perdas: { setup: 0, micro: 0, refugo: 0, total: 0 },
          oeeMedio: 0,
          roi: { investimento: 50000, ganhoMensal: 0, payback: 0, roiAnual: 0 }
        },
        colaboradores: [],
        alocacoes: [],
        evolucao: []
      });
    }

    const cargosRes = await pool.query(
      "SELECT * FROM cargos WHERE empresa_id = $1",
      [empresaId]
    );
    const cargos = cargosRes.rows;

    const colaboradoresRes = await pool.query(`
      SELECT c.id, c.nome, ca.nome as cargo_nome, ca.salario_base, ca.encargos_percentual
      FROM colaborador c
      LEFT JOIN cargos ca ON ca.id = c.cargo_id
      WHERE c.empresa_id = $1
    `, [empresaId]);

    const alocacoesRes = await pool.query(`
      SELECT a.id, a.colaborador_id, a.posto_id, a.turno, a.ativo,
        c.nome as colaborador_nome,
        pt.nome as posto_nome,
        l.nome as linha_nome
      FROM alocacao_colaborador a
      JOIN colaborador c ON c.id = a.colaborador_id
      JOIN posto_trabalho pt ON pt.id = a.posto_id
      JOIN linhas_producao l ON l.id = pt.linha_id
      WHERE a.ativo = true AND l.empresa_id = $1
    `, [empresaId]);

    let custoTotalMaoObra = 0;
    let faturamentoTotal = 0;
    let perdasSetupTotal = 0;
    let perdasMicroTotal = 0;
    let perdasRefugoTotal = 0;
    let listaOEE = [];
    const detalhamentoLinhas = [];

    for (const linha of linhas) {
      const postosRes = await pool.query(
        "SELECT * FROM posto_trabalho WHERE linha_id = $1 ORDER BY ordem_fluxo",
        [linha.id]
      );
      const postos = postosRes.rows;

      let custoLinha = 0;
      const alocacoesLinha = alocacoesRes.rows.filter(a => a.linha_nome === linha.nome);
      for (const aloc of alocacoesLinha) {
        const colaborador = colaboradoresRes.rows.find(c => c.id === aloc.colaborador_id);
        if (colaborador) {
          const salario = parseFloat(colaborador.salario_base) || 0;
          const encargos = parseFloat(colaborador.encargos_percentual) || 70;
          custoLinha += salario * (1 + encargos / 100);
        }
      }
      custoTotalMaoObra += custoLinha;

      const minutosTotais = diasMes * horasDia * 60;
      const custoMinuto = custoLinha / minutosTotais;

      let perdasSetup = 0;
      
      const produtosCountRes = await pool.query(`
        SELECT COUNT(*) as total_produtos
        FROM linha_produto
        WHERE linha_id = $1
      `, [linha.id]);
      const quantidadeProdutos = parseInt(produtosCountRes.rows[0]?.total_produtos) || 1;
      
      const trocasPorMes = quantidadeProdutos > 1 ? quantidadeProdutos : 1;
      
      for (const posto of postos) {
        const tempoSetup = parseFloat(posto.tempo_setup_minutos) || 0;
        perdasSetup += tempoSetup * custoMinuto * trocasPorMes;
      }

      const produtosQuery = `
        SELECT 
          lp.id as vinculo_id,
          p.id as produto_id,
          p.nome as produto_nome,
          p.valor_unitario,
          lp.takt_time_segundos,
          lp.meta_diaria
        FROM linha_produto lp
        JOIN produtos p ON p.id = lp.produto_id
        WHERE lp.linha_id = $1
      `;
      const produtosRes = await pool.query(produtosQuery, [linha.id]);
      const produtos = produtosRes.rows;

      const perdasQuery = `
        SELECT 
          pl.microparadas_minutos,
          pl.refugo_pecas,
          p.nome as produto_nome,
          p.valor_unitario
        FROM perdas_linha pl
        JOIN linha_produto lp ON lp.id = pl.linha_produto_id
        JOIN produtos p ON p.id = lp.produto_id
        WHERE lp.linha_id = $1
      `;
      const perdasReaisRes = await pool.query(perdasQuery, [linha.id]);
      const perdasReais = perdasReaisRes.rows;

      let perdasMicro = 0;
      let perdasRefugo = 0;

      for (const prod of produtos) {
        const perda = perdasReais.find(p => p.produto_nome === prod.produto_nome);
        if (perda) {
          const microMin = parseFloat(perda.microparadas_minutos) || 0;
          perdasMicro += microMin * custoMinuto * diasMes;
          
          const refugoPecas = parseInt(perda.refugo_pecas) || 0;
          const valorPeca = parseFloat(prod.valor_unitario) || 50;
          perdasRefugo += refugoPecas * valorPeca * diasMes;
        }
      }

      perdasSetupTotal += perdasSetup;
      perdasMicroTotal += perdasMicro;
      perdasRefugoTotal += perdasRefugo;

      const producaoQuery = `
        SELECT 
          COALESCE(AVG(pecas_boas), 0) as media_pecas_boas,
          COALESCE(AVG(oee), 0) as oee_medio
        FROM producao_oee
        WHERE linha_id = $1
      `;
      const producaoRes = await pool.query(producaoQuery, [linha.id]);
      const producaoMediaDia = parseFloat(producaoRes.rows[0]?.media_pecas_boas) || 0;
      const oeeLinha = parseFloat(producaoRes.rows[0]?.oee_medio) || 0;

      let faturamentoLinha = 0;
      if (produtos.length > 0 && producaoMediaDia > 0) {
        const valorMedio = produtos.reduce((acc, p) => acc + (parseFloat(p.valor_unitario) || 0), 0) / produtos.length;
        faturamentoLinha = producaoMediaDia * valorMedio * diasMes;
      }
      faturamentoTotal += faturamentoLinha;
      listaOEE.push(oeeLinha);

      let gargalo = "Não identificado";
      let maiorCiclo = 0;
      for (const posto of postos) {
        const ciclo = parseFloat(posto.tempo_ciclo_segundos) || 0;
        if (ciclo > maiorCiclo) {
          maiorCiclo = ciclo;
          gargalo = posto.nome;
        }
      }

      detalhamentoLinhas.push({
        id: linha.id,
        nome: linha.nome,
        taktTime: parseFloat(linha.takt_time_segundos) || 0,
        metaDiaria: parseInt(linha.meta_diaria) || 0,
        horasDisponiveis: parseFloat(linha.horas_disponiveis) || 8.8,
        custoMensal: Math.round(custoLinha * 100) / 100,
        faturamento: Math.round(faturamentoLinha * 100) / 100,
        oee: Math.round(oeeLinha * 100) / 100,
        gargalo: gargalo,
        perdas: {
          setup: Math.round(perdasSetup * 100) / 100,
          micro: Math.round(perdasMicro * 100) / 100,
          refugo: Math.round(perdasRefugo * 100) / 100,
          total: Math.round((perdasSetup + perdasMicro + perdasRefugo) * 100) / 100
        },
        produtos: produtos.map(p => ({
          id: p.produto_id,
          nome: p.produto_nome,
          valorUnitario: parseFloat(p.valor_unitario) || 0,
          takt: parseFloat(p.takt_time_segundos) || 0,
          meta: parseInt(p.meta_diaria) || 0
        })),
        postos: postos.map(p => ({
          id: p.id,
          nome: p.nome,
          tempoCiclo: parseFloat(p.tempo_ciclo_segundos) || 0,
          tempoSetup: parseFloat(p.tempo_setup_minutos) || 0,
          disponibilidade: parseFloat(p.disponibilidade_percentual) || 100,
          ordem: p.ordem_fluxo
        }))
      });
    }

    const perdasTotais = perdasSetupTotal + perdasMicroTotal + perdasRefugoTotal;
    const oeeMedio = listaOEE.length > 0 ? listaOEE.reduce((a, b) => a + b, 0) / listaOEE.length : 0;

    const evolucaoQuery = `
      SELECT 
        DATE_TRUNC('month', data) as mes,
        AVG(oee) as oee_medio,
        SUM(pecas_boas) as total_producao
      FROM producao_oee
      WHERE linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1)
      GROUP BY DATE_TRUNC('month', data)
      ORDER BY mes DESC
      LIMIT 6
    `;
    const evolucaoRes = await pool.query(evolucaoQuery, [empresaId]);
    const evolucao = evolucaoRes.rows.reverse().map(row => ({
      mes: row.mes,
      oee: parseFloat(row.oee_medio) || 0,
      producao: parseInt(row.total_producao) || 0
    }));

    const investimentoSugerido = 50000;
    const ganhoMensal = perdasTotais * 0.3;
    const payback = ganhoMensal > 0 ? investimentoSugerido / ganhoMensal : 999;
    const roiAnual = ganhoMensal > 0 ? (ganhoMensal * 12 / investimentoSugerido) * 100 : 0;

    res.json({
      empresa: {
        id: empresa.id,
        nome: empresa.nome,
        cnpj: empresa.cnpj,
        segmento: empresa.segmento,
        diasProdutivosMes: diasMes
      },
      resumo: {
        totalLinhas: linhas.length,
        totalColaboradores: colaboradoresRes.rows.length,
        totalAlocacoesAtivas: alocacoesRes.rows.length,
        custoMaoObra: Math.round(custoTotalMaoObra * 100) / 100,
        faturamento: Math.round(faturamentoTotal * 100) / 100,
        perdas: {
          setup: Math.round(perdasSetupTotal * 100) / 100,
          micro: Math.round(perdasMicroTotal * 100) / 100,
          refugo: Math.round(perdasRefugoTotal * 100) / 100,
          total: Math.round(perdasTotais * 100) / 100
        },
        oeeMedio: Math.round(oeeMedio * 100) / 100,
        roi: {
          investimento: investimentoSugerido,
          ganhoMensal: Math.round(ganhoMensal * 100) / 100,
          payback: payback.toFixed(1),
          roiAnual: roiAnual.toFixed(0)
        }
      },
      linhas: detalhamentoLinhas,
      colaboradores: colaboradoresRes.rows,
      alocacoes: alocacoesRes.rows,
      evolucao: evolucao,
      geradoEm: new Date().toISOString()
    });

  } catch (error) {
    console.error("❌ Erro na rota unificada:", error.message);
    res.status(500).json({ erro: "Erro ao carregar dados da empresa", detalhe: error.message });
  }
});

// ========================================
// 📊 VALIDAÇÃO DE RESULTADOS - VERSÃO PROFISSIONAL (REFATORADA)
// ========================================

/**
 * CLASSE: CALCULADORA FINANCEIRA
 * Separa a lógica de cálculo da lógica de rota
 */
class CalculadoraFinanceira {
  constructor(config) {
    this.custoHoraMaquina = config.custoHoraMaquina || 80;
    this.valorRefugoMedio = config.valorRefugoMedio || 50;
    this.numTrocasDiarias = config.numTrocasDiarias || 2;
    this.diasProdutivosMes = config.diasProdutivosMes || 22;
    this.investimentoTotal = config.investimentoTotal || 50000;
  }

  calcularPerdaRefugo(refugoDiario) {
    return refugoDiario * this.valorRefugoMedio * this.diasProdutivosMes;
  }

  calcularPerdaMicroparadas(microparadasDiariasMinutos) {
    const horasParadasMes = (microparadasDiariasMinutos / 60) * this.diasProdutivosMes;
    return horasParadasMes * this.custoHoraMaquina;
  }

  calcularPerdaSetup(setupMinutos) {
    const horasSetupDia = (setupMinutos / 60) * this.numTrocasDiarias;
    const horasSetupMes = horasSetupDia * this.diasProdutivosMes;
    return horasSetupMes * this.custoHoraMaquina;
  }

  calcularFinanceiro(dadosAntes, dadosDepois) {
    const perdaRefugoAntes = this.calcularPerdaRefugo(dadosAntes.refugoDiario);
    const perdaRefugoDepois = this.calcularPerdaRefugo(dadosDepois.refugoDiario);
    
    const perdaMicroAntes = this.calcularPerdaMicroparadas(dadosAntes.microparadasDiarias);
    const perdaMicroDepois = this.calcularPerdaMicroparadas(dadosDepois.microparadasDiarias);
    
    const perdaSetupAntes = this.calcularPerdaSetup(dadosAntes.setupMedio);
    const perdaSetupDepois = this.calcularPerdaSetup(dadosDepois.setupMedio);
    
    const perdaTotalAntes = perdaRefugoAntes + perdaMicroAntes + perdaSetupAntes;
    const perdaTotalDepois = perdaRefugoDepois + perdaMicroDepois + perdaSetupDepois;
    
    const economiaMensal = perdaTotalAntes - perdaTotalDepois;
    const economiaAnual = economiaMensal * 12;
    
    const roi = economiaAnual > 0 ? (economiaAnual / this.investimentoTotal) * 100 : 0;
    const paybackMeses = economiaMensal > 0 ? this.investimentoTotal / economiaMensal : 0;
    
    return {
      perdas: {
        refugo: { antes: perdaRefugoAntes, depois: perdaRefugoDepois, delta: perdaRefugoAntes - perdaRefugoDepois },
        microparadas: { antes: perdaMicroAntes, depois: perdaMicroDepois, delta: perdaMicroAntes - perdaMicroDepois },
        setup: { antes: perdaSetupAntes, depois: perdaSetupDepois, delta: perdaSetupAntes - perdaSetupDepois },
        total: { antes: perdaTotalAntes, depois: perdaTotalDepois, delta: perdaTotalAntes - perdaTotalDepois }
      },
      economia: {
        mensal: economiaMensal,
        anual: economiaAnual
      },
      roi: {
        percentual: roi,
        paybackMeses: paybackMeses
      }
    };
  }

  static calcularDelta(antes, depois) {
    const delta = depois - antes;
    const percentual = antes !== 0 ? (delta / Math.abs(antes)) * 100 : 0;
    return {
      valor: parseFloat(delta.toFixed(2)),
      percentual: parseFloat(percentual.toFixed(2)),
      isMelhoria: (delta > 0 && antes <= depois) || (delta < 0 && antes > depois)
    };
  }
}

/**
 * ROTA: COMPARAR PERÍODOS ANTES E DEPOIS (VERSÃO PROFISSIONAL)
 */
app.get("/api/evolution/compare/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;
  const { 
    meses_antes = 3, 
    meses_depois = 3,
    antes_inicio,
    antes_fim,
    depois_inicio,
    depois_fim
  } = req.query;

  const client = await pool.connect();
  
  try {
    const configRes = await client.query(`
      SELECT 
        id, nome,
        COALESCE(custo_hora_maquina_bruto, 80) as custo_hora_maquina,
        COALESCE(valor_unitario_refugo_medio, 50) as valor_refugo,
        COALESCE(num_trocas_diarias_media, 2) as num_trocas,
        COALESCE(dias_produtivos_mes, 22) as dias_produtivos,
        COALESCE(valor_contrato, 50000) as investimento_total
      FROM empresas 
      WHERE id = $1
    `, [empresaId]);

    if (configRes.rows.length === 0) {
      return res.status(404).json({ erro: "Empresa não encontrada" });
    }

    const empresa = configRes.rows[0];
    
    const calculadora = new CalculadoraFinanceira({
      custoHoraMaquina: parseFloat(empresa.custo_hora_maquina),
      valorRefugoMedio: parseFloat(empresa.valor_refugo),
      numTrocasDiarias: parseInt(empresa.num_trocas),
      diasProdutivosMes: parseInt(empresa.dias_produtivos),
      investimentoTotal: parseFloat(empresa.investimento_total)
    });

    let periodoAntes, periodoDepois;
    let dataDiagnostico, dataImplementacao;

    if (antes_inicio && antes_fim && depois_inicio && depois_fim) {
      periodoAntes = { inicio: new Date(antes_inicio), fim: new Date(antes_fim) };
      periodoDepois = { inicio: new Date(depois_inicio), fim: new Date(depois_fim) };
      dataDiagnostico = new Date(periodoAntes.fim);
      dataDiagnostico.setDate(dataDiagnostico.getDate() + 1);
      dataImplementacao = new Date(periodoDepois.inicio);
      dataImplementacao.setDate(dataImplementacao.getDate() - 1);
      
      if (isNaN(periodoAntes.inicio.getTime()) || isNaN(periodoAntes.fim.getTime()) ||
          isNaN(periodoDepois.inicio.getTime()) || isNaN(periodoDepois.fim.getTime())) {
        return res.status(400).json({ erro: "Datas inválidas. Use o formato YYYY-MM-DD." });
      }
    } else {
      const primeiraProducao = await client.query(`
        SELECT MIN(data) as primeira_data
        FROM producao_oee po
        JOIN linhas_producao l ON l.id = po.linha_id
        WHERE l.empresa_id = $1
      `, [empresaId]);

      const ultimaProducao = await client.query(`
        SELECT MAX(data) as ultima_data
        FROM producao_oee po
        JOIN linhas_producao l ON l.id = po.linha_id
        WHERE l.empresa_id = $1
      `, [empresaId]);

      if (!primeiraProducao.rows[0]?.primeira_data) {
        return res.status(404).json({ 
          erro: "Nenhum dado de produção encontrado",
          mensagem: "Registre produções na tabela producao_oee para gerar a validação."
        });
      }

      const primeiraData = new Date(primeiraProducao.rows[0].primeira_data);
      const ultimaData = new Date(ultimaProducao.rows[0].ultima_data);
      
      dataDiagnostico = new Date(primeiraData);
      dataDiagnostico.setDate(dataDiagnostico.getDate() + 30);
      dataImplementacao = new Date(dataDiagnostico);
      dataImplementacao.setDate(dataImplementacao.getDate() + 60);

      const fimPeriodoAntes = new Date(dataDiagnostico);
      fimPeriodoAntes.setDate(fimPeriodoAntes.getDate() - 1);
      const inicioPeriodoAntes = new Date(fimPeriodoAntes);
      inicioPeriodoAntes.setMonth(inicioPeriodoAntes.getMonth() - parseInt(meses_antes));
      
      const inicioPeriodoDepois = new Date(dataImplementacao);
      inicioPeriodoDepois.setDate(inicioPeriodoDepois.getDate() + 1);
      const fimPeriodoDepois = new Date(inicioPeriodoDepois);
      fimPeriodoDepois.setMonth(fimPeriodoDepois.getMonth() + parseInt(meses_depois));
      
      const ajustarPeriodo = (inicio, fim, dataMin, dataMax) => {
        if (inicio < dataMin) inicio = dataMin;
        if (fim > dataMax) fim = dataMax;
        return { inicio, fim };
      };

      periodoAntes = ajustarPeriodo(inicioPeriodoAntes, fimPeriodoAntes, primeiraData, dataDiagnostico);
      periodoDepois = ajustarPeriodo(inicioPeriodoDepois, fimPeriodoDepois, dataImplementacao, ultimaData);
    }

    const [oeeAntes, oeeDepois] = await Promise.all([
      client.query(`
        SELECT 
          COALESCE(AVG(oee), 0) as oee,
          COALESCE(AVG(disponibilidade), 0) as disponibilidade,
          COALESCE(AVG(performance), 0) as performance,
          COALESCE(AVG(qualidade), 0) as qualidade,
          COALESCE(AVG(pecas_produzidas), 0) as produtividade,
          COUNT(*) as total_registros
        FROM producao_oee po
        JOIN linhas_producao l ON l.id = po.linha_id
        WHERE l.empresa_id = $1 AND po.data BETWEEN $2 AND $3
      `, [empresaId, periodoAntes.inicio, periodoAntes.fim]),
      client.query(`
        SELECT 
          COALESCE(AVG(oee), 0) as oee,
          COALESCE(AVG(disponibilidade), 0) as disponibilidade,
          COALESCE(AVG(performance), 0) as performance,
          COALESCE(AVG(qualidade), 0) as qualidade,
          COALESCE(AVG(pecas_produzidas), 0) as produtividade,
          COUNT(*) as total_registros
        FROM producao_oee po
        JOIN linhas_producao l ON l.id = po.linha_id
        WHERE l.empresa_id = $1 AND po.data BETWEEN $2 AND $3
      `, [empresaId, periodoDepois.inicio, periodoDepois.fim])
    ]);

    const [setupAntes, setupDepois] = await Promise.all([
      client.query(`
        SELECT COALESCE(AVG(pt.tempo_setup_minutos), 0) as setup_medio
        FROM posto_trabalho pt
        JOIN linhas_producao l ON l.id = pt.linha_id
        WHERE l.empresa_id = $1
          AND pt.created_at BETWEEN $2 AND $3
      `, [empresaId, periodoAntes.inicio, periodoAntes.fim]),
      client.query(`
        SELECT COALESCE(AVG(pt.tempo_setup_minutos), 0) as setup_medio
        FROM posto_trabalho pt
        JOIN linhas_producao l ON l.id = pt.linha_id
        WHERE l.empresa_id = $1
          AND pt.created_at BETWEEN $2 AND $3
      `, [empresaId, periodoDepois.inicio, periodoDepois.fim])
    ]);

    let setupMedioAntes = parseFloat(setupAntes.rows[0]?.setup_medio || 0);
    let setupMedioDepois = parseFloat(setupDepois.rows[0]?.setup_medio || 0);
    
    if (setupMedioAntes === 0) {
      const ultimoSetup = await client.query(`
        SELECT tempo_setup_minutos
        FROM posto_trabalho pt
        JOIN linhas_producao l ON l.id = pt.linha_id
        WHERE l.empresa_id = $1
        ORDER BY pt.updated_at DESC
        LIMIT 1
      `, [empresaId]);
      setupMedioAntes = parseFloat(ultimoSetup.rows[0]?.tempo_setup_minutos || 0);
      setupMedioDepois = setupMedioAntes;
    }

    const diasAntes = Math.ceil((periodoAntes.fim - periodoAntes.inicio) / (1000 * 60 * 60 * 24)) || 1;
    const diasDepois = Math.ceil((periodoDepois.fim - periodoDepois.inicio) / (1000 * 60 * 60 * 24)) || 1;

    const [perdasAntes, perdasDepois] = await Promise.all([
      client.query(`
        SELECT 
          COALESCE(SUM(pl.refugo_pecas), 0) as total_refugo,
          COALESCE(SUM(pl.microparadas_minutos), 0) as total_microparadas
        FROM perdas_linha pl
        JOIN linha_produto lp ON lp.id = pl.linha_produto_id
        JOIN linhas_producao l ON l.id = lp.linha_id
        WHERE l.empresa_id = $1 AND pl.data_perda BETWEEN $2 AND $3
      `, [empresaId, periodoAntes.inicio, periodoAntes.fim]),
      client.query(`
        SELECT 
          COALESCE(SUM(pl.refugo_pecas), 0) as total_refugo,
          COALESCE(SUM(pl.microparadas_minutos), 0) as total_microparadas
        FROM perdas_linha pl
        JOIN linha_produto lp ON lp.id = pl.linha_produto_id
        JOIN linhas_producao l ON l.id = lp.linha_id
        WHERE l.empresa_id = $1 AND pl.data_perda BETWEEN $2 AND $3
      `, [empresaId, periodoDepois.inicio, periodoDepois.fim])
    ]);

    const refugoDiarioAntes = (perdasAntes.rows[0]?.total_refugo || 0) / diasAntes;
    const refugoDiarioDepois = (perdasDepois.rows[0]?.total_refugo || 0) / diasDepois;
    const microparadasDiariasAntes = (perdasAntes.rows[0]?.total_microparadas || 0) / diasAntes;
    const microparadasDiariasDepois = (perdasDepois.rows[0]?.total_microparadas || 0) / diasDepois;

    const dadosAntes = {
      refugoDiario: refugoDiarioAntes,
      microparadasDiarias: microparadasDiariasAntes,
      setupMedio: setupMedioAntes
    };

    const dadosDepois = {
      refugoDiario: refugoDiarioDepois,
      microparadasDiarias: microparadasDiariasDepois,
      setupMedio: setupMedioDepois
    };

    const financeiro = calculadora.calcularFinanceiro(dadosAntes, dadosDepois);

    const evolucaoMensal = await client.query(`
      SELECT 
        DATE_TRUNC('month', po.data) as mes,
        ROUND(AVG(po.oee), 2) as oee_medio,
        ROUND(AVG(po.disponibilidade), 2) as disponibilidade_media,
        ROUND(AVG(po.performance), 2) as performance_media,
        ROUND(AVG(po.qualidade), 2) as qualidade_media
      FROM producao_oee po
      JOIN linhas_producao l ON l.id = po.linha_id
      WHERE l.empresa_id = $1
      GROUP BY DATE_TRUNC('month', po.data)
      ORDER BY mes ASC
    `, [empresaId]);

    const formatarDataBR = (data) => {
      if (!data) return "";
      const d = new Date(data);
      return `${d.getDate().toString().padStart(2, '0')}/${(d.getMonth() + 1).toString().padStart(2, '0')}/${d.getFullYear()}`;
    };

    const calcularDelta = (antes, depois) => {
      const delta = depois - antes;
      const percentual = antes !== 0 ? (delta / Math.abs(antes)) * 100 : 0;
      return { delta: parseFloat(delta.toFixed(2)), percentual: parseFloat(percentual.toFixed(2)) };
    };

    const oeeAntesVal = parseFloat(oeeAntes.rows[0]?.oee || 0);
    const oeeDepoisVal = parseFloat(oeeDepois.rows[0]?.oee || 0);
    const dispAntes = parseFloat(oeeAntes.rows[0]?.disponibilidade || 0);
    const dispDepois = parseFloat(oeeDepois.rows[0]?.disponibilidade || 0);
    const perfAntes = parseFloat(oeeAntes.rows[0]?.performance || 0);
    const perfDepois = parseFloat(oeeDepois.rows[0]?.performance || 0);
    const qualAntes = parseFloat(oeeAntes.rows[0]?.qualidade || 0);
    const qualDepois = parseFloat(oeeDepois.rows[0]?.qualidade || 0);
    const prodAntes = parseFloat(oeeAntes.rows[0]?.produtividade || 0);
    const prodDepois = parseFloat(oeeDepois.rows[0]?.produtividade || 0);

    res.status(200).json({
      status: "sucesso",
      versao: "2.0",
      empresa: {
        id: empresa.id,
        nome: empresa.nome,
        configuracao: {
          custo_hora_maquina: empresa.custo_hora_maquina,
          valor_refugo_medio: empresa.valor_refugo,
          dias_produtivos_mes: empresa.dias_produtivos
        }
      },
      periodo: {
        antes: {
          inicio: formatarDataBR(periodoAntes.inicio),
          fim: formatarDataBR(periodoAntes.fim),
          dias_analisados: diasAntes
        },
        depois: {
          inicio: formatarDataBR(periodoDepois.inicio),
          fim: formatarDataBR(periodoDepois.fim),
          dias_analisados: diasDepois
        },
        data_diagnostico: formatarDataBR(dataDiagnostico),
        data_implementacao: formatarDataBR(dataImplementacao)
      },
      indicadores: {
        oee: { antes: oeeAntesVal, depois: oeeDepoisVal, ...calcularDelta(oeeAntesVal, oeeDepoisVal) },
        disponibilidade: { antes: dispAntes, depois: dispDepois, ...calcularDelta(dispAntes, dispDepois) },
        performance: { antes: perfAntes, depois: perfDepois, ...calcularDelta(perfAntes, perfDepois) },
        qualidade: { antes: qualAntes, depois: qualDepois, ...calcularDelta(qualAntes, qualDepois) },
        produtividade: { antes: prodAntes, depois: prodDepois, ...calcularDelta(prodAntes, prodDepois) },
        setup: { 
          antes: setupMedioAntes, 
          depois: setupMedioDepois, 
          ...calcularDelta(setupMedioAntes, setupMedioDepois),
          unidade: "minutos"
        },
        refugo_diario: { 
          antes: refugoDiarioAntes, 
          depois: refugoDiarioDepois, 
          ...calcularDelta(refugoDiarioAntes, refugoDiarioDepois),
          unidade: "peças/dia"
        },
        microparadas_diarias: { 
          antes: microparadasDiariasAntes, 
          depois: microparadasDiariasDepois, 
          ...calcularDelta(microparadasDiariasAntes, microparadasDiariasDepois),
          unidade: "minutos/dia"
        }
      },
      financeiro: {
        perda_mensal_antes: financeiro.perdas.total.antes,
        perda_mensal_depois: financeiro.perdas.total.depois,
        economia_mensal: financeiro.economia.mensal,
        economia_anual: financeiro.economia.anual,
        investimento_total: calculadora.investimentoTotal,
        roi: financeiro.roi.percentual,
        payback_meses: financeiro.roi.paybackMeses,
        detalhamento: {
          refugo: {
            antes: financeiro.perdas.refugo.antes,
            depois: financeiro.perdas.refugo.depois,
            economia: financeiro.perdas.refugo.delta
          },
          microparadas: {
            antes: financeiro.perdas.microparadas.antes,
            depois: financeiro.perdas.microparadas.depois,
            economia: financeiro.perdas.microparadas.delta
          },
          setup: {
            antes: financeiro.perdas.setup.antes,
            depois: financeiro.perdas.setup.depois,
            economia: financeiro.perdas.setup.delta
          }
        }
      },
      evolucao_mensal: evolucaoMensal.rows.map(row => ({
        mes: row.mes.toISOString().split('T')[0].substring(0, 7),
        oee: parseFloat(row.oee_medio || 0),
        disponibilidade: parseFloat(row.disponibilidade_media || 0),
        performance: parseFloat(row.performance_media || 0),
        qualidade: parseFloat(row.qualidade_media || 0)
      })),
      metadados: {
        total_registros_antes: parseInt(oeeAntes.rows[0]?.total_registros || 0),
        total_registros_depois: parseInt(oeeDepois.rows[0]?.total_registros || 0),
        data_calculo: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error("❌ Erro na Validação de Resultados:", error);
    res.status(500).json({ 
      erro: "Falha ao processar validação de resultados",
      detalhe: error.message 
    });
  } finally {
    client.release();
  }
});

// ========================================
// 🤖 IA DE SUGESTÕES DE MELHORIA - MOTOR DE INFERÊNCIA
// ========================================

/**
 * ROTA: ANALISAR EMPRESA E GERAR SUGESTÕES
 * Busca dados reais, aplica regras e retorna recomendações detalhadas
 */
app.get("/api/ia/sugestoes/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;
  const { linha_id } = req.query;

  try {
    // 1. Buscar dados da empresa
    const empresaRes = await pool.query(
      "SELECT id, nome FROM empresas WHERE id = $1",
      [empresaId]
    );
    if (empresaRes.rows.length === 0) {
      return res.status(404).json({ erro: "Empresa não encontrada" });
    }
    const empresa = empresaRes.rows[0];

    // 2. Buscar linhas da empresa (ou filtrar por linha específica)
    let linhasQuery = "SELECT * FROM linhas_producao WHERE empresa_id = $1";
    const params = [empresaId];
    if (linha_id) {
      linhasQuery += " AND id = $2";
      params.push(linha_id);
    }
    const linhasRes = await pool.query(linhasQuery, params);
    const linhas = linhasRes.rows;

    if (linhas.length === 0) {
      return res.status(404).json({ 
        erro: "Nenhuma linha de produção encontrada para esta empresa" 
      });
    }

    // 3. Buscar todas as regras de análise
    const regrasRes = await pool.query(`
      SELECT r.*, f.nome as ferramenta_nome, f.passo_a_passo, f.ganho_estimado_percentual, f.esforco_semanas
      FROM regras_analise r
      JOIN ferramentas_lean f ON f.id = r.ferramenta_id
      ORDER BY 
        CASE r.prioridade WHEN 'alta' THEN 1 WHEN 'media' THEN 2 WHEN 'baixa' THEN 3 END
    `);
    const regras = regrasRes.rows;

    // 4. Processar cada linha
    const diagnosticos = [];

    for (const linha of linhas) {
      // Buscar postos da linha
      const postosRes = await pool.query(
        "SELECT * FROM posto_trabalho WHERE linha_id = $1",
        [linha.id]
      );
      const postos = postosRes.rows;

      // Buscar perdas da linha
      const perdasRes = await pool.query(`
        SELECT 
          COALESCE(SUM(pl.microparadas_minutos), 0) as total_microparadas,
          COALESCE(SUM(pl.refugo_pecas), 0) as total_refugo
        FROM perdas_linha pl
        JOIN linha_produto lp ON lp.id = pl.linha_produto_id
        WHERE lp.linha_id = $1
      `, [linha.id]);

      // Buscar produção para calcular percentual de refugo
      const producaoRes = await pool.query(`
        SELECT COALESCE(SUM(pecas_produzidas), 0) as total_producao
        FROM producao_oee
        WHERE linha_id = $1
      `, [linha.id]);

      const totalMicroparadas = parseFloat(perdasRes.rows[0]?.total_microparadas) || 0;
      const totalRefugo = parseFloat(perdasRes.rows[0]?.total_refugo) || 0;
      const totalProducao = parseFloat(producaoRes.rows[0]?.total_producao) || 1;
      const refugoPercentual = (totalRefugo / totalProducao) * 100;

      // Buscar OEE médio da linha
      const oeeLinhaRes = await pool.query(`
        SELECT COALESCE(AVG(oee), 0) as oee_medio
        FROM producao_oee
        WHERE linha_id = $1
      `, [linha.id]);
      const oeeMedio = parseFloat(oeeLinhaRes.rows[0]?.oee_medio) || 0;

      // Calcular desbalanceamento
      let desbalanceamentoPercentual = 0;
      if (postos.length > 0) {
        const temposCiclo = postos.map(p => parseFloat(p.tempo_ciclo_segundos) || 0);
        const mediaCiclo = temposCiclo.reduce((a, b) => a + b, 0) / temposCiclo.length;
        const maxCiclo = Math.max(...temposCiclo);
        if (mediaCiclo > 0) {
          desbalanceamentoPercentual = ((maxCiclo - mediaCiclo) / mediaCiclo) * 100;
        }
      }

      // Setup máximo
      const setupMaximo = Math.max(...postos.map(p => parseFloat(p.tempo_setup_minutos) || 0));

      // Aplicar regras
      for (const regra of regras) {
        let valorReal = null;
        let aplicar = false;

        switch (regra.indicador) {
          case 'tempo_setup_minutos':
            valorReal = setupMaximo;
            if (regra.operador === '>') aplicar = valorReal > regra.valor_limite;
            else if (regra.operador === '>=') aplicar = valorReal >= regra.valor_limite;
            break;
          case 'refugo_percentual':
            valorReal = refugoPercentual;
            if (regra.operador === '>') aplicar = valorReal > regra.valor_limite;
            else if (regra.operador === 'between') aplicar = valorReal >= regra.valor_limite && valorReal <= regra.valor_limite_max;
            break;
          case 'microparadas_minutos':
            valorReal = totalMicroparadas;
            if (regra.operador === '>') aplicar = valorReal > regra.valor_limite;
            break;
          case 'oee_percentual':
            valorReal = oeeMedio;
            if (regra.operador === '<') aplicar = valorReal < regra.valor_limite;
            break;
          case 'desbalanceamento_percentual':
            valorReal = desbalanceamentoPercentual;
            if (regra.operador === '>') aplicar = valorReal > regra.valor_limite;
            break;
          case 'gargalo_existe':
            const gargalo = postos.find(p => parseFloat(p.tempo_ciclo_segundos) === Math.max(...postos.map(p2 => parseFloat(p2.tempo_ciclo_segundos) || 0)));
            valorReal = gargalo ? 1 : 0;
            if (regra.operador === '=') aplicar = valorReal === regra.valor_limite;
            break;
        }

        if (aplicar && valorReal !== null) {
          // Buscar plano de ação completo para esta regra
          const planoAcaoRes = await pool.query(`
            SELECT pa.ordem, f.nome as ferramenta, f.passo_a_passo, pa.descricao_extra, pa.tempo_semanas
            FROM planos_acao pa
            JOIN ferramentas_lean f ON f.id = pa.ferramenta_id
            WHERE pa.regra_id = $1
            ORDER BY pa.ordem ASC
          `, [regra.id]);
          
          const planoAcao = planoAcaoRes.rows;
          
          // Calcular ganho estimado
          let ganhoEstimado = 0;
          if (regra.indicador === 'tempo_setup_minutos') {
            const minutosEconomizados = (valorReal - 15) * 22; // 22 dias/mês
            ganhoEstimado = Math.round(minutosEconomizados * 2); // R$ 2/min estimado
          } else if (regra.indicador === 'refugo_percentual') {
            const reducaoEstimada = (valorReal - 2) / 100 * totalProducao * 50; // R$ 50/peça
            ganhoEstimado = Math.round(reducaoEstimada);
          } else if (regra.indicador === 'microparadas_minutos') {
            ganhoEstimado = Math.round((valorReal - 50) * 2); // R$ 2/min
          } else if (regra.indicador === 'oee_percentual') {
            ganhoEstimado = Math.round((85 - valorReal) / 100 * totalProducao * 50);
          }
          
          // Calcular esforço total (soma dos tempos do plano de ação)
          const esforcoTotalSemanas = planoAcao.reduce((acc, p) => acc + (p.tempo_semanas || 1), 0);

          diagnosticos.push({
            linha_id: linha.id,
            linha_nome: linha.nome,
            problema: regra.descricao,
            indicador: regra.indicador,
            valor_real: parseFloat(valorReal.toFixed(2)),
            valor_limite: regra.valor_limite,
            plano_acao: planoAcao.map(p => ({
              ordem: p.ordem,
              ferramenta: p.ferramenta,
              passo_a_passo: p.passo_a_passo,
              descricao_extra: p.descricao_extra,
              tempo_semanas: p.tempo_semanas
            })),
            ganho_estimado: ganhoEstimado,
            esforco_semanas: esforcoTotalSemanas,
            prioridade: regra.prioridade
          });

          // Salvar na tabela diagnosticos_ia
          await pool.query(`
            INSERT INTO diagnosticos_ia 
            (empresa_id, linha_id, problema_identificado, causa_provavel, ferramentas_sugeridas, ganho_estimado_mensal, esforco_semanas, prioridade, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
          `, [
            empresaId,
            linha.id,
            regra.descricao,
            `Valor atual de ${valorReal.toFixed(2)} ultrapassa o limite de ${regra.valor_limite}`,
            planoAcao.map(p => p.ferramenta),
            ganhoEstimado,
            esforcoTotalSemanas,
            regra.prioridade,
            req.usuario.id
          ]);
        }
      }
    }

    // 5. Agrupar diagnósticos por prioridade
    const altaPrioridade = diagnosticos.filter(d => d.prioridade === 'alta');
    const mediaPrioridade = diagnosticos.filter(d => d.prioridade === 'media');
    const baixaPrioridade = diagnosticos.filter(d => d.prioridade === 'baixa');

    // 6. Calcular ganho total mensal
    const ganhoTotalMensal = diagnosticos.reduce((acc, d) => acc + (d.ganho_estimado || 0), 0);

    // 7. Calcular OEE médio global da empresa (com ROUND)
    let oeeMedioReal = 0;
    try {
      const oeeRes = await pool.query(`
        SELECT ROUND(COALESCE(AVG(oee), 0), 1) as oee_medio
        FROM producao_oee
        WHERE linha_id IN (SELECT id FROM linhas_producao WHERE empresa_id = $1)
      `, [empresaId]);
      oeeMedioReal = parseFloat(oeeRes.rows[0]?.oee_medio) || 0;
    } catch (err) {
      console.log("Erro ao buscar OEE médio:", err.message);
    }

    // 8. Calcular projeções
    const oeeProjetado = Math.min(85, Math.round(oeeMedioReal + 20));
    const tempoTotalSemanas = diagnosticos.reduce((acc, d) => acc + (d.esforco_semanas || 0), 0);
    const tempoMeses = Math.ceil(tempoTotalSemanas / 4);

    // 9. Retornar resultado
    res.json({
      sucesso: true,
      empresa: empresa.nome,
      data_analise: new Date().toLocaleDateString('pt-BR'),
      resumo: {
        total_diagnosticos: diagnosticos.length,
        alta_prioridade: altaPrioridade.length,
        media_prioridade: mediaPrioridade.length,
        baixa_prioridade: baixaPrioridade.length,
        ganho_total_mensal: ganhoTotalMensal,
        oee_projetado: oeeProjetado,
        oee_atual: oeeMedioReal
      },
      diagnosticos: {
        alta: altaPrioridade.map(d => ({
          linha_nome: d.linha_nome,
          problema: d.problema,
          valor_real: d.valor_real,
          valor_limite: d.valor_limite,
          plano_acao: d.plano_acao,
          ganho_estimado: d.ganho_estimado,
          esforco_semanas: d.esforco_semanas,
          prioridade: d.prioridade
        })),
        media: mediaPrioridade.map(d => ({
          linha_nome: d.linha_nome,
          problema: d.problema,
          valor_real: d.valor_real,
          valor_limite: d.valor_limite,
          plano_acao: d.plano_acao,
          ganho_estimado: d.ganho_estimado,
          esforco_semanas: d.esforco_semanas,
          prioridade: d.prioridade
        })),
        baixa: baixaPrioridade.map(d => ({
          linha_nome: d.linha_nome,
          problema: d.problema,
          valor_real: d.valor_real,
          valor_limite: d.valor_limite,
          plano_acao: d.plano_acao,
          ganho_estimado: d.ganho_estimado,
          esforco_semanas: d.esforco_semanas,
          prioridade: d.prioridade
        }))
      },
      projecoes: {
        novo_oee: `${oeeProjetado}%`,
        ganho_mensal: `R$ ${ganhoTotalMensal.toLocaleString('pt-BR')}`,
        tempo_estimado: `${tempoMeses} meses`,
        ganho_oee: `${(oeeProjetado - oeeMedioReal).toFixed(1)} p.p.`
      }
    });

  } catch (error) {
    console.error("❌ Erro na IA de Sugestões:", error.message);
    res.status(500).json({ 
      erro: "Falha ao gerar sugestões",
      detalhe: error.message 
    });
  }
});

// ========================================
// 📄 CONTRATO DE RENOVAÇÃO DE ACOMPANHAMENTO (FASE 3 - EXTENSÃO) - VERSÃO FINAL
// ========================================

app.post("/api/ia/gerar-contrato-renovacao-acompanhamento", autenticarToken, async (req, res) => {
  try {
    const dados = req.body;

    // Formatação robusta de data com timezone Brasil
    const formatarData = (data) => {
      return new Intl.DateTimeFormat('pt-BR', { 
        timeZone: 'America/Sao_Paulo' 
      }).format(data);
    };

    // Validações
    if (!dados.empresa || !dados.empresa.nome) {
      return res.status(400).json({ erro: "Dados da empresa são obrigatórios" });
    }

    if (!dados.meses || dados.meses < 1 || dados.meses > 12) {
      return res.status(400).json({ erro: "Número de meses deve ser entre 1 e 12" });
    }

    if (!dados.valor_mensal || dados.valor_mensal <= 0) {
      return res.status(400).json({ erro: "Valor mensal do acompanhamento é obrigatório" });
    }

    // 🔥 AJUSTE DO VALOR DA RENOVAÇÃO (baseado no porte)
const valorOriginal = parseFloat(dados.valor_mensal);
let valorMensalRenovacao;

if (valorOriginal <= 8500) {
  valorMensalRenovacao = 5000;   // Pequeno (1 linha)
} else if (valorOriginal <= 17000) {
  valorMensalRenovacao = 10000;  // Médio (2-3 linhas)
} else if (valorOriginal <= 25500) {
  valorMensalRenovacao = 15000;  // Grande (4-5 linhas)
} else {
  valorMensalRenovacao = 20000;  // Premium (6+ linhas)
}

// Sobrescrever o valor mensal
dados.valor_mensal = valorMensalRenovacao;


    if (!dados.data_termino_contrato_original) {
      return res.status(400).json({ erro: "Data de término do contrato original é obrigatória" });
    }

    // Calcular valores com desconto progressivo
    const meses = parseInt(dados.meses);
    const valorMensal = parseFloat(dados.valor_mensal);
    
    let descontoPercentual = 0;
    if (meses >= 12) descontoPercentual = 15;
    else if (meses >= 6) descontoPercentual = 10;
    else if (meses >= 3) descontoPercentual = 5;
    
    const valorTotalSemDesconto = valorMensal * meses;
    const descontoValor = valorTotalSemDesconto * (descontoPercentual / 100);
    const valorTotal = valorTotalSemDesconto - descontoValor;
    
    // Calcular parcelas exatas (última parcela ajustada)
    let numParcelas = Math.min(Math.ceil(valorTotal / 5000), meses);
    if (numParcelas < 1) numParcelas = 1;
    
    const valorBaseParcela = valorTotal / numParcelas;
    let parcelasArray = [];
    for (let i = 0; i < numParcelas; i++) {
      if (i === numParcelas - 1) {
        parcelasArray.push(valorTotal - (valorBaseParcela * (numParcelas - 1)));
      } else {
        parcelasArray.push(valorBaseParcela);
      }
    }
    
    const valorParcela = Math.ceil(parcelasArray[0] * 100) / 100;
    const ultimaParcela = Math.ceil(parcelasArray[parcelasArray.length - 1] * 100) / 100;
    const temUltimaDiferente = Math.abs(valorParcela - ultimaParcela) > 0.01;
    
    // Calcular datas com fuso horário corrigido
    const dataInicio = new Date(dados.data_termino_contrato_original);
    dataInicio.setDate(dataInicio.getDate() + 1);
    const dataInicioFormatada = formatarData(dataInicio);
    
    const dataFim = new Date(dataInicio);
    dataFim.setMonth(dataFim.getMonth() + meses);
    dataFim.setDate(dataFim.getDate() - 1);
    const dataFimFormatada = formatarData(dataFim);
    
    const dataAssinaturaFormatada = formatarData(new Date());
    
    // Verificar se deve mostrar projeções (apenas se o cliente solicitou e forneceu os dados)
    const mostrarProjecoes = dados.ganho_mensal_estimado && dados.ganho_mensal_estimado > 0;
    let ganhoMensalEstimado = null;
    let roiMensal = null;
    let paybackMeses = null;
    
    if (mostrarProjecoes) {
      ganhoMensalEstimado = parseFloat(dados.ganho_mensal_estimado);
      roiMensal = (ganhoMensalEstimado / valorMensal) * 100;
      paybackMeses = valorMensal > 0 ? (valorTotal / ganhoMensalEstimado) : 0;
    }

    const formatarMoeda = (valor) => {
      return new Intl.NumberFormat('pt-BR', {
        style: 'currency',
        currency: 'BRL',
        minimumFractionDigits: 2
      }).format(valor || 0);
    };

    // Mapeamento de porte
    const getPorte = (valorMensal) => {
      if (valorMensal <= 8500) return "Pequeno (1 linha)";
      if (valorMensal <= 17000) return "Médio (2-3 linhas)";
      if (valorMensal <= 25500) return "Grande (4-5 linhas)";
      return "Premium (6+ linhas)";
    };

    function mesesPorExtenso(n) {
      const extenso = ['um', 'dois', 'três', 'quatro', 'cinco', 'seis', 'sete', 'oito', 'nove', 'dez', 'onze', 'doze'];
      return extenso[n - 1] || n;
    }

    const contrato = `
CONTRATO DE PRESTAÇÃO DE SERVIÇOS DE CONSULTORIA - PRORROGAÇÃO DE ACOMPANHAMENTO (FASE 3)

CONTRATANTE: ${dados.empresa.nome}, pessoa jurídica de direito privado, inscrita no CNPJ sob o nº ${dados.empresa.cnpj || '[CNPJ]'}, com sede na ${dados.empresa.endereco || '[ENDEREÇO]'}, neste ato representada por ${dados.representante?.nome || '[NOME DO REPRESENTANTE]'}, ${dados.representante?.nacionalidade || '[NACIONALIDADE]'}, ${dados.representante?.estado_civil || '[ESTADO CIVIL]'}, ${dados.representante?.profissao || '[PROFISSÃO]'}, portador do RG nº ${dados.representante?.rg || '[RG]'} e CPF nº ${dados.representante?.cpf || '[CPF]'}, residente e domiciliado na ${dados.representante?.endereco || '[ENDEREÇO]'}.

CONTRATADA: NEXUS ENGENHARIA APLICADA, pessoa jurídica de direito privado, inscrita no CNPJ sob o nº [CNPJ DA NEXUS], com sede na [ENDEREÇO DA NEXUS], neste ato representada por [SEU NOME], [NACIONALIDADE], [ESTADO CIVIL], [PROFISSÃO], portador do RG nº [RG] e CPF nº [CPF], residente e domiciliado na [ENDEREÇO].

As partes, acima identificadas, têm entre si justo e contratado o seguinte:


CLÁUSULA 1 – OBJETO

1.1. O presente contrato tem por objeto a **prorrogação do serviço de acompanhamento pós-implantação** (Fase 3), previsto no contrato original de prestação de serviços de consultoria firmado entre as partes.

1.2. O serviço de acompanhamento prorrogado compreende as seguintes atividades:

   a) **Monitoramento Semanal:** Acompanhamento dos indicadores (OEE, produtividade, qualidade) com análise de tendências e envio de relatório semanal por e-mail;

   b) **Reuniões de Acompanhamento:** 1 (uma) hora por semana, realizada de forma remota (videoconferência), com a liderança designada pela CONTRATANTE, **sendo que qualquer demanda adicional de horas ou reuniões deverá ser previamente acordada entre as partes por escrito**;

   c) **Ajustes Finos:** Correções e otimizações nos processos implementados durante a Fase 2, mediante solicitação da CONTRATANTE com até 48 (quarenta e oito) horas de antecedência;

   d) **Transferência de Conhecimento:** Capacitação complementar da equipe interna para sustentar os resultados;

   e) **Relatórios Mensais:** Documentação detalhada da evolução dos indicadores e resultados alcançados, entregue até o 5º (quinto) dia útil do mês subsequente;

   f) **Plano de Sustentação:** Revisão e atualização do plano de manutenção dos ganhos após o término do período contratado.

1.3. **Não fazem parte do objeto deste contrato:**
   a) Implementação de novas melhorias não previstas no diagnóstico original;
   b) Substituição ou reparo de equipamentos;
   c) Serviços de manutenção corretiva ou preditiva de máquinas;
   d) Qualquer serviço ou atividade não expressamente previsto na Cláusula 1.2.


CLÁUSULA 2 – PRAZO DE PRORROGAÇÃO

2.1. O prazo de prorrogação do acompanhamento é de **${meses} (${mesesPorExtenso(meses)}) meses**, contados a partir do término do período de acompanhamento previsto no contrato original.

2.2. O início do período de prorrogação será em **${dataInicioFormatada}** (dia seguinte ao término do contrato original) e o término em **${dataFimFormatada}**.

2.3. As partes poderão, mediante aditivo contratual, prorrogar este contrato por períodos adicionais, respeitando as mesmas condições aqui estabelecidas, **podendo o valor do acompanhamento mensal ser reajustado com base no índice IPCA (Índice de Preços ao Consumidor Amplo) acumulado desde a data da última renovação, ou pela política comercial vigente da CONTRATADA à época da renovação, sendo este reajuste comunicado com pelo menos 30 (trinta) dias de antecedência.**

2.4. A rescisão antecipada deste contrato seguirá integralmente as condições previstas na Cláusula 8 (Rescisão).


CLÁUSULA 3 – VALOR E CONDIÇÕES DE PAGAMENTO

3.1. O valor mensal do serviço de acompanhamento prorrogado é de **${formatarMoeda(valorMensal)}**.

3.2. O valor total da prorrogação é de **${formatarMoeda(valorTotal)}**, assim calculado:

   - Valor mensal: ${formatarMoeda(valorMensal)}
   - Número de meses: ${meses} meses
   - Subtotal: ${formatarMoeda(valorTotalSemDesconto)}
   - Desconto (${descontoPercentual}%): ${formatarMoeda(descontoValor)}
   - **Valor final: ${formatarMoeda(valorTotal)}**

3.3. O valor total inclui:
   - Acompanhamento mensal por ${meses} meses
   - Relatórios gerenciais
   - Suporte e ajustes finos
   - Transferência de conhecimento

3.4. O pagamento será efetuado da seguinte forma:

   ${dados.forma_pagamento === 'a_vista' ? `
   **À vista:**
   a) Pagamento único no valor de ${formatarMoeda(valorTotal)} na data de assinatura deste contrato, com desconto de ${descontoPercentual}% já aplicado.
   ` : `
   **Parcelado (${numParcelas}x):**
   a) ${numParcelas} parcelas mensais, consecutivas e sucessivas;
   b) ${temUltimaDiferente ? `${numParcelas - 1} primeiras parcelas de ${formatarMoeda(valorParcela)} e a última de ${formatarMoeda(ultimaParcela)}` : `${numParcelas} parcelas de ${formatarMoeda(valorParcela)}`}, **sendo que a última parcela poderá sofrer ajuste de centavos para equalização do valor total**;
   c) Vencendo a primeira na data de assinatura deste contrato e as demais em igual dia dos meses subsequentes.
   `}

3.5. O pagamento deverá ser efetuado mediante depósito/transferência bancária para a conta:
   Banco: [BANCO]
   Agência: [AGÊNCIA]
   Conta: [CONTA]
   Titular: NEXUS ENGENHARIA APLICADA

3.6. O atraso no pagamento sujeitará a CONTRATANTE a:
   a) Multa moratória de 2% (dois por cento) sobre o valor da parcela em atraso;
   b) Juros de mora de 1% (um por cento) ao mês, calculados pro rata die;
   c) Correção monetária pelo índice IPCA.

3.7. Em caso de inadimplemento, a CONTRATADA poderá suspender imediatamente a execução dos serviços até a regularização do pagamento. **A suspensão dos serviços por inadimplência exime a CONTRATADA de qualquer responsabilidade por impactos nos resultados, indicadores ou operações da CONTRATANTE durante o período de suspensão.**

3.8. Os descontos progressivos previstos na Cláusula 3.2 são válidos somente para contratação realizada até **30 (trinta) dias após o término do contrato original**. Após este prazo, será aplicada a tabela de preços vigente à época.

${mostrarProjecoes ? `
CLÁUSULA 3-A – PROJEÇÕES MERAMENTE INDICATIVAS

3-A.1. A pedido da CONTRATANTE, foram apresentadas projeções indicativas, as quais possuem caráter **meramente ilustrativo e indicativo**, sendo baseadas exclusivamente em premissas teóricas e em resultados históricos obtidos em outras empresas, que podem não se aplicar à realidade específica da CONTRATANTE.

3-A.2. A CONTRATADA **não garante, não promete e não se responsabiliza** pela obtenção de qualquer resultado específico, seja ele de produtividade, eficiência, redução de custos, aumento de faturamento ou qualquer outro indicador.

3-A.3. A CONTRATANTE reconhece que os resultados dependem exclusivamente de sua execução, engajamento, disciplina operacional, condições de mercado e fatores externos alheios ao controle da CONTRATADA.

3-A.4. A CONTRATANTE declara que não celebrou este contrato com base em qualquer garantia de resultado, mas sim na confiança na metodologia e na capacidade técnica da CONTRATADA.

3-A.5. A aceitação deste contrato implica concordância expressa de que nenhuma projeção verbal ou escrita constitui obrigação de resultado para a CONTRATADA.
` : ''}

CLÁUSULA 4 – OBRIGAÇÕES DA CONTRATADA

4.1. Executar os serviços com diligência, empregando as melhores práticas e técnicas de engenharia disponíveis.

4.2. Manter absoluto sigilo sobre todas as informações da CONTRATANTE a que tiver acesso.

4.3. Entregar os relatórios mensais de acompanhamento até o 5º (quinto) dia útil do mês subsequente.

4.4. Disponibilizar canal de comunicação para suporte durante o horário comercial (9h às 18h, dias úteis), com prazo de resposta de até 24 (vinte e quatro) horas.

4.5. A responsabilidade da CONTRATADA é de **MEIO, não de resultado**, não respondendo por resultados específicos que dependam de fatores alheios ao seu controle.


CLÁUSULA 5 – OBRIGAÇÕES DA CONTRATANTE

5.1. Fornecer acesso às áreas produtivas, instalações, equipamentos e informações necessárias à execução dos serviços.

5.2. Indicar, por escrito, um responsável técnico que atuará como contato oficial durante a vigência do contrato.

5.3. Efetuar os pagamentos nas datas e condições estipuladas na Cláusula 3.

5.4. Implementar as recomendações acordadas, sendo de sua inteira responsabilidade os resultados decorrentes da não implementação.


CLÁUSULA 6 – PROPRIEDADE INTELECTUAL

6.1. Toda a metodologia, know-how, softwares, sistemas (incluindo a plataforma Hórus), técnicas, ferramentas, modelos, procedimentos, materiais de treinamento, **incluindo, mas não se limitando a: algoritmos, lógica de cálculo, estrutura de dados, dashboards, fórmulas de precificação, critérios de análise e qualquer outro ativo intelectual** desenvolvido ou utilizado pela CONTRATADA são de sua propriedade exclusiva, constituindo segredo de negócio.

6.2. A CONTRATANTE não adquire, por força deste contrato, qualquer direito de propriedade sobre a metodologia, softwares ou ferramentas da CONTRATADA.

6.3. É expressamente proibido à CONTRATANTE copiar, reproduzir, modificar, descompilar ou realizar engenharia reversa da plataforma Hórus ou de qualquer ferramenta da CONTRATADA.

6.4. A violação desta cláusula sujeitará a parte infratora ao pagamento de multa equivalente a 10 (dez) vezes o valor total deste contrato.


CLÁUSULA 7 – CONFIDENCIALIDADE

7.1. As partes obrigam-se a manter absoluto sigilo sobre todas as informações confidenciais a que tiverem acesso em razão deste contrato.

7.2. A obrigação de confidencialidade estende-se pelo prazo de 5 (cinco) anos após o término deste contrato.

7.3. A violação desta cláusula sujeitará a parte infratora ao pagamento de multa equivalente a 3 (três) vezes o valor total deste contrato.


CLÁUSULA 8 – RESCISÃO

8.1. O presente contrato poderá ser rescindido por qualquer das partes, mediante notificação por escrito, nas seguintes hipóteses:
   a) Descumprimento de qualquer cláusula contratual, não sanado no prazo de 15 (quinze) dias úteis após o recebimento da notificação;
   b) Por interesse exclusivo de qualquer das partes, mediante aviso prévio de 30 (trinta) dias, sem justa causa;
   c) Por caso fortuito ou força maior que impeça a execução do objeto, devidamente comprovado.

8.2. Em caso de rescisão unilateral sem justa causa pela CONTRATANTE, será devida multa de 20% (vinte por cento) sobre o saldo remanescente do contrato, calculado com base no valor total previsto na Cláusula 3.2. Caso a rescisão ocorra após o início dos serviços, serão devidos os valores proporcionais às atividades já executadas, **considerando-se como executados todos os serviços disponibilizados pela CONTRATADA, independentemente de sua efetiva utilização pela CONTRATANTE**, não sendo cabível reembolso integral dos valores pagos.

8.3. Em caso de rescisão por descumprimento da CONTRATADA, esta restituirá à CONTRATANTE os valores já pagos e não correspondentes a serviços já executados, atualizados monetariamente, e pagará multa de 20% (vinte por cento) sobre o valor total do contrato, limitada aos valores efetivamente pagos e não correspondentes a serviços já executados, **desde que comprovado descumprimento relevante que inviabilize a continuidade do contrato, não sendo suficiente para tanto descumprimentos meramente formais ou de pouca monta.**

8.4. Em caso de rescisão por descumprimento da CONTRATANTE, esta pagará à CONTRATADA os serviços já prestados, atualizados monetariamente, e multa de 20% (vinte por cento) sobre o valor total do contrato.

8.5. A rescisão não exonera as partes das obrigações de confidencialidade previstas na Cláusula 7 e das penalidades eventualmente já incorridas.


CLÁUSULA 9 – PENALIDADES

9.1. Pelo descumprimento de qualquer obrigação contratual não especificamente penalizada em outras cláusulas, será aplicada multa de 10% (dez por cento) sobre o valor total do contrato, sem prejuízo da obrigação principal.

9.2. As multas previstas neste contrato poderão ser aplicadas de forma cumulativa, desde que não excedam, em conjunto, o valor total deste contrato, **e desde que sejam proporcionais ao prejuízo comprovadamente causado pela infração**, sob pena de redução equitativa pelo juízo.

9.3. A mora de qualquer das partes no cumprimento de suas obrigações sujeitará o infrator à incidência dos encargos previstos na Cláusula 3.6.


CLÁUSULA 10 – DISPOSIÇÕES GERAIS

10.1. Este contrato é celebrado em caráter intuitu personae em relação à CONTRATADA, não podendo a CONTRATANTE ceder ou transferir seus direitos e obrigações sem prévia e expressa anuência por escrito da CONTRATADA.

10.2. As comunicações entre as partes serão consideradas válidas quando enviadas por e-mail para os endereços abaixo:
   CONTRATANTE: ${dados.contato?.email_contratante || '[E-MAIL DA CONTRATANTE]'}
   CONTRATADA: ${dados.contato?.email_contratada || '[SEU E-MAIL]'}

10.3. A tolerância quanto ao descumprimento de qualquer cláusula não constituirá novação, renúncia de direitos ou precedente, mantendo-se a exigibilidade das obrigações.

10.4. Qualquer modificação ou aditivo a este contrato deverá ser formalizado por escrito, com anuência de ambas as partes.

10.5. Os títulos das cláusulas são meramente descritivos e não vinculam a interpretação do contrato.


CLÁUSULA 10-A – NÃO EXCLUSIVIDADE

10-A.1. A CONTRATADA poderá prestar serviços de consultoria, treinamento, acompanhamento e quaisquer outros serviços correlatos a outras empresas, inclusive concorrentes da CONTRATANTE, desde que não haja violação das obrigações de confidencialidade previstas neste contrato.

10-A.2. A CONTRATANTE reconhece e aceita que a metodologia Hórus é aplicável a diferentes setores e empresas, não havendo qualquer compromisso de exclusividade por parte da CONTRATADA.

10-A.3. A presente cláusula prevalece sobre qualquer entendimento em contrário, não sendo devida qualquer compensação ou indenização à CONTRATANTE em razão da prestação de serviços a terceiros.


CLÁUSULA 10-B – INDEPENDÊNCIA DAS PARTES

10-B.1. As partes declaram que este contrato não estabelece qualquer vínculo societário, trabalhista, empregatício, de subordinação ou de parceria entre elas, sendo a CONTRATADA uma prestadora de serviços independente.

10-B.2. A CONTRATADA exerce suas atividades com autonomia técnica, gerencial e operacional, utilizando seus próprios meios, métodos e ferramentas, não havendo qualquer relação de hierarquia ou subordinação com a CONTRATANTE.

10-B.3. A CONTRATANTE não possui qualquer responsabilidade sobre obrigações trabalhistas, previdenciárias, fiscais ou sociais da CONTRATADA, que serão arcadas exclusivamente por esta.

10-B.4. A presente cláusula prevalece sobre qualquer entendimento em contrário, não sendo devida qualquer indenização ou verba trabalhista em razão da execução deste contrato.


CLÁUSULA 10-C – INTEGRAÇÃO DO CONTRATO

10-C.1. Este contrato, juntamente com seus anexos, representa o acordo integral e exclusivo entre as partes, substituindo e extinguindo quaisquer entendimentos, negociações, ajustes, promessas, comunicações ou acordos anteriores, sejam eles verbais ou escritos, mantidos entre as partes em relação ao objeto deste contrato.

10-C.2. Quaisquer declarações, promessas ou informações prestadas por representantes da CONTRATADA durante a fase de negociação que não estejam expressamente contempladas neste contrato não vinculam a CONTRATADA nem constituem obrigação contratual.

10-C.3. A CONTRATANTE declara que não foi induzida a contratar com base em quaisquer promessas, garantias ou representações que não estejam expressamente descritas neste instrumento.

10-C.4. Eventuais aditivos ou alterações a este contrato somente produzirão efeitos se formalizados por escrito e assinados por ambas as partes.


CLÁUSULA 11 – LIMITAÇÃO DE RESPONSABILIDADE

11.1. A responsabilidade total da CONTRATADA, independentemente da natureza da reclamação ou da teoria jurídica aplicável, fica limitada ao valor total pago pela CONTRATANTE nos últimos 12 (doze) meses, nunca excedendo o valor total deste contrato.

11.2. Em nenhuma hipótese a CONTRATADA será responsável por danos indiretos, lucros cessantes, perda de faturamento, perda de clientes, perda de oportunidades de negócio, danos à imagem ou reputação, **incluindo, mas não se limitando a: perda de produção, parada de linha de produção, multas contratuais com terceiros, atrasos na entrega de produtos, perda de matéria-prima, ou qualquer outro dano consequencial**, mesmo que tenha sido avisada da possibilidade de tais danos.

11.3. A CONTRATANTE declara ter ciência de que os resultados do acompanhamento dependem de múltiplos fatores, incluindo sua própria execução e engajamento, não podendo a CONTRATADA ser responsabilizada por resultados não alcançados.


CLÁUSULA 12 – FORO

12.1. Fica eleito o foro da Comarca de [SUA CIDADE/ESTADO] para dirimir quaisquer questões decorrentes deste contrato, com renúncia expressa a qualquer outro, por mais privilegiado que seja.


ASSINATURAS

E, por estarem assim justas e contratadas, as partes assinam o presente instrumento em 2 (duas) vias de igual teor e forma.

${dados.empresa.cidade || '[CIDADE]'}, ${dataAssinaturaFormatada}.

<div style="display: flex; justify-content: space-between; gap: 40px; margin-top: 30px;">
  <div style="flex: 1; text-align: center;">
    <div style="border-top: 1px solid #000; margin: 15px 0 8px 0;"></div>
    <strong>CONTRATANTE</strong><br/>
    ${dados.empresa.nome}<br/>
    ${dados.representante?.nome || '[REPRESENTANTE]'}<br/>
    ${dados.representante?.cargo || '[CARGO]'}
  </div>

  <div style="flex: 1; text-align: center;">
    <div style="border-top: 1px solid #000; margin: 15px 0 8px 0;"></div>
    <strong>CONTRATADA</strong><br/>
    NEXUS ENGENHARIA APLICADA<br/>
    [SEU NOME]<br/>
    [SEU CARGO]
  </div>
</div>
`;

    // Metadata sem projeções
    const metadata = {
      empresa: dados.empresa.nome,
      porte: getPorte(valorMensal),
      meses: meses,
      valor_mensal: valorMensal,
      valor_total: valorTotal,
      desconto_percentual: descontoPercentual,
      data_geracao: new Date().toISOString(),
      tipo: "renovacao-acompanhamento"
    };

    // Só adiciona projeções se foram fornecidas
    if (mostrarProjecoes) {
      metadata.roi_estimado_mensal = `${roiMensal.toFixed(0)}%`;
      metadata.payback_estimado_meses = paybackMeses.toFixed(1);
      metadata.ganho_mensal_estimado = formatarMoeda(ganhoMensalEstimado);
    }

    res.status(200).json({
      status: "sucesso",
      contrato: contrato,
      metadata: metadata
    });

  } catch (error) {
    console.error("❌ Erro ao gerar contrato de renovação:", error.message);
    res.status(500).json({ 
      erro: "Falha ao gerar contrato de renovação",
      detalhe: error.message 
    });
  }
});

// ========================================
// 🏁 START ENGINE: NEXUS HÓRUS PLATFORM
// ========================================

const PORT_SYSTEM = process.env.PORT || 3001;
const ENV_SYSTEM = process.env.NODE_ENV || 'development';

const server = app.listen(PORT_SYSTEM, () => {
  console.log(`
  ================================================
  🚀 NEXUS ENGENHARIA APLICADA - SISTEMA HÓRUS
  ================================================
  📡 Status: Operacional
  🔌 Porta: ${PORT_SYSTEM}
  🌍 Ambiente: ${ENV_SYSTEM}
  📊 Inteligência Industrial: Ativa
  🛡️ Segurança JWT: Protegida
  ================================================
  `);
});

process.on('SIGTERM', () => {
  console.log('🚨 SIGTERM recebido. Encerrando servidor Hórus...');
  server.close(() => {
    if (typeof pool !== 'undefined') {
      pool.end();
    }
    console.log('✅ Processos encerrados e banco de dados desconectado.');
    process.exit(0);
  });
});