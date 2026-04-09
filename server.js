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

/**
 * 3️⃣ EXCLUIR EMPRESA
 * Protegida por Token e com verificação de existência.
 */
app.delete("/api/companies/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query("DELETE FROM empresas WHERE id = $1 RETURNING *", [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Empresa não encontrada para exclusão." });
    }

    res.status(200).json({ mensagem: "Empresa e seus vínculos removidos com sucesso." });
  } catch (error) {
    console.error("❌ Erro DELETE /companies:", error.message);
    res.status(500).json({ erro: "Erro ao excluir empresa. Verifique se há vínculos ativos." });
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
  
  // Aceita horas em qualquer formato
  const horas = req.body.horas_disponiveis || req.body.horas_produtivas_dia || 16;
  const horasNumericas = parseFloat(horas) || 16;
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // 1. Atualizar a linha (nome e horas)
    const result = await client.query(
      `UPDATE linhas_producao 
       SET nome = COALESCE($1, nome), 
           horas_disponiveis = $2
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

  try {
    const result = await pool.query("DELETE FROM colaborador WHERE id = $1 RETURNING *", [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Colaborador não encontrado." });
    }

    res.status(200).json({ mensagem: "Colaborador removido do quadro." });
  } catch (error) {
    console.error("❌ Erro DELETE /employees:", error.message);
    
    // Se o colaborador estiver vinculado a registros históricos de produção (Cronoanálise), 
    // o banco pode barrar a exclusão física dependendo da sua regra de negócio.
    if (error.code === '23503') {
      return res.status(400).json({ 
        erro: "Não é possível excluir: este colaborador possui registros de atividades vinculados." 
      });
    }

    res.status(500).json({ erro: "Erro ao processar exclusão" });
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
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $8
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
// 🗑️ MÓDULO: TERMINAÇÃO DE REGISTROS (SAFE DELETE)
// ========================================

app.delete("/api/companies/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;

  try {
    // 1. Execução do Delete com Retorno de Identificação
    const result = await pool.query(
      "DELETE FROM empresas WHERE id = $1 RETURNING nome", 
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Registro não localizado para exclusão." });
    }

    console.warn(`🚨 Empresa removida do ecossistema: ${result.rows[0].nome}`);
    
    res.json({ 
      mensagem: `A empresa ${result.rows[0].nome} e seus parâmetros foram removidos com sucesso.` 
    });

  } catch (error) {
    // 2. Tratamento de Erro de Chave Estrangeira (O CORAÇÃO DO BLOCO 50)
    if (error.code === '23503') {
      return res.status(409).json({ 
        erro: "Bloqueio de Integridade: Esta empresa possui linhas de produção, funcionários ou contratos ativos no Hórus.",
        sugestao: "Remova os vínculos ou arquive a empresa em vez de excluí-la."
      });
    }

    console.error("❌ Falha crítica na exclusão:", error.message);
    res.status(500).json({ erro: "Erro sistêmico ao processar a exclusão." });
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

/**
 * 3️⃣ GERAR SUGESTÕES DE MELHORIA - CORRIGIDO
 * Analisa dados da empresa e retorna ações prioritárias
 */
app.get("/api/ia/sugestoes/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;

  try {
    // 1. Verificar se a empresa existe
    const empresaRes = await pool.query(
      "SELECT id, nome, segmento, status FROM empresas WHERE id = $1",
      [empresaId]
    );

    if (empresaRes.rows.length === 0) {
      return res.status(404).json({ 
        erro: "Empresa não encontrada",
        sugestoes: {
          resumo: "Empresa não encontrada no sistema.",
          acoes: []
        }
      });
    }

    const empresa = empresaRes.rows[0];

    // 2. Buscar linhas da empresa
    const linhasRes = await pool.query(
      "SELECT * FROM linhas_producao WHERE empresa_id = $1",
      [empresaId]
    );
    
    const linhas = linhasRes.rows;
    
    if (linhas.length === 0) {
      return res.status(200).json({
        sugestoes: {
          resumo: `A empresa ${empresa.nome} ainda não possui linhas de produção cadastradas. Cadastre as linhas para gerar sugestões de melhoria.`,
          acoes: [
            {
              titulo: "Cadastre as linhas de produção",
              descricao: "Acesse o módulo de Linhas e cadastre as linhas de produção da empresa.",
              prioridade: "alta",
              ganho: "R$ 0",
              esforco: "30 minutos",
              investimento: "R$ 0"
            }
          ],
          projecoes: {
            novoOEE: "N/A",
            ganhoMensal: "R$ 0",
            tempoEstimado: "N/A"
          }
        }
      });
    }

    let totalOEE = 0;
    let totalPerdas = 0;
    let qtdOEE = 0;
    const acoes = [];

    for (const linha of linhas) {
      // Buscar análise da linha (tabela analise_linha) - PODE NÃO EXISTIR
      let analiseRes;
      try {
        analiseRes = await pool.query(
          "SELECT eficiencia_percentual FROM analise_linha WHERE linha_id = $1 ORDER BY data_analise DESC LIMIT 1",
          [linha.id]
        );
      } catch (err) {
        console.log(`⚠️ Tabela analise_linha pode não existir: ${err.message}`);
        analiseRes = { rows: [] };
      }

      if (analiseRes.rows.length > 0) {
        const oee = parseFloat(analiseRes.rows[0].eficiencia_percentual) || 0;
        totalOEE += oee;
        qtdOEE++;

        if (oee < 60) {
          acoes.push({
            titulo: `Intervenção crítica na linha ${linha.nome}`,
            descricao: `OEE de ${oee}% está muito abaixo do ideal (mínimo 85%). Realizar diagnóstico detalhado imediatamente.`,
            prioridade: "alta",
            ganho: "R$ 15.000 - R$ 25.000/mês",
            esforco: "2 semanas",
            investimento: "R$ 8.000 - R$ 12.000"
          });
        } else if (oee < 75) {
          acoes.push({
            titulo: `Otimização da linha ${linha.nome}`,
            descricao: `OEE de ${oee}% - potencial para atingir 85% com melhorias focadas.`,
            prioridade: "media",
            ganho: "R$ 8.000 - R$ 15.000/mês",
            esforco: "3 semanas",
            investimento: "R$ 5.000 - R$ 8.000"
          });
        }
      } else {
        // Se não tem análise, adicionar sugestão para coletar dados
        acoes.push({
          titulo: `Coletar dados da linha ${linha.nome}`,
          descricao: "Registre medições de ciclo, perdas e produção para gerar análises precisas.",
          prioridade: "media",
          ganho: "Dados para tomada de decisão",
          esforco: "1 semana",
          investimento: "R$ 0"
        });
      }

      // Buscar postos com setup alto - COM TRATAMENTO DE ERRO
      let postosRes;
      try {
        postosRes = await pool.query(
          "SELECT * FROM posto_trabalho WHERE linha_id = $1 AND tempo_setup_minutos > 20",
          [linha.id]
        );
      } catch (err) {
        console.log(`⚠️ Erro ao buscar postos: ${err.message}`);
        postosRes = { rows: [] };
      }

      if (postosRes.rows && postosRes.rows.length > 0) {
        acoes.push({
          titulo: `Redução de setup na linha ${linha.nome}`,
          descricao: `${postosRes.rows.length} postos com setup acima de 20 minutos. Aplicar metodologia SMED.`,
          prioridade: "alta",
          ganho: "R$ 12.000 - R$ 20.000/mês",
          esforco: "4 semanas",
          investimento: "R$ 10.000 - R$ 15.000"
        });
      }

      // Buscar perdas registradas - COM TRATAMENTO DE ERRO
      let perdasRes;
      try {
        perdasRes = await pool.query(
          `SELECT 
            COALESCE(SUM(pl.microparadas_minutos), 0) as micro, 
            COALESCE(SUM(pl.refugo_pecas), 0) as refugo 
          FROM perdas_linha pl 
          JOIN linha_produto lp ON lp.id = pl.linha_produto_id 
          WHERE lp.linha_id = $1`,
          [linha.id]
        );
      } catch (err) {
        console.log(`⚠️ Erro ao buscar perdas: ${err.message}`);
        perdasRes = { rows: [{ micro: 0, refugo: 0 }] };
      }

      const micro = parseFloat(perdasRes.rows[0]?.micro) || 0;
      const refugo = parseFloat(perdasRes.rows[0]?.refugo) || 0;

      if (micro > 100) {
        totalPerdas += micro * 10;
        acoes.push({
          titulo: `Redução de microparadas na linha ${linha.nome}`,
          descricao: `${Math.round(micro)} minutos de microparadas registrados. Análise de causa raiz recomendada.`,
          prioridade: "media",
          ganho: "R$ 6.000 - R$ 10.000/mês",
          esforco: "2 semanas",
          investimento: "R$ 3.000 - R$ 5.000"
        });
      }

      if (refugo > 50) {
        totalPerdas += refugo * 50;
        acoes.push({
          titulo: `Controle de qualidade na linha ${linha.nome}`,
          descricao: `${Math.round(refugo)} peças de refugo registradas. Análise de causa raiz e implementação de SPC.`,
          prioridade: "alta",
          ganho: "R$ 10.000 - R$ 18.000/mês",
          esforco: "3 semanas",
          investimento: "R$ 7.000 - R$ 12.000"
        });
      }
    }

    const oeeMedio = qtdOEE > 0 ? (totalOEE / qtdOEE).toFixed(1) : 0;
    const ganhoMensalEstimado = Math.max(5000, Math.min(50000, totalPerdas * 0.3));

    // Se poucas ações, adicionar sugestões genéricas
    if (acoes.length < 2) {
      acoes.push({
        titulo: "Treinamento em Ferramentas Lean",
        descricao: "Capacitar equipe em técnicas de melhoria contínua (5S, Kaizen, SMED, VSM).",
        prioridade: "baixa",
        ganho: "R$ 4.000 - R$ 8.000/mês",
        esforco: "1 semana",
        investimento: "R$ 2.000 - R$ 3.000"
      });
      
      acoes.push({
        titulo: "Implementação de Gestão Visual",
        descricao: "Criar quadros de indicadores e gestão à vista no chão de fábrica.",
        prioridade: "baixa",
        ganho: "R$ 3.000 - R$ 6.000/mês",
        esforco: "2 semanas",
        investimento: "R$ 1.500 - R$ 2.500"
      });
    }

    // Ordenar por prioridade
    const prioridadeOrder = { alta: 1, media: 2, baixa: 3 };
    acoes.sort((a, b) => prioridadeOrder[a.prioridade] - prioridadeOrder[b.prioridade]);

    // Gerar resumo personalizado
    let resumoTexto = "";
    if (oeeMedio > 0 && oeeMedio < 85) {
      resumoTexto = `A empresa ${empresa.nome} apresenta OEE médio de ${oeeMedio}%. Identificamos ${acoes.length} oportunidades de melhoria com potencial de redução de perdas de R$ ${ganhoMensalEstimado.toLocaleString('pt-BR')}/mês.`;
    } else if (oeeMedio >= 85) {
      resumoTexto = `Excelente! A empresa ${empresa.nome} já opera com OEE de ${oeeMedio}%, acima do benchmark de classe mundial (85%). Foco em manutenção da performance e melhoria contínua.`;
    } else if (qtdOEE === 0) {
      resumoTexto = `A empresa ${empresa.nome} possui ${linhas.length} linhas cadastradas, mas ainda não há dados de análise de OEE. Complete o cadastro das linhas e registre as medições para gerar sugestões personalizadas.`;
    } else {
      resumoTexto = `A empresa ${empresa.nome} está com desempenho dentro da média. Identificamos ${acoes.length} oportunidades de melhoria que podem gerar ganhos significativos.`;
    }

    res.status(200).json({
      sugestoes: {
        resumo: resumoTexto,
        acoes: acoes.slice(0, 6),
        projecoes: {
          novoOEE: oeeMedio > 0 ? `${Math.min(85, Math.round(oeeMedio * 1.2))}%` : "A definir",
          ganhoMensal: `R$ ${ganhoMensalEstimado.toLocaleString('pt-BR')}`,
          tempoEstimado: oeeMedio < 60 ? "3 meses" : oeeMedio < 75 ? "2 meses" : oeeMedio > 0 ? "1-2 meses" : "A definir",
          roiEstimado: "280% ao ano"
        }
      }
    });

  } catch (error) {
    console.error("❌ Erro ao gerar sugestões IA:", error.message);
    console.error("Detalhes:", error.stack);
    
    // Retorna um erro amigável sem quebrar o frontend
    res.status(200).json({ 
      sugestoes: {
        resumo: "Não foi possível analisar os dados neste momento. Verifique se as tabelas do banco estão configuradas corretamente.",
        acoes: [
          {
            titulo: "Complete o cadastro da empresa",
            descricao: "Cadastre linhas de produção, postos de trabalho e registre perdas para gerar sugestões personalizadas.",
            prioridade: "alta",
            ganho: "R$ 0",
            esforco: "1 semana",
            investimento: "R$ 0"
          },
          {
            titulo: "Registre medições de ciclo",
            descricao: "Utilize o módulo de cronoanálise para coletar dados de tempo de ciclo dos postos.",
            prioridade: "media",
            ganho: "Dados precisos para análise",
            esforco: "2 dias",
            investimento: "R$ 0"
          }
        ],
        projecoes: {
          novoOEE: "A definir",
          ganhoMensal: "R$ 0",
          tempoEstimado: "A definir",
          roiEstimado: "A definir"
        }
      }
    });
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
app.post("/api/ia/precificar", autenticarToken, async (req, res) => {
  try {
    const dados = req.body;

    // ========================================
    // VALIDAÇÃO DOS DADOS DE ENTRADA
    // ========================================
    if (!dados.setor || !dados.faturamento_anual || dados.faturamento_anual <= 0) {
      return res.status(400).json({ 
        erro: "Setor e faturamento anual são obrigatórios para precificação." 
      });
    }

    // ========================================
    // BENCHMARKS POR SETOR (VALORES REALISTAS DE MERCADO - CORRIGIDOS)
    // ========================================
    const benchmarks = {
      automotivo: { 
        perda_percentual: 0.06,
        oee_medio: 78, 
        potencial_melhoria: 0.12,
        horas_diagnostico_por_linha: 25,
        horas_implementacao_por_linha: 60,
        preco_base: 22000
      },
      metalurgico: { 
        perda_percentual: 0.07,
        oee_medio: 72, 
        potencial_melhoria: 0.12,
        horas_diagnostico_por_linha: 28,
        horas_implementacao_por_linha: 65,
        preco_base: 20000
      },
      alimenticio: { 
        perda_percentual: 0.05,
        oee_medio: 82, 
        potencial_melhoria: 0.10,
        horas_diagnostico_por_linha: 20,
        horas_implementacao_por_linha: 50,
        preco_base: 18000
      },
      quimico: { 
        perda_percentual: 0.06,
        oee_medio: 80, 
        potencial_melhoria: 0.11,
        horas_diagnostico_por_linha: 25,
        horas_implementacao_por_linha: 60,
        preco_base: 20000
      },
      farmaceutico: { 
        perda_percentual: 0.04,
        oee_medio: 85, 
        potencial_melhoria: 0.08,
        horas_diagnostico_por_linha: 25,
        horas_implementacao_por_linha: 60,
        preco_base: 18000
      },
      outros: { 
        perda_percentual: 0.06,
        oee_medio: 75, 
        potencial_melhoria: 0.12,
        horas_diagnostico_por_linha: 25,
        horas_implementacao_por_linha: 60,
        preco_base: 18000
      }
    };

    // ========================================
    // APRENDIZADO: AJUSTAR BENCHMARKS COM DADOS REAIS DE PROJETOS ANTERIORES
    // ========================================
    try {
      const projetosAnteriores = await pool.query(`
        SELECT 
          e.segmento as setor,
          AVG(pl.refugo_pecas) as media_refugo,
          AVG(pl.microparadas_minutos) as media_microparadas,
          COUNT(*) as total_projetos
        FROM perdas_linha pl
        JOIN linha_produto lp ON lp.id = pl.linha_produto_id
        JOIN linha_producao l ON l.id = lp.linha_id
        JOIN empresas e ON e.id = l.empresa_id
        WHERE e.segmento ILIKE $1
        GROUP BY e.segmento
      `, [`%${dados.setor}%`]);

      if (projetosAnteriores.rows.length > 0) {
        const aprendizado = projetosAnteriores.rows[0];
        if (aprendizado.media_refugo > 100) {
          benchmarks[dados.setor].potencial_melhoria += 0.005;
        }
        if (aprendizado.media_microparadas > 200) {
          benchmarks[dados.setor].potencial_melhoria += 0.005;
        }
        console.log(`📊 Aprendizado aplicado: ${aprendizado.total_projetos} projetos anteriores do setor ${dados.setor}`);
      }
    } catch (err) {
      console.log("ℹ️ Sem dados históricos para aprendizado ainda.");
    }

    const benchmark = benchmarks[dados.setor] || benchmarks.outros;
    const numeroLinhas = Math.max(1, dados.numero_linhas || 1);

    // ========================================
    // ESTIMAR PERDAS ATUAIS
    // ========================================
    const perdaAnualEstimada = dados.faturamento_anual * benchmark.perda_percentual;
    const perdaMensalEstimada = perdaAnualEstimada / 12;

    // ========================================
    // AJUSTAR POTENCIAL DE MELHORIA BASEADO NOS PROBLEMAS
    // ========================================
    let fatorComplexidade = 1.0;
    
    if (dados.problemas) {
      if (dados.problemas.includes('produtividade')) fatorComplexidade += 0.01;
      if (dados.problemas.includes('qualidade')) fatorComplexidade += 0.01;
      if (dados.problemas.includes('manutencao')) fatorComplexidade += 0.005;
      if (dados.problemas.includes('rh')) fatorComplexidade += 0.005;
    }
    
    if (dados.complexidade === 'alta') fatorComplexidade += 0.05;
    if (dados.complexidade === 'baixa') fatorComplexidade -= 0.03;
    
    // Limitar potencial de melhoria entre 5% e 15%
    let potencialMelhoria = benchmark.potencial_melhoria * fatorComplexidade;
    potencialMelhoria = Math.min(0.15, Math.max(0.05, potencialMelhoria));
    
    const ganhoAnualEstimado = perdaAnualEstimada * potencialMelhoria;
    const ganhoMensalEstimado = ganhoAnualEstimado / 12;

    // ========================================
    // PREÇO DO PROJETO (BASEADO EM VALOR PARA O CLIENTE)
    // ========================================
    
    // 1. Preço base = 20% do ganho anual estimado (benchmark de mercado)
    let precoProjeto = ganhoAnualEstimado * 0.20;
    
    // 2. Mínimo para projetos de valor: R$ 30.000
    if (precoProjeto < 30000) precoProjeto = 30000;
    
    // 3. Aplicar fatores de valor agregado (sua expertise + Hórus)
    const FATOR_FORMACAO = 1.15;      // Engenharia FEI + Pós FGV
    const FATOR_HORUS = 1.20;         // Plataforma proprietária
    const FATOR_METODOLOGIA = 1.10;   // Método Nexus comprovado
    
    precoProjeto = precoProjeto * FATOR_FORMACAO * FATOR_HORUS * FATOR_METODOLOGIA;
    
    // 4. Ajustes por número de linhas (+R$ 5.000 por linha adicional)
    if (numeroLinhas > 1) {
      precoProjeto += (numeroLinhas - 1) * 5000;
    }
    
    // 5. Ajustes por complexidade
    if (dados.complexidade === 'alta') precoProjeto *= 1.15;
    if (dados.complexidade === 'baixa') precoProjeto *= 0.95;
    
    // 6. Ajustes por urgência
    if (dados.urgencia === 'alta') precoProjeto *= 1.10;
    if (dados.urgencia === 'baixa') precoProjeto *= 0.95;
    
    // 7. Ajuste por acesso a dados (restrito = mais trabalho)
    if (dados.acesso_dados === 'restrito') precoProjeto *= 1.10;
    
    // 8. Projeto piloto (desconto para primeiro cliente)
    if (dados.projeto_piloto) precoProjeto *= 0.85;
    
    // 9. Limitar faixa de preço (mínimo R$ 30.000, máximo R$ 150.000)
    precoProjeto = Math.min(150000, Math.max(30000, Math.round(precoProjeto / 5000) * 5000));

    // ========================================
    // FAIXA DE NEGOCIAÇÃO (15% para baixo, 30% para cima)
    // ========================================
    const precoMinimo = Math.round(precoProjeto * 0.85 / 1000) * 1000;
    const precoMaximo = Math.round(precoProjeto * 1.3 / 1000) * 1000;

    // ========================================
    // PREÇO DA FASE 1 (DIAGNÓSTICO) - 30% DO TOTAL
    // ========================================
    let precoFase1 = Math.round(precoProjeto * 0.3 / 1000) * 1000;
    if (precoFase1 < 4000) precoFase1 = 4000;
    if (precoFase1 > 15000) precoFase1 = 15000;

    // ========================================
    // GERAR RESUMO PARA PROPOSTA (SEM ESTIMATIVAS DE GANHO)
    // ========================================
    let resumo = `
📊 ANÁLISE HÓRUS - PROPOSTA PRÉ-DIAGNÓSTICO

Empresa: ${dados.empresa_nome || "Cliente"}
Setor: ${dados.setor}
Data: ${new Date().toLocaleDateString('pt-BR')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 ESCOPO DA FASE 1 (DIAGNÓSTICO)

• Mapeamento do fluxo de valor (VSM) das áreas produtivas
• Coleta e análise de dados operacionais (tempos de ciclo, disponibilidade, qualidade)
• Identificação de gargalos e oportunidades de melhoria
• Elaboração e entrega de relatório técnico contendo diagnóstico e recomendações

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💰 INVESTIMENTO - FASE 1

• Valor total: R$ ${precoFase1.toLocaleString('pt-BR')}
• Forma de pagamento: 100% na assinatura (ou conforme negociado)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 PRÓXIMOS PASSOS

1. Assinar contrato e iniciar diagnóstico
2. Coletar dados reais com a plataforma Hórus
3. Receber relatório técnico com diagnóstico e oportunidades identificadas
4. Após o diagnóstico, apresentaremos proposta para a Fase 2 (Implementação) e Fase 3 (Acompanhamento), com preços baseados nos dados reais coletados

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️ IMPORTANTE

• Este contrato cobre exclusivamente a Fase 1 (Diagnóstico)
• As estimativas de ganho e ROI serão fornecidas APÓS a coleta de dados reais
• A CONTRATADA não garante percentuais específicos de melhoria antes do diagnóstico
• Os resultados dependem da implementação das recomendações pela CONTRATANTE

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Esta proposta é válida por 15 dias.

Atenciosamente,

Nexus Engenharia Aplicada
    `;

    // ========================================
    // RETORNAR RESULTADO (SEM ESTIMATIVAS DE GANHO)
    // ========================================
    res.status(200).json({
      status: "sucesso",
      empresa: dados.empresa_nome || "Cliente",
      data_calculo: new Date().toISOString(),
      
      precos: {
        minimo: precoMinimo,
        ideal: precoProjeto,
        maximo: precoMaximo,
        fase1: precoFase1
      },
      
      resumo: resumo,
      
      dados_para_proposta: {
        empresa: dados.empresa_nome,
        honorarios: precoProjeto,
        fase1: precoFase1,
        setor: dados.setor,
        linhas: numeroLinhas
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

    // TEXTO PURO COM FORMATAÇÃO LIMPA
    const contrato = `
CONTRATO DE PRESTAÇÃO DE SERVIÇOS DE CONSULTORIA - FASE 1 (DIAGNÓSTICO)

CONTRATANTE: ${empresa.nome}, pessoa jurídica de direito privado, inscrita no CNPJ sob o nº ${empresa.cnpj}, com sede na ${empresa.endereco}, neste ato representada por ${representante.nome}, ${representante.nacionalidade}, ${representante.estado_civil}, ${representante.profissao}, portador do RG nº ${representante.rg} e CPF nº ${representante.cpf}, residente e domiciliado na ${representante.endereco}.

CONTRATADA: NEXUS ENGENHARIA APLICADA, pessoa jurídica de direito privado, inscrita no CNPJ sob o nº [CNPJ DA NEXUS], com sede na [ENDEREÇO DA NEXUS], neste ato representada por [SEU NOME], [NACIONALIDADE], [ESTADO CIVIL], [PROFISSÃO], portador do RG nº [RG] e CPF nº [CPF], residente e domiciliado na [ENDEREÇO].

As partes, acima identificadas, têm entre si justo e contratado o seguinte:

-------------------------------------------------------------------------------
CLÁUSULA 1 – OBJETO
-------------------------------------------------------------------------------

1.1. O presente contrato tem por objeto a prestação de serviços de consultoria em engenharia de produção, limitados à Fase 1 – Diagnóstico, conforme descrito no Anexo I, que passa a fazer parte integrante deste instrumento.

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

-------------------------------------------------------------------------------
CLÁUSULA 2 – OBRIGAÇÕES DA CONTRATADA
-------------------------------------------------------------------------------

2.1. Executar os serviços com diligência, empregando as melhores práticas e técnicas de engenharia disponíveis, observando os padrões éticos e técnicos da profissão.

2.2. Fornecer equipe técnica qualificada e compatível com a natureza dos serviços, sendo a CONTRATADA a única responsável pela sua seleção, supervisão e remuneração.

2.3. Entregar o relatório de diagnóstico no prazo estipulado na Cláusula 5.

2.4. Manter absoluto sigilo sobre todas as informações da CONTRATANTE a que tiver acesso, conforme Cláusula 7.

2.5. Informar à CONTRATANTE, por escrito, qualquer fato ou circunstância que possa comprometer a execução dos serviços ou os resultados esperados.

2.6. A responsabilidade da CONTRATADA é de MEIO, não de resultado, não respondendo por resultados específicos que dependam de fatores alheios ao seu controle, tais como:
   a) Falta de engajamento ou disponibilidade da equipe da CONTRATANTE;
   b) Recusa da CONTRATANTE em implementar as recomendações;
   c) Condições operacionais não informadas previamente.

-------------------------------------------------------------------------------
CLÁUSULA 3 – OBRIGAÇÕES DA CONTRATANTE
-------------------------------------------------------------------------------

3.1. Fornecer acesso irrestrito às áreas produtivas, instalações, equipamentos e informações necessárias à execução dos serviços, durante o horário de trabalho normal da CONTRATANTE ou conforme acordado entre as partes.

3.2. Indicar, por escrito, um responsável técnico que atuará como contato oficial durante a vigência do contrato, devendo este ser autorizado a tomar decisões e fornecer informações em nome da CONTRATANTE.

3.3. Disponibilizar, no prazo de 5 (cinco) dias úteis a contar da solicitação da CONTRATADA, todos os dados históricos de produção, manutenção, qualidade e quaisquer outros documentos ou informações que se façam necessários à execução dos serviços.

3.4. Efetuar os pagamentos nas datas e condições estipuladas na Cláusula 4.

3.5. Fornecer, às suas expensas, os equipamentos de proteção individual (EPIs) necessários para que a equipe da CONTRATADA acesse as áreas produtivas, em conformidade com as normas de segurança aplicáveis.

3.6. Comunicar imediatamente à CONTRATADA qualquer alteração nas condições operacionais ou estruturais que possa impactar a execução dos serviços.

3.7. A CONTRATANTE declara estar ciente de que os resultados do diagnóstico dependem diretamente da qualidade e veracidade das informações fornecidas, assumindo integral responsabilidade por eventuais imprecisões ou omissões.

-------------------------------------------------------------------------------
CLÁUSULA 4 – VALOR E CONDIÇÕES DE PAGAMENTO
-------------------------------------------------------------------------------

4.1. O valor total dos serviços objeto deste contrato é de ${formatarMoeda(valorNegociado)} (${valorNegociado.toLocaleString('pt-BR')} reais).

4.1.1. O valor total estimado para o projeto completo (Fase 1 + Fase 2 + Fase 3) é de ${formatarMoeda(valorOriginalIA)}. O presente contrato refere-se exclusivamente à Fase 1 (Diagnóstico), no valor de ${formatarMoeda(valorNegociado)}, sendo que as Fases 2 e 3 serão objeto de contrato ou aditivo específico, após a conclusão do diagnóstico e com base nos dados reais coletados.

4.2. O pagamento será efetuado em parcela única, na seguinte condição:
   Data de assinatura: ${formatarMoeda(valorNegociado)}

4.3. O pagamento deverá ser efetuado mediante depósito/transferência bancária para a conta:
   Banco: [BANCO]
   Agência: [AGÊNCIA]
   Conta: [CONTA]
   Titular: NEXUS ENGENHARIA APLICADA
   CNPJ: [CNPJ DA NEXUS]

4.4. O comprovante de pagamento deverá ser enviado à CONTRATADA por e-mail em até 24 (vinte e quatro) horas após a efetivação, sob pena de suspensão dos serviços até a regularização.

4.5. O atraso no pagamento sujeitará a CONTRATANTE a:
   a) Multa moratória de 2% (dois por cento) sobre o valor total da parcela em atraso;
   b) Juros de mora de 1% (um por cento) ao mês, calculados pro rata die;
   c) Correção monetária pelo índice IPCA (Índice de Preços ao Consumidor Amplo), ou outro índice oficial que venha a substituí-lo, contada da data do vencimento até a data do efetivo pagamento.

4.6. Em caso de inadimplemento, a CONTRATADA poderá suspender imediatamente a execução dos serviços até a regularização do pagamento, sem prejuízo da cobrança dos encargos previstos.

-------------------------------------------------------------------------------
CLÁUSULA 5 – PRAZO E VIGÊNCIA
-------------------------------------------------------------------------------

5.1. O presente contrato terá vigência de ${prazos.meses_vigencia} meses, contados da data de assinatura, ou até a entrega do relatório de diagnóstico, o que ocorrer primeiro.

5.2. O início dos serviços está condicionado ao pagamento da parcela prevista na Cláusula 4.2 e à disponibilização das informações e acessos previstos na Cláusula 3.

5.3. O prazo para entrega do relatório de diagnóstico é de ${prazos.prazo_entrega_semanas} semanas, contadas da data de início efetivo dos serviços.

-------------------------------------------------------------------------------
CLÁUSULA 6 – PROPRIEDADE INTELECTUAL
-------------------------------------------------------------------------------

6.1. Toda a metodologia, know-how, softwares, sistemas (incluindo, mas não se limitando, à plataforma Hórus), técnicas, ferramentas, modelos, planilhas, procedimentos, materiais de treinamento e quaisquer outros ativos intelectuais desenvolvidos ou utilizados pela CONTRATADA na execução dos serviços são de sua propriedade exclusiva, constituindo segredo de negócio.

6.2. A CONTRATANTE não adquire, por força deste contrato, qualquer direito de propriedade sobre a metodologia, softwares ou ferramentas da CONTRATADA, incluindo, expressamente, a plataforma Hórus.

6.3. É expressamente proibido à CONTRATANTE:
   a) Copiar, reproduzir, modificar, descompilar ou realizar engenharia reversa da plataforma Hórus ou de qualquer ferramenta da CONTRATADA;
   b) Utilizar a metodologia da CONTRATADA para prestar serviços a terceiros;
   c) Reproduzir, no todo ou em parte, os relatórios ou documentos entregues para finalidade diversa daquela para a qual foram elaborados.

6.4. Os relatórios e documentos entregues à CONTRATANTE destinam-se ao seu uso exclusivo no âmbito do objeto contratado, sendo vedada sua divulgação a terceiros sem a prévia e expressa autorização por escrito da CONTRATADA.

6.5. A violação desta cláusula sujeitará a parte infratora ao pagamento de multa equivalente a 10 (dez) vezes o valor total deste contrato, sem prejuízo das perdas e danos e demais sanções cabíveis.

-------------------------------------------------------------------------------
CLÁUSULA 7 – CONFIDENCIALIDADE
-------------------------------------------------------------------------------

7.1. As partes obrigam-se a manter absoluto sigilo sobre todas as informações confidenciais a que tiverem acesso em razão deste contrato, considerando-se como tais:
   a) Dados operacionais, financeiros, estratégicos, de produção, qualidade, manutenção, custos e quaisquer informações de negócio da CONTRATANTE;
   b) Metodologia, softwares, ferramentas, técnicas e know-how da CONTRATADA;
   c) Qualquer informação expressamente identificada como confidencial.

7.2. A obrigação de confidencialidade estende-se pelo prazo de 5 (cinco) anos após o término deste contrato.

7.3. A violação desta cláusula sujeitará a parte infratora ao pagamento de multa de R$ 50.000,00 (cinquenta mil reais) por evento de violação, sem prejuízo das perdas e danos e demais sanções cabíveis.

7.4. Não se considera violação da confidencialidade a divulgação de informações:
   a) Exigidas por determinação judicial ou legal;
   b) Já em domínio público;
   c) Autorizadas previamente por escrito pela parte titular.

-------------------------------------------------------------------------------
CLÁUSULA 8 – RESCISÃO
-------------------------------------------------------------------------------

8.1. O presente contrato poderá ser rescindido por qualquer das partes, mediante notificação por escrito, nas seguintes hipóteses:
   a) Descumprimento de qualquer cláusula contratual, não sanado no prazo de 15 (quinze) dias úteis após o recebimento da notificação;
   b) Por interesse exclusivo de qualquer das partes, mediante aviso prévio de 30 (trinta) dias, sem justa causa;
   c) Por caso fortuito ou força maior que impeça a execução do objeto, assim reconhecido judicialmente.

8.2. Em caso de rescisão unilateral sem justa causa pela CONTRATANTE, será devida multa de 20% (vinte por cento) sobre o saldo remanescente do contrato, calculado com base no valor total previsto na Cláusula 4.1.

8.3. Em caso de rescisão por descumprimento da CONTRATADA, esta restituirá à CONTRATANTE os valores já pagos, atualizados monetariamente, e pagará multa de 20% (vinte por cento) sobre o valor total do contrato.

8.4. Em caso de rescisão por descumprimento da CONTRATANTE, esta pagará à CONTRATADA os serviços já prestados, atualizados monetariamente, e multa de 20% (vinte por cento) sobre o valor total do contrato.

8.5. A rescisão não exonera as partes das obrigações de confidencialidade previstas na Cláusula 7 e das penalidades eventualmente já incorridas.

-------------------------------------------------------------------------------
CLÁUSULA 9 – PENALIDADES
-------------------------------------------------------------------------------

9.1. Pelo descumprimento de qualquer obrigação contratual não especificamente penalizada em outras cláusulas, será aplicada multa de 10% (dez por cento) sobre o valor total do contrato, sem prejuízo da obrigação principal.

9.2. As multas previstas neste contrato são independentes e acumuláveis, podendo ser exigidas cumulativamente quando configuradas as respectivas hipóteses.

9.3. A mora de qualquer das partes no cumprimento de suas obrigações sujeitará o infrator à incidência dos encargos previstos na Cláusula 4.5.

-------------------------------------------------------------------------------
CLÁUSULA 10 – DISPOSIÇÕES GERAIS
-------------------------------------------------------------------------------

10.1. Este contrato é celebrado em caráter intuitu personae em relação à CONTRATADA, não podendo a CONTRATANTE ceder ou transferir seus direitos e obrigações sem prévia e expressa anuência por escrito da CONTRATADA.

10.2. As comunicações entre as partes serão consideradas válidas quando enviadas por e-mail para os endereços abaixo, ou por correspondência com aviso de recebimento (AR):
   CONTRATANTE: ${contato.email_contratante}
   CONTRATADA: ${contato.email_contratada}

10.3. A tolerância quanto ao descumprimento de qualquer cláusula não constituirá novação, renúncia de direitos ou precedente, mantendo-se a exigibilidade das obrigações.

10.4. Qualquer modificação ou aditivo a este contrato deverá ser formalizado por escrito, com anuência de ambas as partes.

10.5. Os títulos das cláusulas são meramente descritivos e não vinculam a interpretação do contrato.

-------------------------------------------------------------------------------
CLÁUSULA 11 – FORO
-------------------------------------------------------------------------------

11.1. Fica eleito o foro da Comarca de [SUA CIDADE/ESTADO] para dirimir quaisquer questões decorrentes deste contrato, com renúncia expressa a qualquer outro, por mais privilegiado que seja.

-------------------------------------------------------------------------------
ANEXO I – ESCOPO DETALHADO DA FASE 1 (DIAGNÓSTICO)
-------------------------------------------------------------------------------

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

3.1. O prazo para execução da Fase 1 é de ${prazos.semanas_diagnostico} semanas, contadas da data de início efetivo dos serviços, conforme Cláusula 5.3.

3.2. O cronograma detalhado será apresentado na reunião de abertura e poderá ser ajustado por acordo entre as partes.

-------------------------------------------------------------------------------
ASSINATURAS
-------------------------------------------------------------------------------

E, por estarem assim justas e contratadas, as partes assinam o presente instrumento em 2 (duas) vias de igual teor e forma.

${empresa.cidade}, ${dataAssinatura}.

_________________________________
CONTRATANTE
${empresa.nome}
${representante.nome}
[Cargo]

_________________________________
CONTRATADA
NEXUS ENGENHARIA APLICADA
[SEU NOME]
[Cargo]

TESTEMUNHAS:

1. _________________________________
   Nome: _______________________________
   RG: _______________________________
   CPF: _______________________________

2. _________________________________
   Nome: _______________________________
   RG: _______________________________
   CPF: _______________________________
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

    // Buscar dados da empresa
    const empresaRes = await pool.query(
      "SELECT * FROM empresas WHERE id = $1",
      [dados.empresa_id]
    );

    if (empresaRes.rows.length === 0) {
      return res.status(404).json({ erro: "Empresa não encontrada" });
    }

    const empresa = empresaRes.rows[0];

    // Buscar dados para gerar resultados esperados
    const linhasRes = await pool.query(
      "SELECT * FROM linhas_producao WHERE empresa_id = $1",
      [dados.empresa_id]
    );
    const linhas = linhasRes.rows;

    let oeeAtual = 0;
    let perdasTotais = 0;
    let setupMaior = 0;
    let totalPostos = 0;

    for (const linha of linhas) {
      const analiseRes = await pool.query(
        "SELECT eficiencia_percentual FROM analise_linha WHERE linha_id = $1 ORDER BY data_analise DESC LIMIT 1",
        [linha.id]
      );
      if (analiseRes.rows.length > 0) {
        oeeAtual += parseFloat(analiseRes.rows[0].eficiencia_percentual);
      }

      const postosRes = await pool.query(
        "SELECT * FROM posto_trabalho WHERE linha_id = $1",
        [linha.id]
      );
      totalPostos += postosRes.rows.length;

      for (const posto of postosRes.rows) {
        if (posto.tempo_setup_minutos > setupMaior) {
          setupMaior = posto.tempo_setup_minutos;
        }
        if (posto.cargo_id) {
          const cargoRes = await pool.query(
            "SELECT salario_base, encargos_percentual FROM cargos WHERE id = $1",
            [posto.cargo_id]
          );
          if (cargoRes.rows.length > 0) {
            const cargo = cargoRes.rows[0];
            const salario = parseFloat(cargo.salario_base) || 0;
            const encargos = parseFloat(cargo.encargos_percentual) || 70;
            const custoMensal = salario * (1 + encargos / 100);
            perdasTotais += custoMensal * 0.2;
          }
        }
      }
    }

    oeeAtual = linhas.length > 0 ? oeeAtual / linhas.length : 0;
    const metaOEE = Math.min(85, Math.round(oeeAtual * 1.2));
    const valorTotal = dados.valor_total || Math.round(perdasTotais * 0.3 * 12 * 0.4);
    const prazoImplementacao = dados.prazo_implementacao_semanas || 6;
    const prazoAcompanhamento = dados.prazo_acompanhamento_meses || 3;
    const dataAssinatura = dados.data_assinatura || new Date().toLocaleDateString('pt-BR');

    const representante = {
      nome: dados.representante?.nome || "[NOME DO REPRESENTANTE]",
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

    const contrato = `
CONTRATO DE PRESTAÇÃO DE SERVIÇOS DE CONSULTORIA - FASE 2 (IMPLEMENTAÇÃO) E FASE 3 (ACOMPANHAMENTO)

CONTRATANTE: ${empresa.nome}, pessoa jurídica de direito privado, inscrita no CNPJ sob o nº ${empresa.cnpj || '[CNPJ]'}, com sede na ${empresa.endereco || '[ENDEREÇO]'}, neste ato representada por ${representante.nome}, ${representante.nacionalidade}, ${representante.estado_civil}, ${representante.profissao}, portador do RG nº ${representante.rg} e CPF nº ${representante.cpf}, residente e domiciliado na ${representante.endereco}.

CONTRATADA: NEXUS ENGENHARIA APLICADA, pessoa jurídica de direito privado, inscrita no CNPJ sob o nº [CNPJ DA NEXUS], com sede na [ENDEREÇO DA NEXUS], neste ato representada por [SEU NOME], [NACIONALIDADE], [ESTADO CIVIL], [PROFISSÃO], portador do RG nº [RG] e CPF nº [CPF], residente e domiciliado na [ENDEREÇO].

As partes, acima identificadas, têm entre si justo e contratado o seguinte:


-------------------------------------------------------------------------------
CLÁUSULA 1 – OBJETO
-------------------------------------------------------------------------------

1.1. O presente contrato tem por objeto a prestação de serviços de consultoria em engenharia de produção, compreendendo as Fases 2 e 3, com base nos resultados da Fase 1 (Diagnóstico) previamente concluída.

1.2. FASE 2 – IMPLEMENTAÇÃO (${prazoImplementacao} semanas)

   a) SMED (Troca Rápida de Ferramentas): Implementação nos postos gargalo identificados no diagnóstico, visando redução mínima de 50% no tempo de setup;

   b) Balanceamento de Linha: Redistribuição das atividades entre os postos para equalizar a carga de trabalho e eliminar gargalos;

   c) Padronização de Processos: Elaboração e implementação de Procedimentos Operacionais Padrão (POPs) para as atividades críticas;

   d) Treinamento da Equipe: Capacitação dos operadores e lideranças em ferramentas de Manufatura Enxuta (20 horas presenciais);

   e) Gestão Visual: Implantação de quadros de indicadores no chão de fábrica para acompanhamento em tempo real;

   f) 5S: Implementação da metodologia nos postos de trabalho prioritários.

1.3. FASE 3 – ACOMPANHAMENTO (${prazoAcompanhamento} meses)

   a) Monitoramento Semanal: Acompanhamento dos indicadores (OEE, produtividade, qualidade) com análise de tendências;

   b) Reuniões de Acompanhamento: 1 hora semanal com a liderança para análise de resultados e definição de ações corretivas;

   c) Ajustes Finos: Correções e otimizações nos processos implementados;

   d) Transferência de Conhecimento: Capacitação da equipe interna para sustentar os resultados;

   e) Relatórios Mensais: Documentação da evolução dos indicadores e resultados alcançados;

   f) Plano de Sustentação: Metodologia para manutenção dos ganhos após o término do contrato.


-------------------------------------------------------------------------------
CLÁUSULA 2 – RESULTADOS ESPERADOS
-------------------------------------------------------------------------------

2.1. Com base no diagnóstico realizado na Fase 1, estimamos os seguintes resultados:

   OEE:
   - Situação atual: ${oeeAtual.toFixed(1)}%
   - Meta após implementação: ${metaOEE}%
   - Ganho projetado: ${(metaOEE - oeeAtual).toFixed(1)}%

   Setup (postos gargalo):
   - Situação atual: ${setupMaior} minutos
   - Meta após implementação: ${Math.round(setupMaior * 0.5)} minutos
   - Redução projetada: 50%

   Perdas Totais:
   - Situação atual: R$ ${perdasTotais.toLocaleString('pt-BR')}/mês
   - Meta após implementação: R$ ${(perdasTotais * 0.7).toLocaleString('pt-BR')}/mês
   - Economia projetada: R$ ${(perdasTotais * 0.3).toLocaleString('pt-BR')}/mês

   Indicadores Financeiros:
   - ROI estimado: ${((perdasTotais * 0.3 * 12 / valorTotal) * 100).toFixed(0)}% ao ano
   - Payback estimado: ${(valorTotal / (perdasTotais * 0.3)).toFixed(1)} meses

2.2. Os resultados acima são estimativas baseadas no diagnóstico e nas melhores práticas do setor. Os resultados finais serão medidos e documentados ao longo da execução.

2.3. A CONTRATADA não garante percentuais específicos de melhoria, comprometendo-se a empregar as melhores técnicas e esforços para atingir os objetivos.


-------------------------------------------------------------------------------
CLÁUSULA 3 – OBRIGAÇÕES DA CONTRATADA
-------------------------------------------------------------------------------

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


-------------------------------------------------------------------------------
CLÁUSULA 4 – OBRIGAÇÕES DA CONTRATANTE
-------------------------------------------------------------------------------

4.1. Fornecer acesso irrestrito às áreas produtivas, instalações, equipamentos e informações necessárias à execução dos serviços, durante o horário de trabalho normal da CONTRATANTE ou conforme acordado entre as partes.

4.2. Indicar, por escrito, um responsável técnico que atuará como contato oficial durante a vigência do contrato, devendo este ser autorizado a tomar decisões e fornecer informações em nome da CONTRATANTE.

4.3. Disponibilizar, no prazo de 5 (cinco) dias úteis a contar da solicitação da CONTRATADA, todos os dados históricos de produção, manutenção, qualidade e quaisquer outros documentos ou informações que se façam necessários à execução dos serviços.

4.4. Efetuar os pagamentos nas datas e condições estipuladas na Cláusula 5.

4.5. Fornecer, às suas expensas, os equipamentos de proteção individual (EPIs) necessários para que a equipe da CONTRATADA acesse as áreas produtivas, em conformidade com as normas de segurança aplicáveis.

4.6. Comunicar imediatamente à CONTRATADA qualquer alteração nas condições operacionais ou estruturais que possa impactar a execução dos serviços.

4.7. Implementar as recomendações acordadas, sendo de sua inteira responsabilidade os resultados decorrentes da não implementação.

4.8. A CONTRATANTE declara estar ciente de que os resultados da implementação dependem diretamente da qualidade e veracidade das informações fornecidas, assumindo integral responsabilidade por eventuais imprecisões ou omissões.


-------------------------------------------------------------------------------
CLÁUSULA 5 – VALOR E CONDIÇÕES DE PAGAMENTO
-------------------------------------------------------------------------------

5.1. O valor total dos serviços objeto deste contrato é de ${formatarMoeda(valorTotal)} (${valorTotal.toLocaleString('pt-BR')} reais).

5.2. O pagamento será efetuado da seguinte forma:
   - 40% na assinatura do contrato: ${formatarMoeda(valorTotal * 0.4)}
   - 40% na entrega da Fase 2 (Implementação): ${formatarMoeda(valorTotal * 0.4)}
   - 20% na conclusão da Fase 3 (Acompanhamento): ${formatarMoeda(valorTotal * 0.2)}

5.3. O pagamento deverá ser efetuado mediante depósito/transferência bancária para a conta:
   Banco: [BANCO]
   Agência: [AGÊNCIA]
   Conta: [CONTA]
   Titular: NEXUS ENGENHARIA APLICADA
   CNPJ: [CNPJ DA NEXUS]

5.4. O comprovante de pagamento deverá ser enviado à CONTRATADA por e-mail em até 24 (vinte e quatro) horas após a efetivação, sob pena de suspensão dos serviços até a regularização.

5.5. O atraso no pagamento sujeitará a CONTRATANTE a:
   a) Multa moratória de 2% (dois por cento) sobre o valor total da parcela em atraso;
   b) Juros de mora de 1% (um por cento) ao mês, calculados pro rata die;
   c) Correção monetária pelo índice IPCA (Índice de Preços ao Consumidor Amplo), ou outro índice oficial que venha a substituí-lo, contada da data do vencimento até a data do efetivo pagamento.

5.6. Em caso de inadimplemento, a CONTRATADA poderá suspender imediatamente a execução dos serviços até a regularização do pagamento, sem prejuízo da cobrança dos encargos previstos.


-------------------------------------------------------------------------------
CLÁUSULA 6 – PRAZO E VIGÊNCIA
-------------------------------------------------------------------------------

6.1. O presente contrato terá vigência de ${prazoImplementacao} semanas para a Fase 2, acrescidas de ${prazoAcompanhamento} meses para a Fase 3, contados da data de assinatura.

6.2. O início dos serviços está condicionado ao pagamento da primeira parcela e à disponibilização das informações e acessos previstos na Cláusula 4.

6.3. Os prazos poderão ser ajustados por acordo entre as partes, mediante aditivo contratual.


-------------------------------------------------------------------------------
CLÁUSULA 7 – PROPRIEDADE INTELECTUAL
-------------------------------------------------------------------------------

7.1. Toda a metodologia, know-how, softwares, sistemas (incluindo, mas não se limitando, à plataforma Hórus), técnicas, ferramentas, modelos, planilhas, procedimentos, materiais de treinamento e quaisquer outros ativos intelectuais desenvolvidos ou utilizados pela CONTRATADA são de sua propriedade exclusiva.

7.2. A CONTRATANTE não adquire, por força deste contrato, qualquer direito de propriedade sobre a metodologia, softwares ou ferramentas da CONTRATADA, incluindo, expressamente, a plataforma Hórus.

7.3. É expressamente proibido à CONTRATANTE:
   a) Copiar, reproduzir, modificar, descompilar ou realizar engenharia reversa da plataforma Hórus ou de qualquer ferramenta da CONTRATADA;
   b) Utilizar a metodologia da CONTRATADA para prestar serviços a terceiros;
   c) Reproduzir, no todo ou em parte, os relatórios ou documentos entregues para finalidade diversa daquela para a qual foram elaborados.

7.4. Os relatórios e documentos entregues à CONTRATANTE destinam-se ao seu uso exclusivo no âmbito do objeto contratado, sendo vedada sua divulgação a terceiros sem a prévia e expressa autorização por escrito da CONTRATADA.

7.5. A violação desta cláusula sujeitará a parte infratora ao pagamento de multa equivalente a 10 (dez) vezes o valor total deste contrato, sem prejuízo das perdas e danos e demais sanções cabíveis.


-------------------------------------------------------------------------------
CLÁUSULA 8 – CONFIDENCIALIDADE
-------------------------------------------------------------------------------

8.1. As partes obrigam-se a manter absoluto sigilo sobre todas as informações confidenciais a que tiverem acesso em razão deste contrato, considerando-se como tais:
   a) Dados operacionais, financeiros, estratégicos, de produção, qualidade, manutenção, custos e quaisquer informações de negócio da CONTRATANTE;
   b) Metodologia, softwares, ferramentas, técnicas e know-how da CONTRATADA;
   c) Qualquer informação expressamente identificada como confidencial.

8.2. A obrigação de confidencialidade estende-se pelo prazo de 5 (cinco) anos após o término deste contrato.

8.3. A violação desta cláusula sujeitará a parte infratora ao pagamento de multa de R$ 50.000,00 (cinquenta mil reais) por evento de violação, sem prejuízo das perdas e danos e demais sanções cabíveis.

8.4. Não se considera violação da confidencialidade a divulgação de informações:
   a) Exigidas por determinação judicial ou legal;
   b) Já em domínio público;
   c) Autorizadas previamente por escrito pela parte titular.


-------------------------------------------------------------------------------
CLÁUSULA 9 – RESCISÃO
-------------------------------------------------------------------------------

9.1. O presente contrato poderá ser rescindido por qualquer das partes, mediante notificação por escrito, nas seguintes hipóteses:
   a) Descumprimento de qualquer cláusula contratual, não sanado no prazo de 15 (quinze) dias úteis após o recebimento da notificação;
   b) Por interesse exclusivo de qualquer das partes, mediante aviso prévio de 30 (trinta) dias, sem justa causa;
   c) Por caso fortuito ou força maior que impeça a execução do objeto, assim reconhecido judicialmente.

9.2. Em caso de rescisão unilateral sem justa causa pela CONTRATANTE, será devida multa de 20% (vinte por cento) sobre o saldo remanescente do contrato, calculado com base no valor total previsto na Cláusula 5.1.

9.3. Em caso de rescisão por descumprimento da CONTRATADA, esta restituirá à CONTRATANTE os valores já pagos, atualizados monetariamente, e pagará multa de 20% (vinte por cento) sobre o valor total do contrato.

9.4. Em caso de rescisão por descumprimento da CONTRATANTE, esta pagará à CONTRATADA os serviços já prestados, atualizados monetariamente, e multa de 20% (vinte por cento) sobre o valor total do contrato.

9.5. A rescisão não exonera as partes das obrigações de confidencialidade previstas na Cláusula 8 e das penalidades eventualmente já incorridas.


-------------------------------------------------------------------------------
CLÁUSULA 10 – PENALIDADES
-------------------------------------------------------------------------------

10.1. Pelo descumprimento de qualquer obrigação contratual não especificamente penalizada em outras cláusulas, será aplicada multa de 10% (dez por cento) sobre o valor total do contrato, sem prejuízo da obrigação principal.

10.2. As multas previstas neste contrato são independentes e acumuláveis, podendo ser exigidas cumulativamente quando configuradas as respectivas hipóteses.

10.3. A mora de qualquer das partes no cumprimento de suas obrigações sujeitará o infrator à incidência dos encargos previstos na Cláusula 5.5.


-------------------------------------------------------------------------------
CLÁUSULA 11 – DISPOSIÇÕES GERAIS
-------------------------------------------------------------------------------

11.1. Este contrato é celebrado em caráter intuitu personae em relação à CONTRATADA, não podendo a CONTRATANTE ceder ou transferir seus direitos e obrigações sem prévia e expressa anuência por escrito da CONTRATADA.

11.2. As comunicações entre as partes serão consideradas válidas quando enviadas por e-mail para os endereços abaixo, ou por correspondência com aviso de recebimento (AR):
   CONTRATANTE: ${contato.email_contratante}
   CONTRATADA: ${contato.email_contratada}

11.3. A tolerância quanto ao descumprimento de qualquer cláusula não constituirá novação, renúncia de direitos ou precedente, mantendo-se a exigibilidade das obrigações.

11.4. Qualquer modificação ou aditivo a este contrato deverá ser formalizado por escrito, com anuência de ambas as partes.

11.5. Os títulos das cláusulas são meramente descritivos e não vinculam a interpretação do contrato.


-------------------------------------------------------------------------------
CLÁUSULA 12 – FORO
-------------------------------------------------------------------------------

12.1. Fica eleito o foro da Comarca de [SUA CIDADE/ESTADO] para dirimir quaisquer questões decorrentes deste contrato, com renúncia expressa a qualquer outro, por mais privilegiado que seja.


-------------------------------------------------------------------------------
ASSINATURAS
-------------------------------------------------------------------------------

E, por estarem assim justas e contratadas, as partes assinam o presente instrumento em 2 (duas) vias de igual teor e forma.

${empresa.cidade || '[CIDADE]'}, ${dataAssinatura}.


CONTRATANTE
${empresa.nome}

_________________________________
Assinatura

${representante.nome}
[Cargo]


CONTRATADA
NEXUS ENGENHARIA APLICADA

_________________________________
Assinatura

[SEU NOME]
[Cargo]


TESTEMUNHAS

1. _________________________________
   Nome: _______________________________
   RG: _______________________________
   CPF: _______________________________

2. _________________________________
   Nome: _______________________________
   RG: _______________________________
   CPF: _______________________________
`;

    res.status(200).json({
      status: "sucesso",
      contrato: contrato,
      metadata: {
        empresa: empresa.nome,
        valor_total: valorTotal,
        oee_atual: oeeAtual.toFixed(1),
        meta_oee: metaOEE,
        perdas_totais: perdasTotais,
        roi_estimado: ((perdasTotais * 0.3 * 12 / valorTotal) * 100).toFixed(0),
        payback_estimado: (valorTotal / (perdasTotais * 0.3)).toFixed(1),
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
    
    const query = `
      INSERT INTO interacoes_leads (lead_id, tipo, descricao, data, hora, criado_por, criado_em)
      VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
      RETURNING *
    `;
    
    const values = [
      id, 
      tipo, 
      descricao || null, 
      data || new Date().toISOString().split('T')[0], 
      hora || new Date().toLocaleTimeString('pt-BR', { hour12: false }), 
      criado_por
    ];
    
    const result = await client.query(query, values);
    
    await client.query(
      `UPDATE leads SET 
        ultimo_contato = $1,
        data_atualizacao = CURRENT_TIMESTAMP
      WHERE id = $2`,
      [data, id]
    );
    
    await client.query('COMMIT');
    
    console.log(`✅ Interação registrada - Lead: ${id}, Usuário: ${criado_por}`);
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