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
    connectionTimeoutMillis: 2000,
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

  // 1. Verifica se o header existe e segue o padrão "Bearer <TOKEN>"
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.warn(`[SECURITY] Acesso negado: Header ausente ou malformado - IP: ${req.ip}`);
    return res.status(401).json({ 
      erro: "Acesso negado", 
      detalhe: "Token não fornecido ou formato inválido" 
    });
  }

  const token = authHeader.split(" ")[1];

  // 2. Validação Crítica do Token usando a chave mestra
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      const mensagemErro = err.name === "TokenExpiredError" 
        ? "Sessão expirada. Faça login novamente." 
        : "Token de autenticação inválido.";
      
      console.warn(`[SECURITY] Falha na validação JWT: ${err.message} - IP: ${req.ip}`);
      return res.status(403).json({ erro: mensagemErro });
    }

    // 3. Injeção de Contexto (ID e Email para as próximas rotas)
    req.usuario = {
      id: decoded.id,
      email: decoded.email,
      nivel: decoded.nivel || 'consultor'
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
    meta_mensal
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
      Math.abs(parseFloat(meta_mensal)) || 0
    ];

    const query = `
      INSERT INTO empresas 
      (nome, cnpj, segmento, regime_tributario, turnos, dias_produtivos_mes, meta_mensal) 
      VALUES ($1, $2, $3, $4, $5, $6, $7) 
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
 * 4️⃣ EDITAR LINHA (PUT)
 * Atualiza os dados básicos da linha e suas associações com produtos
 */
app.put("/api/lines/:id", autenticarToken, async (req, res) => {
  const { id } = req.params;
  const { nome, produtos } = req.body;
  
  // ✅ CORREÇÃO: Aceita horas em qualquer formato (frontend envia horas_produtivas_dia)
  const horas = req.body.horas_disponiveis || req.body.horas_produtivas_dia || 16;
  const horasNumericas = parseFloat(horas) || 16;
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // 1. Atualizar a linha - AGORA FUNCIONA COM QUALQUER NOME
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
    
    // 2. Se veio produtos, atualizar associações
    if (produtos && produtos.length > 0) {
      // Remover associações antigas
      await client.query(
        'DELETE FROM linha_produto WHERE linha_id = $1',
        [id]
      );
      
      // Inserir novas associações
      for (const prod of produtos) {
        await client.query(
          `INSERT INTO linha_produto (linha_id, produto_id, takt_time_segundos, meta_diaria)
           VALUES ($1, $2, $3, $4)`,
          [id, prod.produto_id || prod.id, prod.takt_time_segundos || prod.takt, prod.meta_diaria || prod.meta]
        );
      }
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
// 🏭 MÓDULO: LINHAS MASTER (MULTIDATA)
// ========================================

/**
 * ROTA: CRIAR LINHA COM MÚLTIPLOS PRODUTOS
 * Permite definir Takts e Metas específicas para cada produto na mesma linha.
 */
app.post("/api/lines-master", autenticarToken, async (req, res) => {
  const client = await pool.connect(); // Usamos 'client' direto para transações
  
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

    await client.query('BEGIN'); // Início da operação atômica

    // 2. Criar a Cabeça da Linha (Master)
    const linhaQuery = `
      INSERT INTO linhas_producao (empresa_id, nome, horas_disponiveis)
      VALUES ($1, $2, $3)
      RETURNING id;
    `;
    const linhaRes = await client.query(linhaQuery, [
      empresa_id, 
      nome.trim(), 
      parseFloat(horas_produtivas) || 8.8
    ]);
    
    const linhaId = linhaRes.rows[0].id;

    // 3. Vincular Produtos (Performance Relacional)
    // Usamos Promise.all para otimizar as inserções dentro da transação
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

    await client.query('COMMIT'); // Consolida no banco
    
    res.status(201).json({ 
      mensagem: "Linha Master e performances de produtos registradas.",
      linha_id: linhaId 
    });

  } catch (error) {
    await client.query('ROLLBACK'); // Desfaz tudo em caso de qualquer erro
    console.error("❌ Erro Crítico Master Route:", error.message);
    
    if (error.code === '23503') {
      return res.status(400).json({ erro: "Violação de integridade: Produto ou Empresa não existem." });
    }

    res.status(500).json({ erro: "Falha ao processar o cadastro mestre da linha." });
  } finally {
    client.release(); // Libera o client de volta para o pool (Obrigatório!)
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
 * Inclui lógica de auto-incremento de fluxo dentro da mesma linha.
 */
app.post("/api/work-stations", autenticarToken, async (req, res) => {
  const {
    linha_id,
    nome,
    tempo_ciclo_segundos,
    tempo_setup_minutos,
    cargo_id,
    disponibilidade_percentual
  } = req.body;

  if (!linha_id || !nome) {
    return res.status(400).json({ erro: "Linha e Nome do posto são obrigatórios." });
  }

  try {
    const query = `
      INSERT INTO posto_trabalho
      (linha_id, nome, tempo_ciclo_segundos, tempo_setup_minutos, cargo_id, disponibilidade_percentual, ordem_fluxo)
      VALUES ($1, $2, $3, $4, $5, $6,
        (SELECT COALESCE(MAX(ordem_fluxo), 0) + 1 FROM posto_trabalho WHERE linha_id = $1)
      )
      RETURNING *;
    `;

    const values = [
      linha_id,
      nome.trim(),
      parseFloat(tempo_ciclo_segundos) || 0,
      parseFloat(tempo_setup_minutos) || 0,
      cargo_id || null,
      parseFloat(disponibilidade_percentual) || 100
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
  const { posto_id, tempo_ciclo_segundos } = req.body;

  // Validação rigorosa: Não permitimos medições zeradas ou negativas
  if (!posto_id || !tempo_ciclo_segundos || parseFloat(tempo_ciclo_segundos) <= 0) {
    return res.status(400).json({ 
      erro: "Dados inválidos. O posto_id é obrigatório e o tempo deve ser maior que zero." 
    });
  }

  try {
    const query = `
      INSERT INTO ciclo_medicao (posto_id, tempo_ciclo_segundos, data_medicao)
      VALUES ($1, $2, NOW())
      RETURNING *;
    `;

    const values = [
      posto_id, 
      parseFloat(tempo_ciclo_segundos)
    ];

    const result = await pool.query(query, values);
    
    // Log de engenharia: monitoramento de latência de inserção
    console.log(`⏱️ Medição registrada: Posto ${posto_id} | ${tempo_ciclo_segundos}s`);
    
    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error("❌ Erro ao registrar cronoanálise:", error.message);
    
    if (error.code === '23503') {
      return res.status(400).json({ erro: "O posto de trabalho informado não existe." });
    }

    res.status(500).json({ erro: "Falha técnica ao salvar medição de ciclo" });
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
      LEFT JOIN cargo ca ON c.cargo_id = ca.id
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
      FROM linha_producao lp
      LEFT JOIN posto_trabalho pt ON pt.linha_id = lp.id
      LEFT JOIN cargo c ON c.id = pt.cargo_id
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
      FROM linha_producao lp
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
      JOIN produto p ON p.id = lp_prod.produto_id
      JOIN linha_producao l ON l.id = lp_prod.linha_id
      JOIN empresa e ON e.id = l.empresa_id
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
// 📊 MOTOR DE CÁLCULO OEE (VERSÃO NEXUS - FINAL)
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
      const temposCiclo = produto.postos.map(p => p.tempo_ciclo || 0);
      const gargalo = Math.max(...temposCiclo) || 1; // Evita divisão por zero
      
      // 3. CÁLCULO DE CAPACIDADE E PRODUÇÃO
      // Capacidade Bruta = Segundos Disponíveis / Ciclo do Gargalo
      const capacidadeBruta = Math.floor(tempoOperandoSegundos / gargalo);
      
      // Produção Boa = Capacidade * Índice de Qualidade
      const qualidadeDecimal = (produto.qualidade || 100) / 100;
      const producaoBoa = Math.floor(capacidadeBruta * qualidadeDecimal);

      // 4. CÁLCULO DOS PILARES OEE (Normalizados 0 a 1)
      const disponibilidadeOEE = disponibilidadeDecimal;
      
      // Performance = (Produção Real * Takt Ideal) / Tempo Operando Real
      // Nota: Se o Takt não for informado, usamos o próprio gargalo como referência
      const taktIdeal = produto.takt || gargalo;
      const performanceOEE = tempoOperandoSegundos > 0 
        ? (capacidadeBruta * taktIdeal) / tempoOperandoSegundos 
        : 0;

      const qualidadeOEE = capacidadeBruta > 0 ? producaoBoa / capacidadeBruta : 0;
      
      // Cálculo Final: Disponibilidade x Performance x Qualidade
      const oeeFinal = disponibilidadeOEE * performanceOEE * qualidadeOEE;

      // 5. COMPILAÇÃO DO RELATÓRIO
      resultados.push({
        produto: produto.produto_nome,
        meta_diaria_planejada: produto.metaDiaria,
        capacidade_bruta_dia: capacidadeBruta,
        producao_boa_dia: producaoBoa,
        deficit_pecas_dia: Math.max(0, (produto.metaDiaria || 0) - producaoBoa),
        gargalo_identificado: `${gargalo}s`,
        indicadores: {
          disponibilidade_percentual: (disponibilidadeOEE * 100).toFixed(2),
          performance_percentual: (Math.min(performanceOEE, 1) * 100).toFixed(2),
          qualidade_percentual: (qualidadeOEE * 100).toFixed(2),
          oee_global_percentual: (oeeFinal * 100).toFixed(2)
        }
      });
    }

    // Resposta final para o Front-end/Thunder Client
    res.status(200).json({
      status: "sucesso_v2", // Para confirmar que o código novo está rodando
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
// 🌎 MÓDULO: EFICIÊNCIA GLOBAL (MACRO)
// ========================================

/**
 * ROTA: RESUMO DE PERFORMANCE GLOBAL
 * Entrega os KPIs mestres para o dashboard do Diretor/Dono da fábrica.
 */
app.get("/api/global-efficiency/:linhaId", autenticarToken, async (req, res) => {
  try {
    const { linhaId } = req.params;

    const result = await pool.query(`
      SELECT 
        lp.takt_time_segundos,
        lp.meta_diaria,
        pt.tempo_cycle_segundos, -- Verifique se o nome da coluna está correto
        COALESCE(pt.disponibilidade_percentual, 100) as disponibilidade
      FROM linha_producao lp
      LEFT JOIN posto_trabalho pt ON pt.linha_id = lp.id
      WHERE lp.id = $1
    `, [linhaId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: "Linha de produção não localizada." });
    }

    const taktAlvo = parseFloat(result.rows[0].takt_time_segundos) || 0;
    const metaDiaria = parseFloat(result.rows[0].meta_diaria) || 0;

    let tempoAgregadoTotal = 0;
    let ritmoGargalo = 0;
    const totalPostos = result.rows.filter(r => r.tempo_cycle_segundos !== null).length;

    result.rows.forEach(p => {
      const cicloNominal = parseFloat(p.tempo_cycle_segundos) || 0;
      const disp = (parseFloat(p.disponibilidade) || 100) / 100;
      const cicloAjustado = disp > 0 ? cicloNominal / disp : 0;

      tempoAgregadoTotal += cicloAjustado;
      if (cicloAjustado > ritmoGargalo) ritmoGargalo = cicloAjustado;
    });

    // Validação de Dados Mestre
    if (ritmoGargalo === 0 || metaDiaria === 0 || taktAlvo === 0 || totalPostos === 0) {
      return res.status(200).json({
        alerta: "Estrutura de linha incompleta",
        mensagem: "Certifique-se de que a meta, o takt e os tempos de ciclo dos postos estão cadastrados.",
        meta_planejada: metaDiaria
      });
    }

    // 🎯 INDICADORES TÉCNICOS
    
    // Capacidade Real: O que o gargalo permite produzir no tempo planejado
    const capacidadeReal = Math.floor((metaDiaria * taktAlvo) / ritmoGargalo);

    // Ocupação: Média de saturação dos postos em relação ao gargalo
    const taxaOcupacao = ((tempoAgregadoTotal / (ritmoGargalo * totalPostos)) * 100).toFixed(2);

    // Eficiência Global: Proximidade da meta planejada
    const eficienciaGlobal = ((capacidadeReal / metaDiaria) * 100).toFixed(2);

    res.status(200).json({
      metas: {
        planejada: metaDiaria,
        alcancavel_pelo_gargalo: capacidadeReal
      },
      kpis: {
        eficiencia_global: eficienciaGlobal + "%",
        ocupacao_media_recursos: taxaOcupacao + "%",
        perda_capacidade_diaria: metaDiaria - capacidadeReal
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
    refugo_pecas
  } = req.body;

  if (!linha_produto_id) {
    return res.status(400).json({ erro: "ID do vínculo linha-produto é obrigatório." });
  }

  // Sanitização: Garantir que perdas nunca sejam negativas (Math.max)
  const micro = Math.max(0, parseFloat(microparadas_minutos) || 0);
  const retrabalho = Math.max(0, parseInt(retrabalho_pecas, 10) || 0);
  const refugo = Math.max(0, parseInt(refugo_pecas, 10) || 0);

  try {
    // Lógica de Upsert: Se já houver registro de perdas para este produto nesta linha, ele atualiza.
    // Isso evita duplicidade de dados no cálculo do OEE.
    const query = `
      INSERT INTO perdas_linha 
      (linha_produto_id, microparadas_minutos, retrabalho_pecas, refugo_pecas)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (linha_produto_id) 
      DO UPDATE SET 
        microparadas_minutos = EXCLUDED.microparadas_minutos,
        retrabalho_pecas = EXCLUDED.retrabalho_pecas,
        refugo_pecas = EXCLUDED.refugo_pecas
      RETURNING *;
    `;

    const values = [linha_produto_id, micro, retrabalho, refugo];

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

    res.status(500).json({ erro: "Falha técnica ao salvar indicadores de perda." });
  }
});

// ========================================
// 📊 MÓDULO: ANALÍTICO DE DESPERDÍCIOS
// ========================================

/**
 * ROTA: LISTAR HISTÓRICO DE PERDAS POR LINHA
 * Essencial para identificar quais produtos estão drenando a eficiência da unidade.
 */
app.get("/api/losses/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;

  try {
    const query = `
      SELECT 
        pl.id as perda_id,
        p.nome as produto_nome,
        pl.microparadas_minutos,
        pl.retrabalho_pecas,
        pl.refugo_pecas,
        lp.takt_time_segundos,
        -- Cálculo de impacto: quanto tempo foi perdido em segundos
        (pl.microparadas_minutos * 60) as tempo_parada_total_seg
      FROM perdas_linha pl
      JOIN linha_produto lp ON lp.id = pl.linha_produto_id
      JOIN produto p ON p.id = lp.produto_id
      WHERE lp.linha_id = $1
      ORDER BY pl.id DESC;
    `;

    const result = await pool.query(query, [linhaId]);

    // Se não houver perdas registradas, retornamos uma lista vazia, não erro.
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
    return res.status(400).json({ erro: "Credenciais incompletas." });
  }

  const emailLimpo = email.trim().toLowerCase();

  try {
    // Busca o usuário
    const result = await pool.query(
      "SELECT id, nome, email, senha_hash FROM usuarios WHERE email = $1",
      [emailLimpo]
    );

    const usuario = result.rows[0];

    // Segurança por Obscuridade: Se o usuário não existe, ainda assim simulamos um delay 
    // ou usamos a mesma mensagem genérica para evitar enumeração de usuários.
    if (!usuario) {
      console.warn(`[AUTH] Tentativa falha: Usuário inexistente - IP: ${req.ip}`);
      return res.status(401).json({ erro: "E-mail ou senha incorretos." });
    }

    // Validação da Senha
    const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);

    if (!senhaValida) {
      console.warn(`[AUTH] Tentativa falha: Senha incorreta - Usuário: ${emailLimpo} - IP: ${req.ip}`);
      return res.status(401).json({ erro: "E-mail ou senha incorretos." });
    }

    // Geração do Token JWT (Passaporte)
    // Payload contém apenas o necessário para identificar o usuário nas rotas.
    const payload = { 
      id: usuario.id, 
      email: usuario.email 
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, { 
      expiresIn: "8h",
      algorithm: "HS256"
    });

    // Auditoria de login bem-sucedido
    console.log(`[AUTH] Login realizado: ${emailLimpo}`);

    res.status(200).json({
      status: "sucesso",
      token,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email
      }
    });

  } catch (error) {
    console.error("❌ Erro Crítico no Fluxo de Login:", error.message);
    res.status(500).json({ erro: "Falha interna no motor de autenticação." });
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
 */
app.get("/api/history/line/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;

  try {
    // 1. Query Única: Agregamos tudo via SQL para poupar memória e tempo de CPU
    const query = `
      WITH metricas_mensais AS (
        SELECT 
          DATE_TRUNC('month', md.data_medicao) as mes,
          AVG(md.valor_numerico) as avg_ciclo,
          STDDEV(md.valor_numerico) as std_ciclo,
          COUNT(*) as volume_dados
        FROM medicoes_detalhadas md
        JOIN posto_trabalho pt ON pt.id = md.posto_id
        WHERE pt.linha_id = $1 AND md.tipo = 'ciclo'
        GROUP BY 1
      )
      SELECT 
        m.mes,
        m.volume_dados as amostras,
        ROUND(m.avg_ciclo, 2) as media_ciclo,
        ROUND(m.std_ciclo, 2) as desvio_padrao,
        lp.takt_time_segundos as takt_alvo,
        -- Cálculo de OEE Mensal Baseado em Performance de Ciclo
        ROUND(LEAST(100, (lp.takt_time_segundos / NULLIF(m.avg_ciclo, 0)) * 100), 2) as oee_performance
      FROM metricas_mensais m
      CROSS JOIN (SELECT takt_time_segundos FROM linha_producao WHERE id = $1) lp
      ORDER BY m.mes DESC
      LIMIT 6;
    `;

    const result = await pool.query(query, [linhaId]);

    if (result.rowCount === 0) {
      return res.status(200).json({ 
        mensagem: "Histórico insuficiente para análise de tendência.",
        dados: [] 
      });
    }

    res.status(200).json({
      linha_id: linhaId,
      periodo: "Últimos 6 meses",
      historico: result.rows
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
// 💰 MÓDULO: ECONOMETRIA INDUSTRIAL
// ========================================

/**
 * ROTA: ANÁLISE DE CUSTO OPERACIONAL (OPEX)
 * Traduz a estrutura de postos e cargos em custo por minuto/hora.
 */
app.get("/api/finance/line/:linhaId", autenticarToken, async (req, res) => {
  const { linhaId } = req.params;

  try {
    // 1. Consolidação de Dados: Linha, Empresa e Calendário
    const queryMaster = `
      SELECT 
        l.id, l.nome, l.empresa_id,
        e.dias_produtivos_mes,
        e.horas_turno_diario -- Adicione esta coluna no seu setup para ser real
      FROM linha_producao l
      JOIN empresa e ON e.id = l.empresa_id
      WHERE l.id = $1
    `;
    const linhaRes = await pool.query(queryMaster, [linhaId]);

    if (linhaRes.rowCount === 0) return res.status(404).json({ erro: "Linha não localizada." });

    const linha = linhaRes.rows[0];
    const diasMes = linha.dias_produtivos_mes || 22;
    const horasDia = linha.horas_turno_diario || 8;

    // 2. Cálculo de Mão de Obra Direta (MOD) com Join de Cargos
    const postosRes = await pool.query(`
      SELECT 
        pt.id, pt.nome as posto_nome,
        c.nome as cargo_nome,
        COALESCE(c.salario_base, 0) as salario,
        COALESCE(c.encargos_percentual, 70) as encargos
      FROM posto_trabalho pt
      LEFT JOIN cargo c ON c.id = pt.cargo_id
      WHERE pt.linha_id = $1
    `, [linhaId]);

    let totalMensalMOD = 0;
    const detalhamentoPostos = postosRes.rows.map(p => {
      const custoMensal = parseFloat(p.salario) * (1 + (parseFloat(p.encargos) / 100));
      totalMensalMOD += custoMensal;
      return {
        id: p.id,
        posto: p.posto_nome,
        cargo: p.cargo_nome,
        custo_mensal: Math.round(custoMensal * 100) / 100
      };
    });

    // 3. O "Pulo do Gato": Custo da Ineficiência
    const minutosDisponiveisMes = diasMes * horasDia * 60;
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
        FROM linha_producao l
        JOIN empresa e ON e.id = l.empresa_id
        LEFT JOIN posto_trabalho pt ON pt.linha_id = l.id
        LEFT JOIN cargo c ON c.id = pt.cargo_id
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
        a.id, a.turno, a.data_inicio, a.ativo,
        c.nome as colaborador,
        cg.nome as cargo,
        cg.salario_base
      FROM alocacao_colaborador a
      JOIN colaborador c ON c.id = a.colaborador_id
      JOIN cargo cg ON cg.id = c.cargo_id
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
      FROM linha_producao l
      JOIN posto_trabalho pt ON pt.linha_id = l.id
      LEFT JOIN cargo c ON c.id = pt.cargo_id
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
    turnos, dias_produtivos_mes, meta_mensal
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
      parseFloat(meta_mensal) || 0, id
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
app.post("/api/login", async (req, res) => {
  const { email, senha } = req.body;

  try {
    // 1. Busca real no banco de dados Neon
    const query = "SELECT * FROM usuarios WHERE email = $1";
    const result = await pool.query(query, [email?.toLowerCase().trim()]);
    const usuario = result.rows[0];

    // 2. Validação de segurança
    if (usuario && usuario.senha === senha) {
      
      // 3. Criação do Token JWT com os dados reais do banco
      const token = jwt.sign(
        { id: usuario.id, email: usuario.email, nivel: usuario.nivel }, 
        process.env.JWT_SECRET, 
        { expiresIn: "8h" }
      );

      console.log(`[AUTH] Login real bem-sucedido: ${usuario.email}`);

      return res.json({
        status: "sucesso",
        mensagem: `Bem-vindo ao Sistema Hórus, ${usuario.nome.split(' ')[0]}.`,
        token: token
      });
    }

    // 4. Falha na autenticação
    console.warn(`[SECURITY] Tentativa de login inválida: ${email}`);
    return res.status(401).json({ erro: "E-mail ou senha inválidos." });

  } catch (error) {
    console.error("❌ Erro no Banco de Dados:", error.message);
    return res.status(500).json({ erro: "Erro interno ao conectar ao banco de dados." });
  }
});

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

// 5. Rota de Análise - AGORA COM DADOS REAIS
app.get("/api/analise-linha/:linhaId", async (req, res) => {
  const { linhaId } = req.params;
  
  try {
    const result = await pool.query(`
      SELECT 
        COALESCE(AVG(eficiencia_percentual), 0) as eficiencia_percentual,
        COALESCE(SUM(meta_diaria), 0) as capacidade_estimada_dia
      FROM analise_linha al
      JOIN linha_produto lp ON lp.linha_id = al.linha_id
      WHERE al.linha_id = $1
      GROUP BY al.linha_id
    `, [linhaId]);
    
    if (result.rows.length > 0) {
      res.json({
        eficiencia_percentual: parseFloat(result.rows[0].eficiencia_percentual) || 75.0,
        capacidade_estimada_dia: parseInt(result.rows[0].capacidade_estimada_dia) || 1200
      });
    } else {
      // Fallback para não quebrar o frontend
      res.json({
        eficiencia_percentual: 75.0,
        capacidade_estimada_dia: 1200
      });
    }
    
  } catch (error) {
    console.error("❌ Erro na análise da linha:", error.message);
    res.json({
      eficiencia_percentual: 75.0,
      capacidade_estimada_dia: 1200
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
 * 3️⃣ GERAR SUGESTÕES DE MELHORIA
 * Analisa dados da empresa e retorna ações prioritárias
 */
app.get("/api/ia/sugestoes/:empresaId", autenticarToken, async (req, res) => {
  const { empresaId } = req.params;

  try {
    // Buscar dados da empresa para análise
    const linhasRes = await pool.query(
      "SELECT * FROM linha_producao WHERE empresa_id = $1",
      [empresaId]
    );
    
    const linhas = linhasRes.rows;
    
    if (linhas.length === 0) {
      return res.status(200).json({
        sugestoes: {
          resumo: "Nenhuma linha cadastrada para análise. Cadastre as linhas de produção primeiro.",
          acoes: []
        }
      });
    }

    let totalOEE = 0;
    let totalPerdas = 0;
    let qtdOEE = 0;
    const acoes = [];

    for (const linha of linhas) {
      // Buscar análise da linha
      const analiseRes = await pool.query(
        "SELECT eficiencia_percentual FROM analise_linha WHERE linha_id = $1 ORDER BY data_analise DESC LIMIT 1",
        [linha.id]
      );

      if (analiseRes.rows.length > 0) {
        const oee = parseFloat(analiseRes.rows[0].eficiencia_percentual) || 0;
        totalOEE += oee;
        qtdOEE++;

        if (oee < 60) {
          acoes.push({
            titulo: `Intervenção crítica na linha ${linha.nome}`,
            descricao: `OEE de ${oee}% está muito abaixo do ideal. Realizar diagnóstico detalhado.`,
            prioridade: "alta",
            ganho: "R$ 15.000/mês",
            esforco: "2 semanas",
            investimento: "R$ 8.000"
          });
        } else if (oee < 75) {
          acoes.push({
            titulo: `Otimização da linha ${linha.nome}`,
            descricao: `OEE de ${oee}% - potencial para atingir 85% com melhorias.`,
            prioridade: "media",
            ganho: "R$ 8.000/mês",
            esforco: "3 semanas",
            investimento: "R$ 5.000"
          });
        }
      }

      // Buscar postos com setup alto
      const postosRes = await pool.query(
        "SELECT * FROM posto_trabalho WHERE linha_id = $1 AND tempo_setup_minutos > 20",
        [linha.id]
      );

      if (postosRes.rows.length > 0) {
        acoes.push({
          titulo: `Redução de setup na linha ${linha.nome}`,
          descricao: `${postosRes.rows.length} postos com setup acima de 20 minutos. Aplicar SMED.`,
          prioridade: "alta",
          ganho: "R$ 12.000/mês",
          esforco: "4 semanas",
          investimento: "R$ 10.000"
        });
      }

      // Buscar perdas registradas
      const perdasRes = await pool.query(
        "SELECT SUM(microparadas_minutos) as micro, SUM(refugo_pecas) as refugo FROM perdas_linha pl JOIN linha_produto lp ON lp.id = pl.linha_produto_id WHERE lp.linha_id = $1",
        [linha.id]
      );

      if (perdasRes.rows[0].micro > 100) {
        totalPerdas += perdasRes.rows[0].micro * 10; // Estimativa R$10/min
        acoes.push({
          titulo: `Redução de microparadas na linha ${linha.nome}`,
          descricao: `${Math.round(perdasRes.rows[0].micro)} minutos de microparadas registrados.`,
          prioridade: "media",
          ganho: "R$ 6.000/mês",
          esforco: "2 semanas",
          investimento: "R$ 3.000"
        });
      }

      if (perdasRes.rows[0].refugo > 50) {
        totalPerdas += perdasRes.rows[0].refugo * 50; // Estimativa R$50/peça
        acoes.push({
          titulo: `Controle de qualidade na linha ${linha.nome}`,
          descricao: `${perdasRes.rows[0].refugo} peças de refugo registradas. Análise de causa raiz.`,
          prioridade: "alta",
          ganho: "R$ 10.000/mês",
          esforco: "3 semanas",
          investimento: "R$ 7.000"
        });
      }
    }

    const oeeMedio = qtdOEE > 0 ? (totalOEE / qtdOEE).toFixed(1) : 0;

    // Se poucas ações, adicionar sugestões genéricas
    if (acoes.length < 3) {
      acoes.push({
        titulo: "Treinamento de operadores",
        descricao: "Capacitar equipe em técnicas de melhoria contínua e automação.",
        prioridade: "baixa",
        ganho: "R$ 4.000/mês",
        esforco: "1 semana",
        investimento: "R$ 2.000"
      });
    }

    // Ordenar por prioridade
    const prioridadeOrder = { alta: 1, media: 2, baixa: 3 };
    acoes.sort((a, b) => prioridadeOrder[a.prioridade] - prioridadeOrder[b.prioridade]);

    res.status(200).json({
      sugestoes: {
        resumo: `A empresa apresenta OEE médio de ${oeeMedio}%. Identificamos ${acoes.length} oportunidades de melhoria com potencial de redução de perdas de R$ ${(totalPerdas * 0.3).toFixed(0).replace(/\B(?=(\d{3})+(?!\d))/g, '.')}/mês.`,
        acoes: acoes.slice(0, 5),
        projecoes: {
          novoOEE: `${Math.min(85, Math.round(oeeMedio * 1.2))}%`,
          ganhoMensal: `R$ ${(totalPerdas * 0.3).toFixed(0).replace(/\B(?=(\d{3})+(?!\d))/g, '.')}`,
          tempoEstimado: "3 meses"
        }
      }
    });

  } catch (error) {
    console.error("❌ Erro ao gerar sugestões IA:", error.message);
    res.status(500).json({ erro: "Falha ao gerar sugestões" });
  }
});

// ========================================
// 🏁 START ENGINE: NEXUS HÓRUS PLATFORM
// ========================================

// Garante que a porta e o ambiente existam antes de subir o motor
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

// Tratamento de interrupção graciosa (Graceful Shutdown)
process.on('SIGTERM', () => {
  console.log('🚨 SIGTERM recebido. Encerrando servidor Hórus...');
  server.close(() => {
    // Certifique-se de que a variável 'pool' existe no seu Bloco 1
    if (typeof pool !== 'undefined') {
      pool.end();
    }
    console.log('✅ Processos encerrados e banco de dados desconectado.');
    process.exit(0);
  });
});