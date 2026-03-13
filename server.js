require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const helmet = require("helmet");
const rateLimit = require('express-rate-limit');

const app = express();

// ========================================
// 🔒 MIDDLEWARE DE SEGURANÇA
// ========================================
app.use(helmet()); // Headers de segurança
app.use(cors());
app.use(express.json());

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fetch = require('node-fetch');

// ========================================
// 🔐 VARIÁVEIS DE AMBIENTE
// ========================================
const JWT_SECRET = process.env.JWT_SECRET || "horus_super_secret_key_fallback";
const DB_USER = process.env.DB_USER || "postgres";
const DB_PASSWORD = process.env.DB_PASSWORD || "29031996Hlp.,";
const DB_NAME = process.env.DB_NAME || "horus_db";
const DB_HOST = process.env.DB_HOST || "localhost";
const PORT = process.env.PORT || 3001;

// ========================================
// 🔒 RATE LIMITING PARA LOGIN
// ========================================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // 5 tentativas por IP
  message: { 
    erro: "Muitas tentativas de login. Tente novamente em 15 minutos." 
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting geral para API (opcional)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100, // 100 requisições por IP a cada 15 minutos
  message: { erro: "Muitas requisições. Tente novamente mais tarde." }
});

// Aplicar rate limiting global (exceto para rotas específicas)
app.use('/api/', apiLimiter);

// ========================================
//    MIDDLEWARE DE AUTENTICAÇÃO
// ========================================
function autenticarToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({ erro: "Token não fornecido" });
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ erro: "Token inválido" });
  }

  jwt.verify(token, JWT_SECRET, (err, usuario) => {
    if (err) {
      return res.status(403).json({ erro: "Token inválido ou expirado" });
    }

    req.usuario = usuario;
    next();
  });
}

// ========================================
// 🔌 Conexão PostgreSQL Estabilizada
// ========================================
const poolConfig = process.env.DB_CONNECTION_STRING 
  ? {
      connectionString: process.env.DB_CONNECTION_STRING,
      ssl: { rejectUnauthorized: false },
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
    }
  : {
      user: DB_USER,
      host: DB_HOST,
      database: DB_NAME,
      password: DB_PASSWORD,
      port: 5432,
    };

const pool = new Pool(poolConfig);

// IMPORTANTE: Listener de erro para o processo não morrer
pool.on('error', (err) => {
  console.error('❌ Erro inesperado no pool do Postgres:', err.message);
});

// Teste de conexão sem travar o event loop
pool.query('SELECT NOW()')
  .then(() => console.log('✅ Conectado ao banco de dados com sucesso!'))
  .catch(err => console.error('❌ Erro ao conectar ao banco:', err.message));

// ========================================
// 🔎 Teste API
// ========================================
app.get("/", (req, res) => {
  res.send("API do Hórus está rodando 🧠");
});

// ========================================
// 🏢 EMPRESAS
// ========================================

app.get("/empresas", autenticarToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM empresas ORDER BY created_at DESC");
    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar empresas:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 🏭 BLOCO INTEGRADO: GESTÃO DE EMPRESAS
// ========================================

// 1️⃣ ROTA: LISTAR EMPRESAS (Faz a lista aparecer embaixo da ficha)
app.get("/empresas", async (req, res) => {
  try {
    // Busca na tabela PLURAL 'empresas'
    const result = await pool.query("SELECT * FROM empresas ORDER BY created_at DESC");
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("❌ Erro no GET /empresas:", error.message);
    res.status(500).json({ erro: "Erro ao carregar lista de empresas" });
  }
});

// 2️⃣ ROTA: CADASTRAR EMPRESA (O bloco que você validou)
app.post("/empresas", async (req, res) => {
  try {
    const {
      nome,
      cnpj,
      segmento,
      regime_tributario,
      turnos,
      dias_produtivos_mes,
      meta_mensal
    } = req.body;

    // Sanitização e Conversão de Tipos
    const nomeSanitizado = nome?.trim();
    const cnpjSanitizado = cnpj?.replace(/[^\d]/g, '');
    const turnosInt = turnos ? parseInt(turnos, 10) : 0;
    const diasInt = dias_produtivos_mes ? parseInt(dias_produtivos_mes, 10) : 0;
    const metaFloat = meta_mensal ? parseFloat(meta_mensal) : 0;

    const query = `
      INSERT INTO empresas 
      (nome, cnpj, segmento, regime_tributario, turnos, dias_produtivos_mes, meta_mensal) 
      VALUES ($1, $2, $3, $4, $5, $6, $7) 
      RETURNING *;
    `;

    const values = [
      nomeSanitizado,
      cnpjSanitizado,
      segmento,
      regime_tributario,
      turnosInt,
      diasInt,
      metaFloat
    ];

    const result = await pool.query(query, values);
    console.log(`✅ Sucesso: Empresa ${nomeSanitizado} registrada.`);
    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error("❌ Erro no POST /empresas:", error.message);
    res.status(500).json({ erro: "Falha ao salvar no banco de dados" });
  }
});

// 3️⃣ ROTA: EXCLUIR EMPRESA
app.delete("/empresas/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query("DELETE FROM empresas WHERE id = $1", [id]);
    res.status(200).json({ mensagem: "Empresa excluída com sucesso" });
  } catch (error) {
    console.error("❌ Erro no DELETE /empresas:", error.message);
    res.status(500).json({ erro: "Erro ao excluir empresa" });
  }
});

// ========================================
// 🏭 LINHAS
// ========================================

app.get("/linhas/:empresaId", async (req, res) => {
  try {
    const { empresaId } = req.params;

    const result = await pool.query(
      "SELECT * FROM linha_producao WHERE empresa_id = $1 ORDER BY id",
      [empresaId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar linhas:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

app.post("/linhas", async (req, res) => {
  try {
    const { empresa_id, nome, produto_id, takt_time_segundos, meta_diaria } = req.body;

    const result = await pool.query(
      `INSERT INTO linha_producao
      (empresa_id, nome, produto_id, takt_time_segundos, meta_diaria)
      VALUES ($1,$2,$3,$4,$5)
      RETURNING *`,
      [empresa_id, nome, produto_id, takt_time_segundos, meta_diaria]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao criar linha:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 🏭 CRIAR LINHA COM MÚLTIPLOS PRODUTOS (NOVA ROTA)
// ========================================
app.post("/linhas-com-multiplos-produtos", autenticarToken, async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { empresa_id, nome, produtos_ids, takt_time_segundos, meta_diaria } = req.body;

    // Validar se veio pelo menos um produto
    if (!produtos_ids || produtos_ids.length === 0) {
      return res.status(400).json({ erro: "Selecione pelo menos um produto" });
    }

    // Validar campos obrigatórios
    if (!empresa_id || !nome || !takt_time_segundos || !meta_diaria) {
      return res.status(400).json({ erro: "Todos os campos são obrigatórios" });
    }

    // 1. Criar a linha
    const linhaRes = await client.query(
      `INSERT INTO linha_producao (empresa_id, nome, takt_time_segundos, meta_diaria)
       VALUES ($1, $2, $3, $4)
       RETURNING id`,
      [empresa_id, nome, takt_time_segundos, meta_diaria]
    );
    
    const linhaId = linhaRes.rows[0].id;

    // 2. Para cada produto, criar vínculo
    for (const produto_id of produtos_ids) {
      await client.query(
        `INSERT INTO linha_produto (linha_id, produto_id)
         VALUES ($1, $2)`,
        [linhaId, produto_id]
      );
    }

    await client.query('COMMIT');
    
    res.status(201).json({ 
      mensagem: "Linha criada com sucesso",
      linha_id: linhaId,
      quantidade_produtos: produtos_ids.length
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("Erro ao criar linha com múltiplos produtos:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  } finally {
    client.release();
  }
});

// ========================================
// 🏗 POSTOS DE TRABALHO
// ========================================

app.get("/postos/:linhaId", async (req, res) => {
  try {
    const { linhaId } = req.params;

    const result = await pool.query(
      "SELECT * FROM posto_trabalho WHERE linha_id = $1 ORDER BY ordem_fluxo",
      [linhaId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar postos:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

app.post("/postos", async (req, res) => {
  try {
    const {
      linha_id,
      nome,
      tempo_ciclo_segundos,
      tempo_setup_minutos,
      cargo_id,
      disponibilidade_percentual
    } = req.body;

    const result = await pool.query(
      `INSERT INTO posto_trabalho
      (linha_id, nome, tempo_ciclo_segundos, tempo_setup_minutos, cargo_id, disponibilidade_percentual, ordem_fluxo)
      VALUES ($1,$2,$3,$4,$5,$6,
        (SELECT COALESCE (MAX(ordem_fluxo),0)+1 FROM posto_trabalho WHERE linha_id=$1)
      )
      RETURNING *`,
      [
        linha_id,
        nome,
        tempo_ciclo_segundos,
        tempo_setup_minutos,
        cargo_id,
        disponibilidade_percentual
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao criar posto:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// 🔥 PUT INTELIGENTE (ATUALIZA SOMENTE O QUE FOR ENVIADO)

app.put("/postos/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const fields = [];
    const values = [];
    let index = 1;

    for (let key in req.body) {
      fields.push(`${key} = $${index}`);
      values.push(req.body[key]);
      index++;
    }

    if (fields.length === 0) {
      return res.status(400).json({ erro: "Nenhum campo enviado para atualização" });
    }

    const query = `
      UPDATE posto_trabalho
      SET ${fields.join(", ")}
      WHERE id = $${index}
      RETURNING *
    `;

    values.push(id);

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Posto não encontrado" });
    }

    res.json(result.rows[0]);

  } catch (error) {
    console.error("Erro ao atualizar posto:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 📈 MEDIÇÕES DE CICLO (VARIABILIDADE)
// ========================================

app.post("/medicoes-ciclo", async (req, res) => {
  try {
    const { posto_id, tempo_ciclo_segundos } = req.body;

    if (!posto_id || !tempo_ciclo_segundos) {
      return res.status(400).json({ erro: "posto_id e tempo_ciclo_segundos são obrigatórios" });
    }

    const result = await pool.query(
      `INSERT INTO ciclo_medicao (posto_id, tempo_ciclo_segundos)
       VALUES ($1, $2)
       RETURNING *`,
      [posto_id, tempo_ciclo_segundos]
    );

    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error("Erro ao registrar medição:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 👷 CARGOS
// ========================================

app.get("/cargos/:departamentoId", async (req, res) => {
  try {
    const { departamentoId } = req.params;

    const result = await pool.query(
      "SELECT * FROM cargo WHERE departamento_id = $1 ORDER BY id",
      [departamentoId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar cargos:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

app.post("/cargos", async (req, res) => {
  try {
    const { departamento_id, nome, salario_base, encargos_percentual } = req.body;

    const result = await pool.query(
      `INSERT INTO cargo
      (departamento_id, nome, salario_base, encargos_percentual)
      VALUES ($1,$2,$3,$4)
      RETURNING *`,
      [
        departamento_id,
        nome,
        salario_base,
        encargos_percentual || 70
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao criar cargo:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// Excluir cargo
app.delete("/cargos/:id", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query("DELETE FROM cargo WHERE id = $1 RETURNING *", [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Cargo não encontrado" });
    }

    res.json({ mensagem: "Cargo excluído com sucesso" });
  } catch (error) {
    console.error("Erro ao excluir cargo:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 👤 COLABORADORES
// ========================================

app.get("/colaboradores/:empresaId", async (req, res) => {
  try {
    const { empresaId } = req.params;

    const result = await pool.query(
      "SELECT * FROM colaborador WHERE empresa_id = $1 ORDER BY id",
      [empresaId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar colaboradores:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

app.post("/colaboradores", async (req, res) => {
  try {
    const { empresa_id, cargo_id, nome } = req.body;

    const result = await pool.query(
      `INSERT INTO colaborador
      (empresa_id, cargo_id, nome)
      VALUES ($1,$2,$3)
      RETURNING *`,
      [empresa_id, cargo_id, nome]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao criar colaborador:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// Excluir colaborador
app.delete("/colaboradores/:id", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query("DELETE FROM colaborador WHERE id = $1 RETURNING *", [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Colaborador não encontrado" });
    }

    res.json({ mensagem: "Colaborador excluído com sucesso" });
  } catch (error) {
    console.error("Erro ao excluir colaborador:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 📊 VISÃO COMPLETA DA LINHA (CÉREBRO DO HÓRUS)
// ========================================

app.get("/linha-completa/:linhaId", async (req, res) => {
  try {
    const { linhaId } = req.params;

    const result = await pool.query(
      `
      SELECT 
        lp.nome AS linha,
        pt.id AS posto_id,
        pt.nome AS posto,
        pt.tempo_ciclo_segundos,
        pt.disponibilidade_percentual,
        c.nome AS cargo,
        c.salario_base,
        c.encargos_percentual
      FROM linha_producao lp
      LEFT JOIN posto_trabalho pt ON pt.linha_id = lp.id
      LEFT JOIN cargo c ON c.id = pt.cargo_id
      WHERE lp.id = $1
      ORDER BY pt.id
      `,
      [linhaId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao montar visão completa da linha:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 🧠 ANALISE INTELIGENTE DA LINHA
// ========================================

app.get("/analise-linha/:linhaId", async (req, res) => {
  try {
    const { linhaId } = req.params;

    const result = await pool.query(
      `
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
      `,
      [linhaId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Linha não encontrada" });
    }

    const takt = parseFloat(result.rows[0].takt_time_segundos || 0);
    const meta = parseFloat(result.rows[0].meta_diaria || 0);

    if (!takt) {
      return res.json({
        mensagem: "Linha sem takt definido",
        takt_time_segundos: takt,
        meta_diaria_planejada: meta,
        postos: []
      });
    }

    let maiorCiclo = 0;
    let gargalo = null;

    const postos = result.rows.map(p => {
      const ciclo = parseFloat(p.tempo_ciclo_segundos || 0);
      const disponibilidade = parseFloat(p.disponibilidade) / 100;

      const cicloReal = disponibilidade > 0 ? ciclo / disponibilidade : ciclo;

      if (cicloReal > maiorCiclo) {
        maiorCiclo = cicloReal;
        gargalo = p.nome;
      }

      return {
        posto: p.nome,
        ciclo_segundos: ciclo,
        disponibilidade_percentual: p.disponibilidade,
        ciclo_real_ajustado: cicloReal.toFixed(2)
      };
    });

    if (maiorCiclo === 0) {
      return res.json({
        mensagem: "Linha sem postos cadastrados",
        takt_time_segundos: takt,
        meta_diaria_planejada: meta,
        postos: []
      });
    }

    const eficiencia = maiorCiclo > 0
      ? ((takt / maiorCiclo) * 100).toFixed(2)
      : 0;

    const capacidadeEstimada = maiorCiclo > 0
      ? Math.floor((meta * takt) / maiorCiclo)
      : 0;

    res.json({
      takt_time_segundos: takt,
      meta_diaria_planejada: meta,
      gargalo: gargalo,
      maior_tempo_ciclo_real_segundos: maiorCiclo.toFixed(2),
      eficiencia_percentual: eficiencia,
      capacidade_estimada_dia: capacidadeEstimada,
      postos
    });

  } catch (error) {
    console.error("Erro na análise da linha:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 💰 SIMULAÇÃO E IMPACTO FINANCEIRO
// ========================================

app.get("/simulacao-linha/:linhaId", async (req, res) => {
  try {
    const { linhaId } = req.params;

    const result = await pool.query(
      `
      SELECT 
        lp_prod.id as linha_produto_id,
        p.nome as produto_nome,
        lp_prod.takt_time_segundos,
        lp_prod.meta_diaria,
        l.horas_produtivas_dia,
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
      `,
      [linhaId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Linha não encontrada" });
    }

    const horasProdutivas = parseFloat(result.rows[0].horas_produtivas_dia || 0);
    const diasMes = parseFloat(result.rows[0].dias_produtivos_mes || 0);

    const produtosMap = {};

    result.rows.forEach(row => {
      if (!produtosMap[row.linha_produto_id]) {
        produtosMap[row.linha_produto_id] = {
          produto_nome: row.produto_nome,
          takt: parseFloat(row.takt_time_segundos),
          metaDiaria: parseFloat(row.meta_diaria),
          microparadas: parseFloat(row.microparadas),
          retrabalho: parseFloat(row.retrabalho),
          refugo: parseFloat(row.refugo),
          postos: []
        };
      }

      produtosMap[row.linha_produto_id].postos.push({
        nome: row.posto_nome,
        ciclo: parseFloat(row.tempo_ciclo_segundos || 0),
        setup: parseFloat(row.tempo_setup_minutos || 0),
        disponibilidade: parseFloat(row.disponibilidade) / 100
      });
    });

    const resultados = [];

    for (const key in produtosMap) {
      const produto = produtosMap[key];

      let maiorCiclo = 0;
      let gargalo = null;
      let setupTotalMinutos = 0;

      produto.postos.forEach(p => {
        setupTotalMinutos += p.setup;

        const cicloReal = p.disponibilidade > 0
          ? p.ciclo / p.disponibilidade
          : p.ciclo;

        if (cicloReal > maiorCiclo) {
          maiorCiclo = cicloReal;
          gargalo = p.nome;
        }
      });

      const tempoPlanejado = horasProdutivas * 3600;
      const tempoParadas = (setupTotalMinutos * 60) + (produto.microparadas * 60);
      const tempoOperando = tempoPlanejado - tempoParadas;

      const capacidadeBruta = maiorCiclo > 0
        ? Math.floor(tempoOperando / maiorCiclo)
        : 0;

      const producaoBoa = capacidadeBruta - produto.refugo;

      // -------------------
      // CÁLCULO OEE
      // -------------------

      const disponibilidadeOEE = tempoPlanejado > 0
        ? tempoOperando / tempoPlanejado
        : 0;

      const performanceOEE = tempoOperando > 0
        ? (capacidadeBruta * produto.takt) / tempoOperando
        : 0;

      const qualidadeOEE = capacidadeBruta > 0
        ? producaoBoa / capacidadeBruta
        : 0;

      const oeeFinal =
        disponibilidadeOEE *
        performanceOEE *
        qualidadeOEE;

      resultados.push({
        produto: produto.produto_nome,
        meta_diaria_planejada: produto.metaDiaria,
        capacidade_bruta_dia: capacidadeBruta,
        producao_boa_dia: producaoBoa,
        deficit_pecas_dia: produto.metaDiaria - producaoBoa,
        gargalo: gargalo,
        tempo_ciclo_real_gargalo: maiorCiclo.toFixed(2),

        disponibilidade_percentual: (disponibilidadeOEE * 100).toFixed(2),
        performance_percentual: (performanceOEE * 100).toFixed(2),
        qualidade_percentual: (qualidadeOEE * 100).toFixed(2),
        oee_percentual: (oeeFinal * 100).toFixed(2)
      });
    }

    res.json({
      linha_id: linhaId,
      horas_produtivas_dia: horasProdutivas,
      produtos: resultados
    });

  } catch (error) {
    console.error("Erro no cálculo OEE:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// ⚖ BALANCEAMENTO DA LINHA
// ========================================

app.get("/balanceamento/:linhaId", async (req, res) => {
  try {
    const { linhaId } = req.params;

    const result = await pool.query(
      `
      SELECT 
        pt.nome,
        pt.tempo_ciclo_segundos,
        COALESCE(pt.disponibilidade_percentual, 100) as disponibilidade
      FROM posto_trabalho pt
      WHERE pt.linha_id = $1
      ORDER BY pt.ordem_fluxo
      `,
      [linhaId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Nenhum posto encontrado" });
    }

    let soma = 0;
    let maior = 0;
    let menor = Infinity;

    const postos = result.rows.map(p => {
      const ciclo = parseFloat(p.tempo_ciclo_segundos || 0);
      const disponibilidade = parseFloat(p.disponibilidade) / 100;
      const cicloReal = disponibilidade > 0 ? ciclo / disponibilidade : ciclo;

      soma += cicloReal;
      if (cicloReal > maior) maior = cicloReal;
      if (cicloReal < menor) menor = cicloReal;

      return {
        posto: p.nome,
        ciclo_real: cicloReal.toFixed(2)
      };
    });

    const media = soma / result.rows.length;

    const indiceBalanceamento = ((media / maior) * 100).toFixed(2);

    res.json({
      quantidade_postos: result.rows.length,
      tempo_medio_segundos: media.toFixed(2),
      maior_tempo_segundos: maior.toFixed(2),
      menor_tempo_segundos: menor.toFixed(2),
      indice_balanceamento_percentual: indiceBalanceamento,
      postos
    });

  } catch (error) {
    console.error("Erro no balanceamento:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 🌎 EFICIÊNCIA GLOBAL DA LINHA
// ========================================

app.get("/eficiencia-global/:linhaId", async (req, res) => {
  try {
    const { linhaId } = req.params;

    const result = await pool.query(
      `
      SELECT 
        lp.takt_time_segundos,
        lp.meta_diaria,
        pt.tempo_ciclo_segundos,
        COALESCE(pt.disponibilidade_percentual, 100) as disponibilidade
      FROM linha_producao lp
      LEFT JOIN posto_trabalho pt ON pt.linha_id = lp.id
      WHERE lp.id = $1
      `,
      [linhaId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Linha não encontrada" });
    }

    const takt = parseFloat(result.rows[0].takt_time_segundos || 0);
    const meta = parseFloat(result.rows[0].meta_diaria || 0);

    let maiorCiclo = 0;
    let somaCiclos = 0;

    result.rows.forEach(p => {
      const ciclo = parseFloat(p.tempo_ciclo_segundos || 0);
      const disponibilidade = parseFloat(p.disponibilidade) / 100;
      const cicloReal = disponibilidade > 0 ? ciclo / disponibilidade : ciclo;

      somaCiclos += cicloReal;

      if (cicloReal > maiorCiclo) {
        maiorCiclo = cicloReal;
      }
    });

    if (maiorCiclo === 0 || meta === 0 || takt === 0) {
      return res.json({
        mensagem: "Linha ainda não estruturada",
        meta_planejada: meta
      });
    }
    const capacidadeTeorica = meta;

    const capacidadeReal = Math.floor((meta * takt) / maiorCiclo);

    const ocupacaoLinha = ((somaCiclos / (maiorCiclo * result.rows.length)) * 100).toFixed(2);

    const eficienciaGlobal = ((capacidadeReal / meta) * 100).toFixed(2);

    res.json({
      meta_planejada: meta,
      capacidade_teorica_maxima: capacidadeTeorica,
      capacidade_real: capacidadeReal,
      taxa_ocupacao_linha_percentual: ocupacaoLinha,
      eficiencia_global_percentual: eficienciaGlobal
    });

  } catch (error) {
    console.error("Erro na eficiência global:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 📊 ANALISE DE VARIABILIDADE DO POSTO
// ========================================

app.get("/variabilidade/:postoId", async (req, res) => {
  try {
    const { postoId } = req.params;

    const result = await pool.query(
      `SELECT tempo_ciclo_segundos
       FROM ciclo_medicao
       WHERE posto_id = $1`,
      [postoId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Nenhuma medição encontrada para este posto" });
    }

    const valores = result.rows.map(r => parseFloat(r.tempo_ciclo_segundos));

    const n = valores.length;

    const media = valores.reduce((a, b) => a + b, 0) / n;

    const variancia =
      valores.reduce((acc, val) => acc + Math.pow(val - media, 2), 0) / n;

    const desvioPadrao = Math.sqrt(variancia);

    const coeficienteVariacao = (desvioPadrao / media) * 100;

    let classificacao = "";

    if (coeficienteVariacao < 5) {
      classificacao = "Processo muito estável";
    } else if (coeficienteVariacao < 10) {
      classificacao = "Processo estável";
    } else if (coeficienteVariacao < 20) {
      classificacao = "Processo instável";
    } else {
      classificacao = "Processo crítico";
    }

    res.json({
      quantidade_medicoes: n,
      media_segundos: media.toFixed(2),
      desvio_padrao_segundos: desvioPadrao.toFixed(2),
      coeficiente_variacao_percentual: coeficienteVariacao.toFixed(2),
      classificacao
    });

  } catch (error) {
    console.error("Erro na análise de variabilidade:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 📦 VINCULAR PRODUTO À LINHA
// ========================================

app.post("/linha-produto", async (req, res) => {
  try {
    const { linha_id, produto_id, takt_time_segundos, meta_diaria } = req.body;

    if (!linha_id || !produto_id || !takt_time_segundos || !meta_diaria) {
      return res.status(400).json({
        erro: "linha_id, produto_id, takt_time_segundos e meta_diaria são obrigatórios"
      });
    }

    const result = await pool.query(
      `
      INSERT INTO linha_produto (linha_id, produto_id, takt_time_segundos, meta_diaria)
      VALUES ($1, $2, $3, $4)
      RETURNING *
      `,
      [linha_id, produto_id, takt_time_segundos, meta_diaria]
    );

    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error("Erro ao vincular produto à linha:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 📉 REGISTRAR PERDAS POR PRODUTO NA LINHA
// ========================================

app.post("/perdas", async (req, res) => {
  try {
    const {
      linha_produto_id,
      microparadas_minutos,
      retrabalho_pecas,
      refugo_pecas
    } = req.body;

    if (!linha_produto_id) {
      return res.status(400).json({
        erro: "linha_produto_id é obrigatório"
      });
    }

    const result = await pool.query(
      `
      INSERT INTO perdas_linha 
      (linha_produto_id, microparadas_minutos, retrabalho_pecas, refugo_pecas)
      VALUES ($1, $2, $3, $4)
      RETURNING *
      `,
      [
        linha_produto_id,
        microparadas_minutos || 0,
        retrabalho_pecas || 0,
        refugo_pecas || 0
      ]
    );

    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error("Erro ao registrar perdas:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 📋 LISTAR PERDAS POR LINHA
// ========================================

app.get("/perdas/:linhaId", autenticarToken, async (req, res) => {
  try {
    const { linhaId } = req.params;
    
    const result = await pool.query(
      `SELECT pl.*, p.nome as produto_nome
       FROM perdas_linha pl
       JOIN linha_produto lp ON lp.id = pl.linha_produto_id
       JOIN produto p ON p.id = lp.produto_id
       WHERE lp.linha_id = $1
       ORDER BY pl.id DESC`,
      [linhaId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar perdas:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// ✏️ ATUALIZAR PERDA
// ========================================

app.put("/perdas/:id", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { microparadas_minutos, retrabalho_pecas, refugo_pecas } = req.body;

    const result = await pool.query(
      `UPDATE perdas_linha 
       SET microparadas_minutos = COALESCE($1, microparadas_minutos),
           retrabalho_pecas = COALESCE($2, retrabalho_pecas),
           refugo_pecas = COALESCE($3, refugo_pecas)
       WHERE id = $4
       RETURNING *`,
      [microparadas_minutos, retrabalho_pecas, refugo_pecas, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Registro não encontrado" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao atualizar perda:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 🗑️ EXCLUIR PERDA
// ========================================

app.delete("/perdas/:id", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query("DELETE FROM perdas_linha WHERE id = $1 RETURNING *", [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Registro não encontrado" });
    }

    res.json({ mensagem: "Registro excluído com sucesso" });
  } catch (error) {
    console.error("Erro ao excluir perda:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 👤 CRIAR USUÁRIO (ADMIN INICIAL)
// ========================================

app.post("/auth/register", async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
      return res.status(400).json({ erro: "Nome, email e senha são obrigatórios" });
    }

    // Sanitização básica
    const emailSanitizado = email?.trim().toLowerCase();
    const nomeSanitizado = nome?.trim();

    const senhaHash = await bcrypt.hash(senha, 10);

    const result = await pool.query(
      `INSERT INTO usuarios (nome, email, senha_hash)
       VALUES ($1, $2, $3)
       RETURNING id, nome, email`,
      [nomeSanitizado, emailSanitizado, senhaHash]
    );

    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error("Erro ao registrar usuário:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 🔐 LOGIN COM RATE LIMITING
// ========================================

app.post("/auth/login", loginLimiter, async (req, res) => {
  try {
    const { email, senha } = req.body;

    if (!email || !senha) {
      return res.status(400).json({ erro: "Email e senha são obrigatórios" });
    }

    // Sanitização
    const emailSanitizado = email?.trim().toLowerCase();

    const result = await pool.query(
      "SELECT * FROM usuarios WHERE LOWER(email) = LOWER($1)",
      [emailSanitizado]
    );

    if (result.rows.length === 0) {
      // Log de segurança
      console.warn(`Tentativa de login falha - Email: ${emailSanitizado} - IP: ${req.ip}`);
      return res.status(401).json({ erro: "Usuário não encontrado" });
    }

    const usuario = result.rows[0];

    const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);

    if (!senhaValida) {
      console.warn(`Tentativa de login falha - Senha inválida - Email: ${emailSanitizado} - IP: ${req.ip}`);
      return res.status(401).json({ erro: "Senha inválida" });
    }

    const token = jwt.sign(
      { id: usuario.id, email: usuario.email },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({
      token,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email
      }
    });

  } catch (error) {
    console.error("Erro no login:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 🔒 MIDDLEWARE DE AUTENTICAÇÃO
// ========================================

function autenticarToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({ erro: "Token não fornecido" });
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ erro: "Token inválido" });
  }

  jwt.verify(token, JWT_SECRET, (err, usuario) => {
    if (err) {
      return res.status(403).json({ erro: "Token inválido ou expirado" });
    }

    req.usuario = usuario;
    next();
  });
}

// ========================================
// 📝 AÇÕES DO CONSULTOR
// ========================================

// Criar tabela de ações se não existir
app.get("/acoes/criar-tabela", async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS acoes_consultor (
        id SERIAL PRIMARY KEY,
        linha_id INTEGER NOT NULL REFERENCES linha_producao(id) ON DELETE CASCADE,
        texto TEXT NOT NULL,
        concluida BOOLEAN DEFAULT FALSE,
        prioridade VARCHAR(20) DEFAULT 'media',
        data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        data_conclusao TIMESTAMP,
        criado_por INTEGER REFERENCES usuarios(id)
      );
    `);
    res.json({ mensagem: "Tabela de ações criada/verificada com sucesso" });
  } catch (error) {
    console.error("Erro ao criar tabela:", error);
    res.status(500).json({ erro: "Erro ao criar tabela" });
  }
});

// Listar ações de uma linha
app.get("/acoes/:linhaId", autenticarToken, async (req, res) => {
  try {
    const { linhaId } = req.params;
    
    const result = await pool.query(
      `SELECT * FROM acoes_consultor 
       WHERE linha_id = $1 
       ORDER BY data_criacao DESC`,
      [linhaId]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar ações:", error);
    res.status(500).json({ erro: "Erro ao buscar ações" });
  }
});

// Criar nova ação
app.post("/acoes", autenticarToken, async (req, res) => {
  try {
    const { linha_id, texto, prioridade = 'media' } = req.body;
    const usuario_id = req.usuario.id;

    if (!linha_id || !texto) {
      return res.status(400).json({ erro: "linha_id e texto são obrigatórios" });
    }

    const result = await pool.query(
      `INSERT INTO acoes_consultor (linha_id, texto, prioridade, criado_por)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [linha_id, texto, prioridade, usuario_id]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao criar ação:", error);
    res.status(500).json({ erro: "Erro ao criar ação" });
  }
});

// Atualizar ação (concluir, editar texto, etc)
app.put("/acoes/:id", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { texto, concluida, prioridade } = req.body;

    let query = "UPDATE acoes_consultor SET ";
    const values = [];
    const updates = [];
    let index = 1;

    if (texto !== undefined) {
      updates.push(`texto = $${index}`);
      values.push(texto);
      index++;
    }

    if (concluida !== undefined) {
      updates.push(`concluida = $${index}`);
      updates.push(`data_conclusao = ${concluida ? 'CURRENT_TIMESTAMP' : 'NULL'}`);
      values.push(concluida);
      index++;
    }

    if (prioridade !== undefined) {
      updates.push(`prioridade = $${index}`);
      values.push(prioridade);
      index++;
    }

    if (updates.length === 0) {
      return res.status(400).json({ erro: "Nenhum campo para atualizar" });
    }

    query += updates.join(", ") + ` WHERE id = $${index} RETURNING *`;
    values.push(id);

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Ação não encontrada" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao atualizar ação:", error);
    res.status(500).json({ erro: "Erro ao atualizar ação" });
  }
});

// Excluir ação
app.delete("/acoes/:id", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(
      "DELETE FROM acoes_consultor WHERE id = $1 RETURNING *",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Ação não encontrada" });
    }

    res.json({ mensagem: "Ação excluída com sucesso" });
  } catch (error) {
    console.error("Erro ao excluir ação:", error);
    res.status(500).json({ erro: "Erro ao excluir ação" });
  }
});

// ========================================
// 📊 MEDIÇÕES MELHORADAS
// ========================================

// Criar tabela de medições estendida se não existir
app.get("/medicoes/criar-tabela", async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medicoes_detalhadas (
        id SERIAL PRIMARY KEY,
        posto_id INTEGER NOT NULL REFERENCES posto_trabalho(id) ON DELETE CASCADE,
        tipo VARCHAR(20) NOT NULL, -- 'ciclo', 'parada', 'evento'
        valor_numerico DECIMAL(10,2),
        turno INTEGER,
        descricao TEXT,
        data_medicao DATE DEFAULT CURRENT_DATE,
        hora_medicao TIME DEFAULT CURRENT_TIME,
        criado_por INTEGER REFERENCES usuarios(id)
      );
    `);
    res.json({ mensagem: "Tabela de medições criada/verificada com sucesso" });
  } catch (error) {
    console.error("Erro ao criar tabela:", error);
    res.status(500).json({ erro: "Erro ao criar tabela" });
  }
});

// Registrar medição detalhada
app.post("/medicoes", autenticarToken, async (req, res) => {
  try {
    const { 
      posto_id, 
      tipo,           // 'ciclo', 'parada', 'evento'
      valor_numerico, // segundos ou minutos
      turno,
      descricao,
      data_medicao
    } = req.body;

    const usuario_id = req.usuario.id;

    if (!posto_id || !tipo) {
      return res.status(400).json({ erro: "posto_id e tipo são obrigatórios" });
    }

    const result = await pool.query(
      `INSERT INTO medicoes_detalhadas 
       (posto_id, tipo, valor_numerico, turno, descricao, data_medicao, criado_por)
       VALUES ($1, $2, $3, $4, $5, COALESCE($6, CURRENT_DATE), $7)
       RETURNING *`,
      [posto_id, tipo, valor_numerico, turno, descricao, data_medicao, usuario_id]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao registrar medição:", error);
    res.status(500).json({ erro: "Erro ao registrar medição" });
  }
});

// Listar medições de um posto
app.get("/medicoes/:postoId", autenticarToken, async (req, res) => {
  try {
    const { postoId } = req.params;
    const { tipo, inicio, fim } = req.query;

    let query = "SELECT * FROM medicoes_detalhadas WHERE posto_id = $1";
    const params = [postoId];
    let index = 2;

    if (tipo) {
      query += ` AND tipo = $${index}`;
      params.push(tipo);
      index++;
    }

    if (inicio && fim) {
      query += ` AND data_medicao BETWEEN $${index} AND $${index+1}`;
      params.push(inicio, fim);
      index += 2;
    }

    query += " ORDER BY data_medicao DESC, hora_medicao DESC";

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar medições:", error);
    res.status(500).json({ erro: "Erro ao buscar medições" });
  }
});

// Estatísticas de medições de um posto
app.get("/medicoes/estatisticas/:postoId", autenticarToken, async (req, res) => {
  try {
    const { postoId } = req.params;

    // Médias por tipo
    const result = await pool.query(
      `SELECT 
         tipo,
         COUNT(*) as quantidade,
         AVG(valor_numerico) as media,
         MIN(valor_numerico) as minimo,
         MAX(valor_numerico) as maximo,
         STDDEV(valor_numerico) as desvio_padrao
       FROM medicoes_detalhadas
       WHERE posto_id = $1
       GROUP BY tipo`,
      [postoId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar estatísticas:", error);
    res.status(500).json({ erro: "Erro ao buscar estatísticas" });
  }
});

// ========================================
// 🗑️ ROTA PARA CRIAR TODAS AS TABELAS
// ========================================

app.get("/setup", async (req, res) => {
  try {
    // Criar tabela de ações
    await pool.query(`
      CREATE TABLE IF NOT EXISTS acoes_consultor (
        id SERIAL PRIMARY KEY,
        linha_id INTEGER NOT NULL REFERENCES linha_producao(id) ON DELETE CASCADE,
        texto TEXT NOT NULL,
        concluida BOOLEAN DEFAULT FALSE,
        prioridade VARCHAR(20) DEFAULT 'media',
        data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        data_conclusao TIMESTAMP,
        criado_por INTEGER REFERENCES usuarios(id)
      );
    `);

    // Criar tabela de medições
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medicoes_detalhadas (
        id SERIAL PRIMARY KEY,
        posto_id INTEGER NOT NULL REFERENCES posto_trabalho(id) ON DELETE CASCADE,
        tipo VARCHAR(20) NOT NULL,
        valor_numerico DECIMAL(10,2),
        turno INTEGER,
        descricao TEXT,
        data_medicao DATE DEFAULT CURRENT_DATE,
        hora_medicao TIME DEFAULT CURRENT_TIME,
        criado_por INTEGER REFERENCES usuarios(id)
      );
    `);

    res.json({ 
      mensagem: "Tabelas criadas/verificadas com sucesso",
      tabelas: ["acoes_consultor", "medicoes_detalhadas"]
    });
  } catch (error) {
    console.error("Erro no setup:", error);
    res.status(500).json({ erro: "Erro ao criar tabelas" });
  }
});

// ========================================
// 📊 MEDIÇÕES DETALHADAS
// ========================================

// DELETE /medicoes/:id (NOVO)
app.delete("/medicoes/:id", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(
      "DELETE FROM medicoes_detalhadas WHERE id = $1 RETURNING *",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Medição não encontrada" });
    }

    res.json({ mensagem: "Medição excluída com sucesso" });
  } catch (error) {
    console.error("Erro ao excluir medição:", error);
    res.status(500).json({ erro: "Erro ao excluir medição" });
  }
});

// ========================================
// 📈 HISTÓRICO DA LINHA (COMPARATIVO)
// ========================================

app.get("/historico-linha/:linhaId", autenticarToken, async (req, res) => {
  try {
    const { linhaId } = req.params;

    // Buscar medições agrupadas por mês para calcular OEE histórico
    const result = await pool.query(
      `
      SELECT 
        DATE_TRUNC('month', data_medicao) as mes,
        COUNT(*) as total_medicoes,
        AVG(valor_numerico) as media_ciclo,
        STDDEV(valor_numerico) as desvio_padrao
      FROM medicoes_detalhadas md
      JOIN posto_trabalho pt ON pt.id = md.posto_id
      WHERE pt.linha_id = $1 AND md.tipo = 'ciclo'
      GROUP BY DATE_TRUNC('month', data_medicao)
      ORDER BY mes DESC
      LIMIT 6
      `,
      [linhaId]
    );

    // Para cada mês, calcular OEE aproximado
    const historico = await Promise.all(
      result.rows.map(async (row) => {
        // Buscar dados da linha para o período
        const linhaData = await pool.query(
          `SELECT takt_time_segundos, meta_diaria FROM linha_producao WHERE id = $1`,
          [linhaId]
        );

        const takt = linhaData.rows[0]?.takt_time_segundos || 1;
        const meta = linhaData.rows[0]?.meta_diaria || 1;
        
        // Cálculo simplificado do OEE histórico
        const oeeCalculado = (takt / (row.media_ciclo || takt)) * 100;
        
        return {
          mes: row.mes,
          oee: Math.min(100, Math.round(oeeCalculado * 100) / 100),
          medicoes: parseInt(row.total_medicoes),
          media_ciclo: parseFloat(row.media_ciclo).toFixed(2),
          desvio_padrao: parseFloat(row.desvio_padrao).toFixed(2)
        };
      })
    );

    res.json(historico);
  } catch (error) {
    console.error("Erro ao buscar histórico:", error);
    res.status(500).json({ erro: "Erro ao buscar histórico" });
  }
});

// ========================================
// 📦 PRODUTOS (CRUD COMPLETO)
// ========================================

// Listar todos os produtos
app.get("/produtos", autenticarToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM produto ORDER BY id");
    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar produtos:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// Buscar um produto específico
app.get("/produtos/:id", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query("SELECT * FROM produto WHERE id = $1", [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Produto não encontrado" });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao buscar produto:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// Criar novo produto (CORRIGIDO: AGORA SALVA A EMPRESA)
app.post("/produtos", autenticarToken, async (req, res) => {
  try {
    // 1. Pegamos o empresa_id que vem do frontend
    const { nome, valor_unitario, empresa_id } = req.body;

    if (!nome) {
      return res.status(400).json({ erro: "Nome do produto é obrigatório" });
    }
    
    if (!empresa_id) {
      return res.status(400).json({ erro: "ID da empresa é obrigatório para o vínculo" });
    }

    // 2. Ajustamos para a tabela "produtos" (plural) e incluímos empresa_id
    const result = await pool.query(
      `INSERT INTO produtos (nome, valor_unitario, empresa_id)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [nome, valor_unitario || 0, empresa_id]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao criar produto:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// Atualizar produto (CORRIGIDO: TABELA NO PLURAL)
app.put("/produtos/:id", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { nome, valor_unitario } = req.body;

    // Convertendo para float para garantir que o banco aceite o decimal
    const valorNum = valor_unitario !== undefined ? parseFloat(valor_unitario) : null;

    const result = await pool.query(
      `UPDATE produtos 
       SET nome = COALESCE($1, nome), 
           valor_unitario = COALESCE($2, valor_unitario)
       WHERE id = $3
       RETURNING *`,
      [nome, valorNum, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Produto não encontrado" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao atualizar produto:", error);
    res.status(500).json({ erro: "Erro no servidor ao atualizar" });
  }
});

// Excluir produto (CORRIGIDO: TABELA NO PLURAL)
app.delete("/produtos/:id", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // ✅ Alterado de 'produto' para 'produtos'
    const result = await pool.query(
      "DELETE FROM produtos WHERE id = $1 RETURNING *", 
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Produto não encontrado" });
    }

    res.json({ mensagem: "Produto excluído com sucesso" });
  } catch (error) {
    console.error("Erro ao excluir produto:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 📦 PRODUTOS POR EMPRESA (CORRIGIDO: TABELA NO PLURAL)
// ========================================
app.get("/produtos/empresa/:empresaId", autenticarToken, async (req, res) => {
  try {
    const { empresaId } = req.params;
    
    // ✅ Alterado de 'produto' para 'produtos' para bater com o Banco de Dados
    const result = await pool.query(`
      SELECT * FROM produtos 
      WHERE empresa_id = $1
      ORDER BY nome
    `, [empresaId]);

    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar produtos da empresa:", error);
    res.status(500).json({ erro: "Erro no servidor ao buscar lista" });
  }
});

// ========================================
// 📋 LISTAR PRODUTOS VINCULADOS A UMA LINHA
// ========================================

app.get("/linha-produto/:linhaId", autenticarToken, async (req, res) => {
  try {
    const { linhaId } = req.params;
    
    const result = await pool.query(
      `SELECT lp.*, p.nome as produto_nome, p.valor_unitario
       FROM linha_produto lp
       JOIN produto p ON p.id = lp.produto_id
       WHERE lp.linha_id = $1
       ORDER BY lp.id`,
      [linhaId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar produtos da linha:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 💰 ESTATÍSTICAS FINANCEIRAS DA LINHA
// ========================================

app.get("/financeiro/linha/:linhaId", autenticarToken, async (req, res) => {
  try {
    const { linhaId } = req.params;

    // Buscar dados da linha
    const linhaData = await pool.query(
      `SELECT l.*, e.dias_produtivos_mes 
       FROM linha_producao l
       JOIN empresa e ON e.id = l.empresa_id
       WHERE l.id = $1`,
      [linhaId]
    );

    if (linhaData.rows.length === 0) {
      return res.status(404).json({ erro: "Linha não encontrada" });
    }

    const linha = linhaData.rows[0];
    const diasMes = linha.dias_produtivos_mes || 22;

    // Buscar postos com cargos
    const postosData = await pool.query(
      `SELECT pt.*, c.salario_base, c.encargos_percentual
       FROM posto_trabalho pt
       LEFT JOIN cargo c ON c.id = pt.cargo_id
       WHERE pt.linha_id = $1`,
      [linhaId]
    );

    // Calcular custos
    let custoTotalMaoObra = 0;
    let custoPorMinuto = 0;

    postosData.rows.forEach(posto => {
      if (posto.salario_base) {
        const salario = parseFloat(posto.salario_base);
        const encargos = parseFloat(posto.encargos_percentual || 70) / 100;
        const custoMensal = salario * (1 + encargos);
        custoTotalMaoObra += custoMensal;
      }
    });

    // Custo por minuto (considerando 22 dias, 8h/dia, 60min/h)
    const minutosMes = diasMes * 8 * 60;
    custoPorMinuto = minutosMes > 0 ? custoTotalMaoObra / minutosMes : 0;

    res.json({
      linha_id: linhaId,
      linha_nome: linha.nome,
      dias_produtivos_mes: diasMes,
      custo_mao_obra_mensal: custoTotalMaoObra,
      custo_por_minuto: custoPorMinuto,
      postos: postosData.rows.map(p => ({
        id: p.id,
        nome: p.nome,
        custo_mensal: p.salario_base ? 
          parseFloat(p.salario_base) * (1 + (parseFloat(p.encargos_percentual || 70) / 100)) : 0
      }))
    });

  } catch (error) {
    console.error("Erro ao calcular financeiro:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 💰 ESTATÍSTICAS FINANCEIRAS DA EMPRESA
// ========================================

app.get("/financeiro/empresa/:empresaId", autenticarToken, async (req, res) => {
  try {
    const { empresaId } = req.params;

    // Buscar todas as linhas da empresa
    const linhasData = await pool.query(
      `SELECT id FROM linha_producao WHERE empresa_id = $1`,
      [empresaId]
    );

    let custoTotalMaoObra = 0;
    const linhas = [];

    for (const linha of linhasData.rows) {
      const financeiroLinha = await pool.query(
        `SELECT * FROM financeiro_cache WHERE linha_id = $1 ORDER BY id DESC LIMIT 1`,
        [linha.id]
      );

      if (financeiroLinha.rows.length > 0) {
        const dados = financeiroLinha.rows[0];
        custoTotalMaoObra += parseFloat(dados.custo_mao_obra_mensal || 0);
        linhas.push({
          linha_id: linha.id,
          custo_mao_obra: dados.custo_mao_obra_mensal,
          custo_por_minuto: dados.custo_por_minuto
        });
      }
    }

    res.json({
      empresa_id: empresaId,
      total_linhas: linhasData.rows.length,
      custo_total_mao_obra_mensal: custoTotalMaoObra,
      linhas: linhas
    });

  } catch (error) {
    console.error("Erro ao calcular financeiro da empresa:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 📋 ALOCAÇÃO DE COLABORADORES
// ========================================

// Listar alocações de um posto
app.get("/alocacoes/posto/:postoId", autenticarToken, async (req, res) => {
  try {
    const { postoId } = req.params;
    const { turno, ativo } = req.query;

    let query = `
      SELECT a.*, c.nome as colaborador_nome, c.cargo_id,
             cr.nome as cargo_nome, cr.salario_base, cr.encargos_percentual
      FROM alocacao_colaborador a
      JOIN colaborador c ON c.id = a.colaborador_id
      LEFT JOIN cargo cr ON cr.id = c.cargo_id
      WHERE a.posto_id = $1
    `;
    const params = [postoId];
    let paramIndex = 2;

    if (turno) {
      query += ` AND a.turno = $${paramIndex}`;
      params.push(turno);
      paramIndex++;
    }

    if (ativo !== undefined) {
      query += ` AND a.ativo = $${paramIndex}`;
      params.push(ativo === 'true');
      paramIndex++;
    }

    query += " ORDER BY a.turno, a.data_inicio DESC";

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar alocações:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// Listar alocações de um colaborador
app.get("/alocacoes/colaborador/:colaboradorId", autenticarToken, async (req, res) => {
  try {
    const { colaboradorId } = req.params;
    const { ativo } = req.query;

    let query = `
      SELECT a.*, pt.nome as posto_nome, pt.linha_id,
             l.nome as linha_nome
      FROM alocacao_colaborador a
      JOIN posto_trabalho pt ON pt.id = a.posto_id
      JOIN linha_producao l ON l.id = pt.linha_id
      WHERE a.colaborador_id = $1
    `;
    const params = [colaboradorId];
    let paramIndex = 2;

    if (ativo !== undefined) {
      query += ` AND a.ativo = $${paramIndex}`;
      params.push(ativo === 'true');
      paramIndex++;
    }

    query += " ORDER BY a.data_inicio DESC";

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar alocações do colaborador:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// Criar nova alocação
app.post("/alocacoes", autenticarToken, async (req, res) => {
  try {
    const { colaborador_id, posto_id, turno, data_inicio, data_fim } = req.body;

    if (!colaborador_id || !posto_id || !turno) {
      return res.status(400).json({ 
        erro: "colaborador_id, posto_id e turno são obrigatórios" 
      });
    }

    // Verificar se já existe alocação ativa para este colaborador no mesmo turno
    const checkQuery = `
      SELECT id FROM alocacao_colaborador 
      WHERE colaborador_id = $1 AND turno = $2 AND ativo = true
    `;
    const checkResult = await pool.query(checkQuery, [colaborador_id, turno]);
    
    if (checkResult.rows.length > 0) {
      return res.status(400).json({ 
        erro: "Colaborador já possui alocação ativa neste turno" 
      });
    }

    const result = await pool.query(
      `INSERT INTO alocacao_colaborador 
       (colaborador_id, posto_id, turno, data_inicio, data_fim, ativo)
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING *`,
      [colaborador_id, posto_id, turno, data_inicio || new Date(), data_fim]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao criar alocação:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// Atualizar alocação (desativar, alterar datas)
app.put("/alocacoes/:id", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { data_fim, ativo } = req.body;

    const result = await pool.query(
      `UPDATE alocacao_colaborador 
       SET data_fim = COALESCE($1, data_fim),
           ativo = COALESCE($2, ativo),
           atualizado_em = CURRENT_TIMESTAMP
       WHERE id = $3
       RETURNING *`,
      [data_fim, ativo, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Alocação não encontrada" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao atualizar alocação:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// Excluir alocação
app.delete("/alocacoes/:id", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      "DELETE FROM alocacao_colaborador WHERE id = $1 RETURNING *",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Alocação não encontrada" });
    }

    res.json({ mensagem: "Alocação excluída com sucesso" });
  } catch (error) {
    console.error("Erro ao excluir alocação:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 🤖 IA PARA RELATÓRIOS (VERSÃO SEM IA)
// ========================================
app.post("/api/ia/gerar-relatorio", autenticarToken, async (req, res) => {
  try {
    const { dados, tipo } = req.body;

    if (!dados || !tipo) {
      return res.status(400).json({ erro: "Dados e tipo do relatório são obrigatórios." });
    }

    let relatorio = "";

    if (tipo === 'especifico') {
      // Relatório específico (linha única)
      const oeeAtual = dados.analise?.eficiencia_percentual || 0;
      const perdas = dados.perdasFinanceiras || { setup: 0, micro: 0, refugo: 0, total: 0 };
      
      let classificacao = "";
      if (oeeAtual < 40) classificacao = "Crítico";
      else if (oeeAtual < 60) classificacao = "Regular";
      else if (oeeAtual < 75) classificacao = "Bom";
      else classificacao = "Excelente";

      relatorio = `
RELATÓRIO TÉCNICO - ANÁLISE DE LINHA

Empresa: ${dados.empresa}
Linha: ${dados.linha}
Data: ${new Date().toLocaleDateString('pt-BR')}

1. RESUMO EXECUTIVO
A linha apresenta OEE de ${oeeAtual}%, classificado como "${classificacao}".
O gargalo identificado é ${dados.analise?.gargalo || "não identificado"}.

2. ANÁLISE DO OEE
O OEE atual está ${oeeAtual < 85 ? "abaixo" : "acima"} do benchmark World Class (85%),
${oeeAtual < 85 ? "indicando oportunidades significativas de melhoria." : "demonstrando excelente desempenho."}

3. ANÁLISE DO GARGALO
${dados.analise?.gargalo ? 
  `O gargalo em ${dados.analise.gargalo} limita a capacidade produtiva da linha.` : 
  "Nenhum gargalo crítico identificado."}

4. ANÁLISE FINANCEIRA
Perdas totais estimadas: R$ ${(perdas.total || 0).toFixed(2)}/mês
• Setup: R$ ${(perdas.setup || 0).toFixed(2)}/mês
• Microparadas: R$ ${(perdas.micro || 0).toFixed(2)}/mês
• Refugo: R$ ${(perdas.refugo || 0).toFixed(2)}/mês

5. PROJEÇÕES DE MELHORIA
• Cenário 10%: R$ ${((perdas.total || 0) * 0.1).toFixed(2)}/mês
• Cenário 20%: R$ ${((perdas.total || 0) * 0.2).toFixed(2)}/mês
• Cenário 30%: R$ ${((perdas.total || 0) * 0.3).toFixed(2)}/mês

6. RECOMENDAÇÕES
• Aplicar SMED nos postos com setup elevado
• Balancear linha para eliminar gargalos
• Implementar 5S para melhorar organização
• Treinar equipe em manutenção autônoma

7. PLANO DE AÇÃO
1. Diagnóstico detalhado (2 semanas)
2. Implantação de melhorias (4 semanas)
3. Acompanhamento de resultados (3 meses)

8. CONCLUSÃO
A linha apresenta potencial de ganho significativo com baixo investimento.
Recomenda-se iniciar pelas ações de maior impacto e menor esforço.
      `;
    } else {
      // Relatório geral
      const oeeMedio = dados.resumoFinanceiro?.oeeMedio || 0;
      const perdas = dados.resumoFinanceiro?.perdas || { setup: 0, micro: 0, refugo: 0 };
      const perdasTotais = dados.resumoFinanceiro?.perdasTotais || 0;

      relatorio = `
RELATÓRIO GERAL DE DIAGNÓSTICO

Empresa: ${dados.empresa}
Data: ${new Date().toLocaleDateString('pt-BR')}

1. RESUMO EXECUTIVO
A empresa possui ${dados.linhas?.length || 0} linhas de produção,
com OEE médio de ${oeeMedio}%.

2. ANÁLISE POR INDICADOR
• OEE Médio: ${oeeMedio}%
• Perdas totais: R$ ${perdasTotais.toFixed(2)}/mês
• Gargalos críticos: ${dados.resumoFinanceiro?.gargalosCriticos || 0}

3. DETALHAMENTO DAS PERDAS
• Setup: R$ ${(perdas.setup || 0).toFixed(2)}/mês (${((perdas.setup/perdasTotais)*100).toFixed(1)}%)
• Microparadas: R$ ${(perdas.micro || 0).toFixed(2)}/mês (${((perdas.micro/perdasTotais)*100).toFixed(1)}%)
• Refugo: R$ ${(perdas.refugo || 0).toFixed(2)}/mês (${((perdas.refugo/perdasTotais)*100).toFixed(1)}%)

4. RANKING DE LINHAS POR DESEMPENHO
${dados.linhas?.map((l, idx) => 
  `${idx+1}. ${l.nome}: OEE ${l.analise?.eficiencia_percentual || 0}%`
).join('\n')}

5. OPORTUNIDADES DE MELHORIA
• Redução de 10% nas perdas: R$ ${(perdasTotais * 0.1).toFixed(2)}/mês
• Redução de 20% nas perdas: R$ ${(perdasTotais * 0.2).toFixed(2)}/mês
• Redução de 30% nas perdas: R$ ${(perdasTotais * 0.3).toFixed(2)}/mês

6. RECOMENDAÇÕES ESTRATÉGICAS
• Priorizar ações nas linhas com menor OEE
• Focar na redução do tipo de perda mais significativo
• Estabelecer metas progressivas de melhoria
• Criar programa de treinamento em ferramentas Lean

7. PLANO DE AÇÃO CONSOLIDADO
• Fase 1: Diagnóstico aprofundado (2 semanas)
• Fase 2: Implantação piloto (4 semanas)
• Fase 3: Expansão para todas as linhas (3 meses)
• Fase 4: Acompanhamento e sustentação (contínuo)

8. CONCLUSÃO
A empresa possui oportunidades significativas de melhoria.
Recomenda-se iniciar um programa estruturado de otimização.
      `;
    }

    res.json({ relatorio });

  } catch (error) {
    console.error("Erro na rota /api/ia/gerar-relatorio:", error);
    res.status(500).json({ erro: "Erro interno no servidor" });
  }
});

// ========================================
// 👤 CONSULTOR - ROTAS
// ========================================

// Setup do consultor (cria tabela e usuário)
app.get("/consultor/setup", async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS consultores (
        id SERIAL PRIMARY KEY,
        nome VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        senha_hash VARCHAR(255) NOT NULL,
        telefone VARCHAR(20),
        cargo VARCHAR(50),
        foto TEXT,
        faturamento_mes DECIMAL(12,2) DEFAULT 45000,
        faturamento_ano DECIMAL(12,2) DEFAULT 540000,
        faturamento_projetado DECIMAL(12,2) DEFAULT 1200000,
        taxa_retencao DECIMAL(5,2) DEFAULT 98,
        satisfacao_media DECIMAL(3,1) DEFAULT 4.8,
        projetos_concluidos INTEGER DEFAULT 156,
        horas_consultadas INTEGER DEFAULT 450,
        roi_medio DECIMAL(4,2) DEFAULT 3.2,
        meta_faturamento DECIMAL(12,2) DEFAULT 1200000,
        meta_clientes INTEGER DEFAULT 15,
        meta_satisfacao DECIMAL(3,1) DEFAULT 4.8,
        missao TEXT,
        visao TEXT,
        valores TEXT[],
        data_cadastro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    const checkUser = await pool.query("SELECT id FROM consultores WHERE email = $1", ["henriquelimapaiva@nexus.com.br"]);
    if (checkUser.rows.length > 0) {
      await pool.query("DELETE FROM consultores WHERE email = $1", ["henriquelimapaiva@nexus.com.br"]);
      console.log("Usuário antigo removido para recriação");
    }

    const senhaHash = await bcrypt.hash("Nexus2903.", 10);
    await pool.query(`
      INSERT INTO consultores (nome, email, senha_hash, cargo, missao, visao, valores)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [
      "Henrique de Lima Paiva",
      "henriquelimapaiva@nexus.com.br",
      senhaHash,
      "Consultor Sênior",
      "Transformar indústrias através da engenharia aplicada, maximizando eficiência e reduzindo perdas com soluções personalizadas e baseadas em dados.",
      "Ser referência nacional em consultoria de otimização de processos industriais até 2030, impactando mais de 100 empresas com ganhos superiores a R$ 100 milhões.",
      ["Excelência Técnica", "Transparência", "Inovação Constante", "Resultado para o Cliente", "Ética e Integridade", "Sustentabilidade"]
    ]);

    const testUser = await pool.query("SELECT senha_hash FROM consultores WHERE email = $1", ["henriquelimapaiva@nexus.com.br"]);
    const senhaValida = await bcrypt.compare("Nexus2903.", testUser.rows[0].senha_hash);

    res.json({ 
      mensagem: "Tabela de consultores criada e usuário padrão inserido!",
      teste_login: senhaValida ? "✅ Senha OK" : "❌ Problema na senha"
    });
  } catch (error) {
    console.error("Erro ao criar tabela de consultores:", error);
    res.status(500).json({ erro: error.message });
  }
});

// LOGIN DO CONSULTOR
app.post("/consultor/login", loginLimiter, async (req, res) => {
  try {
    const { email, senha } = req.body;

    if (!email || !senha) {
      return res.status(400).json({ erro: "Email e senha são obrigatórios" });
    }

    const emailSanitizado = email?.trim().toLowerCase();

    const result = await pool.query(
      "SELECT * FROM consultores WHERE LOWER(email) = LOWER($1)",
      [emailSanitizado]
    );

    if (result.rows.length === 0) {
      console.warn(`Tentativa de login falha - Usuário não encontrado: ${emailSanitizado} - IP: ${req.ip}`);
      return res.status(401).json({ erro: "Usuário não encontrado" });
    }

    const consultor = result.rows[0];

    const senhaValida = await bcrypt.compare(senha, consultor.senha_hash);

    if (!senhaValida) {
      console.warn(`Tentativa de login falha - Senha inválida - Email: ${emailSanitizado} - IP: ${req.ip}`);
      return res.status(401).json({ erro: "Senha inválida" });
    }

    const token = jwt.sign(
      { id: consultor.id, email: consultor.email, role: "consultor" },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({
      token,
      usuario: {
        id: consultor.id,
        nome: consultor.nome,
        email: consultor.email,
        cargo: consultor.cargo
      }
    });

  } catch (error) {
    console.error("Erro no login do consultor:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// DEBUG (opcional)
app.get("/consultor/debug", async (req, res) => {
  try {
    const user = await pool.query(
      "SELECT id, nome, email, senha_hash FROM consultores WHERE email = $1",
      ["henriquelimapaiva@nexus.com.br"]
    );
    if (user.rows.length === 0) return res.json({ erro: "Usuário não encontrado" });
    const consultor = user.rows[0];
    const senhaValida = await bcrypt.compare("Nexus2903.", consultor.senha_hash);
    res.json({
      usuario: { id: consultor.id, nome: consultor.nome, email: consultor.email },
      senha_valida: senhaValida
    });
  } catch (error) {
    console.error("Erro:", error);
    res.status(500).json({ erro: error.message });
  }
});

// ========================================
// 🤖 IA PARA PROPOSTA COMERCIAL (VERSÃO SEM IA)
// ========================================
app.post("/api/ia/gerar-proposta", autenticarToken, async (req, res) => {
  try {
    const { dadosProposta } = req.body;

    if (!dadosProposta) {
      return res.status(400).json({ erro: "Dados da proposta são obrigatórios" });
    }

    const proposta = `
NEXUS ENGENHARIA APLICADA
PROPOSTA COMERCIAL

Data: ${dadosProposta.data || new Date().toLocaleDateString('pt-BR')}
Validade: 15 dias

À
${dadosProposta.empresa || "Cliente"}
At.: Diretoria

Prezados,

Após análise detalhada, apresentamos nossa proposta para otimização dos processos produtivos.

1. DIAGNÓSTICO ATUAL
• OEE Médio: ${dadosProposta.diagnostico?.oeeMedio || "XX"}%
• Perdas Totais: R$ ${(dadosProposta.diagnostico?.perdasTotais || 0).toFixed(2)}/mês
• Gargalos Críticos: ${dadosProposta.diagnostico?.gargalosCriticos || 0}
• Linhas: ${dadosProposta.diagnostico?.totalLinhas || 0}
• Postos: ${dadosProposta.diagnostico?.totalPostos || 0}

2. ESCOPO DO TRABALHO
• Diagnóstico: ${dadosProposta.escopo?.diagnostico || "2 semanas"}
• Implementação: ${dadosProposta.escopo?.implementacao || "4 semanas"}
• Acompanhamento: ${dadosProposta.escopo?.acompanhamento || "3 meses"}

3. INVESTIMENTO
• Honorários totais: R$ ${(dadosProposta.investimento?.honorarios || 0).toFixed(2)}
• Entrada (50%): R$ ${(dadosProposta.investimento?.entrada || 0).toFixed(2)}
• Saldo (50%): R$ ${(dadosProposta.investimento?.saldo || 0).toFixed(2)}

4. RETORNO SOBRE INVESTIMENTO
• Ganho Mensal: R$ ${(dadosProposta.retorno?.ganhoMensal || 0).toFixed(2)}
• ROI Anual: ${dadosProposta.retorno?.roiAnual || "XX"}%
• Payback: ${dadosProposta.retorno?.payback || "XX"} meses

5. CRONOGRAMA
• Semana 1-2: Diagnóstico aprofundado
• Semana 3-6: Implementação das melhorias
• Semana 7-18: Acompanhamento e sustentação

6. CONDIÇÕES GERAIS
• Validade: 15 dias
• Início: mediante assinatura do contrato
• Horário: segunda a sexta, 8h às 18h

Atenciosamente,

__________________________
Eng. Responsável
Nexus Engenharia Aplicada
`;

    res.json({ proposta });

  } catch (error) {
    console.error("Erro na rota /api/ia/gerar-proposta:", error);
    res.status(500).json({ erro: "Erro interno no servidor" });
  }
});

// ========================================
// 🤖 IA PARA PROPOSTA COMPLETA (VERSÃO SEM IA)
// ========================================
app.post("/api/ia/gerar-proposta-completa", autenticarToken, async (req, res) => {
  try {
    const dados = req.body;

    if (!dados || !dados.empresa) {
      return res.status(400).json({ erro: "Dados da empresa são obrigatórios" });
    }

    // Gerar a proposta COMPLETA usando os dados (sem IA)
    const proposta = `
NEXUS ENGENHARIA APLICADA
PROPOSTA COMERCIAL Nº ___/2026

Data: ${dados.data}
Validade: 15 dias

À
${dados.empresa}
At.: Diretoria Industrial

Prezados,

Após análise detalhada realizada em sua planta industrial, apresentamos nossa proposta para otimização dos processos produtivos.

1. DIAGNÓSTICO ATUAL
   Com base nos dados coletados, identificamos:
   • OEE Médio: ${dados.oeeMedio}% (benchmark World Class: 85%)
   • Perdas Totais: R$ ${(dados.perdasTotais || 0).toFixed(2)}/mês
   • Gargalos Críticos: ${dados.gargalosCriticos || 0}
   • Linhas de Produção: ${dados.totalLinhas || 0}
   • Postos de Trabalho: ${dados.totalPostos || 0}
   
   ${dados.dadosLinhas?.map(l => 
     `• ${l.nome}: OEE ${l.oee}%, Gargalo em ${l.gargalo}, Capacidade de ${l.capacidade} peças/dia`
   ).join('\n   ')}

2. ESCOPO DOS SERVIÇOS (DETALHADO)

   2.1. FASE 1 - DIAGNÓSTICO APROFUNDADO (2 semanas)
        - Mapeamento completo do fluxo de valor (VSM) de todas as linhas
        - Cronoanálise detalhada de cada posto de trabalho (100+ medições)
        - Identificação e quantificação de todas as perdas:
          * Setup (troca de ferramentas)
          * Microparadas (pequenas interrupções)
          * Refugo (peças defeituosas)
        - Cálculo do OEE real por linha e por posto
        - Análise financeira do impacto das perdas (R$/mês)
        - Relatório técnico completo (40+ páginas) com:
          * Diagnóstico detalhado
          * Oportunidades de melhoria
          * Priorização das ações

   2.2. FASE 2 - IMPLANTAÇÃO DAS MELHORIAS (4 semanas)
        - Implementação de SMED (Troca Rápida de Ferramentas) nos postos gargalo
        - Balanceamento de linha com redistribuição de tarefas
        - Padronização de procedimentos operacionais (POPs)
        - Criação de indicadores visuais de gestão
        - Treinamento da equipe (20 horas):
          * Conceitos de Manufatura Enxuta
          * Operação padrão
          * Identificação e eliminação de perdas
        - Documentação completa dos novos processos

   2.3. FASE 3 - ACOMPANHAMENTO E SUSTENTAÇÃO (${dados.mesesAcompanhamento || 3} meses)
        - Monitoramento semanal de indicadores (OEE, produtividade, qualidade)
        - Reuniões de acompanhamento (1h/semana) com a liderança
        - Ajustes finos nos processos
        - Transferência de conhecimento para a equipe interna
        - Relatórios mensais de evolução
        - Plano de sustentação para manter os resultados

3. INVESTIMENTO
   Valor total: R$ ${(dados.honorarios || 0).toFixed(2)}
   
   Condições de pagamento:
   • 50% na assinatura: R$ ${((dados.honorarios || 0) * 0.5).toFixed(2)}
   • 50% na entrega da Fase 2: R$ ${((dados.honorarios || 0) * 0.5).toFixed(2)}
   • Opção à vista: 5% de desconto (R$ ${((dados.honorarios || 0) * 0.95).toFixed(2)})

4. RETORNO SOBRE INVESTIMENTO
   Projeções baseadas na redução das perdas atuais:
   • Cenário conservador (10%): R$ ${((dados.perdasTotais || 0) * 0.1).toFixed(2)}/mês
   • Cenário moderado (20%): R$ ${((dados.perdasTotais || 0) * 0.2).toFixed(2)}/mês
   • Cenário otimista (30%): R$ ${((dados.perdasTotais || 0) * 0.3).toFixed(2)}/mês
   
   ROI projetado: ${dados.roiAnual}% ao ano
   Payback: ${dados.payback} meses

5. CONDIÇÕES COMERCIAIS
   • Validade da proposta: 15 dias
   • Início dos serviços: mediante assinatura do contrato e pagamento da entrada
   • Horário de trabalho: segunda a sexta, 8h às 18h
   • A Nexus fornece: metodologia, treinadores, materiais, relatórios
   • O cliente fornece: acesso às áreas, dados históricos, contato dedicado

Atenciosamente,

__________________________
Eng. ________________________________
Consultor Sênior - CREA/SP __________________________________
Nexus Engenharia Aplicada

═══════════════════════════════════════════════════════════════════
             M I N U T A   D O   C O N T R A T O                    
═══════════════════════════════════════════════════════════════════


CONTRATO DE PRESTAÇÃO DE SERVIÇOS DE CONSULTORIA EM ENGENHARIA

Pelo presente instrumento particular,

CONTRATANTE: ${dados.empresa}, pessoa jurídica de direito privado, inscrita no CNPJ sob o nº [CNPJ], com sede na [Endereço], neste ato representada por [Nome do Representante], [Cargo], portador do RG nº [RG] e CPF nº [CPF].

CONTRATADA: NEXUS ENGENHARIA APLICADA, pessoa jurídica de direito privado, inscrita no CNPJ sob o nº [CNPJ da Nexus], com sede na [Endereço da Nexus], neste ato representada por [Nome do Consultor], [Cargo], portador do RG nº [RG] e CPF nº [CPF].

As partes, acima identificadas, têm entre si justo e contratado o seguinte:

CLÁUSULA 1 - OBJETO
1.1. O presente contrato tem por objeto a prestação de serviços de consultoria em engenharia de produção, conforme escopo detalhado na Proposta Comercial Nº ___/2026, que passa a fazer parte integrante deste instrumento.
1.2. Os serviços compreendem as fases detalhadas no item 2 da Proposta Comercial (Diagnóstico Aprofundado, Implantação das Melhorias e Acompanhamento).
1.3. Qualquer serviço ou atividade não previsto expressamente neste contrato será considerado serviço extraordinário, podendo ser executado mediante novo orçamento e aprovação prévia da CONTRATANTE, com custos adicionais.

CLÁUSULA 2 - OBRIGAÇÕES DA CONTRATADA
2.1. Executar os serviços com diligência, empregando as melhores práticas e técnicas de engenharia disponíveis.
2.2. Fornecer equipe técnica qualificada e compatível com a natureza dos serviços.
2.3. Entregar os relatórios e documentações previstos no escopo, nos prazos estipulados.
2.4. Manter absoluto sigilo sobre todas as informações da CONTRATANTE a que tiver acesso.
2.5. A responsabilidade da CONTRATADA é de MEIO, não de resultado, não respondendo por resultados específicos que dependam de fatores alheios ao seu controle.

CLÁUSULA 3 - OBRIGAÇÕES DA CONTRATANTE
3.1. Fornecer acesso irrestrito às áreas produtivas, instalações e informações necessárias à execução dos serviços.
3.2. Indicar um responsável técnico como contato oficial durante a vigência do contrato.
3.3. Disponibilizar dados históricos de produção, manutenção e qualidade quando solicitados.
3.4. Efetuar os pagamentos nas datas e condições estipuladas.
3.5. Implementar as recomendações acordadas, quando for o caso, sendo de sua inteira responsabilidade os resultados decorrentes da não implementação.

CLÁUSULA 4 - PRAZO E VIGÊNCIA
4.1. O presente contrato vigorará pelo prazo de ${parseInt(dados.mesesAcompanhamento || 3) + 2} meses, contados da data de assinatura.
4.2. O prazo poderá ser prorrogado mediante aditivo contratual, por acordo entre as partes.
4.3. O início dos serviços está condicionado ao pagamento da entrada estipulada na Cláusula 5.

CLÁUSULA 5 - VALOR E CONDIÇÕES DE PAGAMENTO
5.1. O valor total dos serviços é de R$ ${(dados.honorarios || 0).toFixed(2)}.
5.2. Condições de pagamento:
    - 50% (R$ ${((dados.honorarios || 0) * 0.5).toFixed(2)}) na assinatura do contrato
    - 50% (R$ ${((dados.honorarios || 0) * 0.5).toFixed(2)}) na entrega da Fase 2
5.3. O pagamento deverá ser efetuado mediante depósito/transferência na conta:
    Banco: [Banco]
    Agência: [Agência]
    Conta: [Conta]
    Titular: NEXUS ENGENHARIA APLICADA
5.4. O atraso no pagamento sujeitará a CONTRATANTE a:
    - Multa de 2% (dois por cento) sobre o valor da parcela
    - Juros de mora de 1% (um por cento) ao mês, calculados pro rata die
    - Correção monetária pelos índices oficiais

CLÁUSULA 6 - PROPRIEDADE INTELECTUAL
6.1. Toda a metodologia, know-how, softwares, técnicas, ferramentas e materiais desenvolvidos e utilizados pela CONTRATADA são de sua propriedade exclusiva.
6.2. Os relatórios e documentos entregues à CONTRATANTE destinam-se ao seu uso exclusivo no âmbito do objeto contratado.
6.3. Fica expressamente proibida a utilização da metodologia Nexus pela CONTRATANTE após o término do contrato, salvo mediante nova contratação.

CLÁUSULA 7 - CONFIDENCIALIDADE
7.1. As partes obrigam-se a manter absoluto sigilo sobre todas as informações confidenciais a que tiverem acesso em razão deste contrato.
7.2. A obrigação de confidencialidade estende-se pelo prazo de 5 (cinco) anos após o término do contrato.
7.3. A violação desta cláusula sujeitará a parte infratora ao pagamento de multa de R$ 50.000,00 (cinquenta mil reais) por evento.

CLÁUSULA 8 - RESCISÃO
8.1. Qualquer das partes poderá rescindir o presente contrato nas seguintes hipóteses:
    a) Descumprimento de qualquer cláusula contratual, não sanado em 15 (quinze) dias após notificação;
    b) Por interesse exclusivo de qualquer das partes, mediante aviso prévio de 30 (trinta) dias;
    c) Por caso fortuito ou força maior que impeça a execução do objeto.
8.2. Em caso de rescisão unilateral sem justa causa pela CONTRATANTE, será devida multa de 20% (vinte por cento) sobre o saldo remanescente do contrato.
8.3. Em caso de rescisão por descumprimento da CONTRATADA, esta restituirá os valores recebidos, atualizados, e pagará multa de 20% (vinte por cento) sobre o valor total do contrato.

CLÁUSULA 9 - PENALIDADES
9.1. Pelo descumprimento de qualquer obrigação contratual não especificamente penalizada em outras cláusulas, será aplicada multa de 10% (dez por cento) sobre o valor total do contrato.
9.2. A multa prevista no item 9.1 poderá ser reduzida equitativamente pelo juiz nos termos do Art. 413 do Código Civil.

CLÁUSULA 10 - DISPOSIÇÕES GERAIS
10.1. Este contrato é celebrado em caráter intuitu personae, não podendo a CONTRATANTE ceder ou transferir seus direitos e obrigações sem prévia anuência da CONTRATADA.
10.2. As comunicações entre as partes serão consideradas válidas quando enviadas por e-mail para os endereços indicados.
10.3. A tolerância quanto ao descumprimento de qualquer cláusula não constituirá renúncia aos direitos previstos neste contrato.

CLÁUSULA 11 - FORO
11.1. Fica eleito o foro da cidade de [Cidade/Estado] para dirimir quaisquer questões decorrentes deste contrato.

E, por estarem assim justas e contratadas, as partes assinam o presente instrumento em 2 (duas) vias de igual teor e forma.

[Local], ${dados.data}.

__________________________
CONTRATANTE
${dados.empresa}
Nome: __________________________
Cargo: __________________________

__________________________
CONTRATADA
NEXUS ENGENHARIA APLICADA
Nome: __________________________
Cargo: __________________________

TESTEMUNHAS:

1. __________________________
Nome: __________________________
RG: __________________________
CPF: __________________________

2. __________________________
Nome: __________________________
RG: __________________________
CPF: __________________________
`;

    res.json({ proposta });

  } catch (error) {
    console.error("Erro na rota /api/ia/gerar-proposta-completa:", error);
    res.status(500).json({ erro: "Erro interno no servidor" });
  }
});

// ========================================
// 🤖 IA PARA SUGESTÕES DE MELHORIA (VERSÃO SEM IA - REGRAS DE NEGÓCIO)
// ========================================
app.get("/api/ia/sugestoes/:empresaId", autenticarToken, async (req, res) => {
  try {
    const { empresaId } = req.params;

    console.log("🔍 Buscando dados para empresa:", empresaId);

    // 1. Buscar dados da empresa com postos e perdas
    const linhas = await pool.query(
      `SELECT l.id, l.nome, l.takt_time_segundos, l.meta_diaria,
        (SELECT json_agg(json_build_object(
          'id', p.id,
          'nome', p.nome,
          'tempo_ciclo', p.tempo_ciclo_segundos,
          'setup', p.tempo_setup_minutos,
          'disponibilidade', p.disponibilidade_percentual,
          'ordem', p.ordem_fluxo,
          'cargo_id', p.cargo_id
        )) FROM posto_trabalho p WHERE p.linha_id = l.id) as postos,
        (SELECT json_agg(pl) FROM perdas_linha pl 
         JOIN linha_produto lp ON lp.id = pl.linha_produto_id 
         WHERE lp.linha_id = l.id) as perdas
       FROM linha_producao l
       WHERE l.empresa_id = $1`,
      [empresaId]
    );

    console.log("📊 Linhas encontradas:", linhas.rows.length);

    if (linhas.rows.length === 0) {
      return res.json({ 
        sugestoes: { 
          resumo: "Nenhuma linha encontrada para esta empresa.", 
          acoes: [],
          projecoes: {} 
        } 
      });
    }

    // 2. Calcular custos dos postos para ganhos reais
    const custosPorPosto = {};
    let custoMedioMinuto = 10;

    for (const linha of linhas.rows) {
      if (linha.postos) {
        for (const posto of linha.postos) {
          if (posto.cargo_id) {
            const cargoRes = await pool.query(
              "SELECT salario_base, encargos_percentual FROM cargo WHERE id = $1",
              [posto.cargo_id]
            );
            
            if (cargoRes.rows.length > 0) {
              const cargo = cargoRes.rows[0];
              const salario = parseFloat(cargo.salario_base) || 0;
              const encargos = parseFloat(cargo.encargos_percentual) || 70;
              const custoMensal = salario * (1 + encargos / 100);
              const custoPorMinuto = custoMensal / (22 * 8 * 60);
              custosPorPosto[posto.id] = custoPorMinuto;
              custoMedioMinuto = (custoMedioMinuto + custoPorMinuto) / 2;
            }
          }
        }
      }
    }

    // 3. Gerar sugestões baseadas em regras de negócio
    const sugestoes = [];
    let ganhoTotal = 0;

    for (const linha of linhas.rows) {
      if (!linha.postos || linha.postos.length === 0) continue;

      // Ordenar postos por ordem de fluxo
      const postosOrdenados = [...linha.postos].sort((a, b) => a.ordem - b.ordem);
      
      // Calcular tempos reais com disponibilidade
      const postosComCicloReal = postosOrdenados.map(p => ({
        ...p,
        cicloReal: (p.tempo_ciclo || 0) / ((p.disponibilidade || 100) / 100)
      }));

      // Encontrar gargalo (maior ciclo real)
      let maiorCiclo = 0;
      let postoGargalo = null;
      
      for (const posto of postosComCicloReal) {
        if (posto.cicloReal > maiorCiclo) {
          maiorCiclo = posto.cicloReal;
          postoGargalo = posto;
        }
      }

      if (!postoGargalo) continue;

      const custoPosto = custosPorPosto[postoGargalo.id] || custoMedioMinuto;

      // REGRA 1: Setup alto (> 15 minutos)
      if (postoGargalo.setup > 15) {
        const reducaoEstimada = Math.round(postoGargalo.setup * 0.4); // 40% de redução
        const minutosEconomizados = reducaoEstimada * 22; // por mês
        const ganho = Math.round(minutosEconomizados * custoPosto);
        ganhoTotal += ganho;
        
        sugestoes.push({
          titulo: `🔧 Aplicar SMED no posto ${postoGargalo.nome} (${linha.nome})`,
          descricao: `Setup atual de ${postoGargalo.setup} minutos. Com SMED, estima-se redução para ${postoGargalo.setup - reducaoEstimada} minutos. Ganho de ${minutosEconomizados} minutos/mês.`,
          prioridade: 'ALTA',
          ferramenta: 'SMED (Troca Rápida de Ferramentas)',
          ganho: `R$ ${ganho.toLocaleString()}/mês`,
          esforco: '2-3 dias',
          investimento: 'baixo'
        });
      }

      // REGRA 2: Disponibilidade baixa (< 85%)
      if (postoGargalo.disponibilidade < 85) {
        const ganho = Math.round(5000);
        ganhoTotal += ganho;
        
        sugestoes.push({
          titulo: `🧹 Implementar 5S + TPM no posto ${postoGargalo.nome}`,
          descricao: `Disponibilidade atual de ${postoGargalo.disponibilidade}%. Aplicar 5S para organização e TPM para manutenção autônoma.`,
          prioridade: 'MÉDIA',
          ferramenta: '5S + TPM (Manutenção Produtiva Total)',
          ganho: `R$ ${ganho.toLocaleString()}/mês`,
          esforco: '1 semana',
          investimento: 'baixo'
        });
      }

      // REGRA 3: Gargalo muito acima da média
      const mediaCiclo = postosComCicloReal.reduce((acc, p) => acc + p.cicloReal, 0) / postosComCicloReal.length;
      if (maiorCiclo > mediaCiclo * 1.3) { // 30% acima da média
        const ganho = Math.round(8000);
        ganhoTotal += ganho;
        
        sugestoes.push({
          titulo: `⚖️ Balancear linha ${linha.nome}`,
          descricao: `Gargalo no posto ${postoGargalo.nome} (${maiorCiclo.toFixed(1)}s) está ${((maiorCiclo/mediaCiclo - 1)*100).toFixed(0)}% acima da média. Redistribuir tarefas.`,
          prioridade: 'ALTA',
          ferramenta: 'Balanceamento de Linha',
          ganho: `R$ ${ganho.toLocaleString()}/mês`,
          esforco: '1 semana',
          investimento: 'baixo'
        });
      }

      // REGRA 4: Perdas por refugo (se houver)
      if (linha.perdas && linha.perdas.length > 0) {
        const totalRefugo = linha.perdas.reduce((acc, p) => acc + (p.refugo_pecas || 0), 0);
        if (totalRefugo > 10) { // mais de 10 peças/dia
          const ganho = Math.round(totalRefugo * 50 * 22); // R$ 50/peça
          ganhoTotal += ganho;
          
          sugestoes.push({
            titulo: `📉 Reduzir refugo na linha ${linha.nome}`,
            descricao: `Refugo atual de ${totalRefugo} peças/dia. Aplicar Ishikawa e CEP para identificar causas raiz.`,
            prioridade: 'MÉDIA',
            ferramenta: 'Ishikawa + CEP (Controle Estatístico)',
            ganho: `R$ ${ganho.toLocaleString()}/mês`,
            esforco: '2 semanas',
            investimento: 'baixo'
          });
        }
      }
    }

    // REGRA 5: Sugestão genérica se não houver nenhuma
    if (sugestoes.length === 0) {
      sugestoes.push({
        titulo: '📋 Realizar diagnóstico detalhado',
        descricao: 'Os dados atuais não indicam problemas críticos. Recomenda-se um diagnóstico aprofundado para identificar oportunidades.',
        prioridade: 'MÉDIA',
        ferramenta: 'Diagnóstico Lean',
        ganho: 'R$ 0 (investimento)',
        esforco: '2 semanas',
        investimento: 'médio'
      });
    }

    // Ordenar por prioridade (ALTA primeiro)
    sugestoes.sort((a, b) => {
      const prioridade = { 'ALTA': 1, 'MÉDIA': 2, 'BAIXA': 3 };
      return (prioridade[a.prioridade] || 99) - (prioridade[b.prioridade] || 99);
    });

    // Limitar a 5 sugestões
    const sugestoesLimitadas = sugestoes.slice(0, 5);

    res.json({ 
      sugestoes: {
        resumo: `🔍 Análise concluída. Identificamos ${sugestoesLimitadas.length} oportunidades de melhoria com ganho total estimado de R$ ${ganhoTotal.toLocaleString()}/mês.`,
        acoes: sugestoesLimitadas,
        projecoes: {
          novoOEE: '85%',
          ganhoMensal: `R$ ${ganhoTotal.toLocaleString()}`,
          tempoEstimado: '2-3 meses',
          investimentoTotal: 'baixo'
        }
      }
    });

  } catch (error) {
    console.error("Erro na rota /api/ia/sugestoes:", error);
    res.status(500).json({ 
      sugestoes: { 
        resumo: "Erro ao gerar sugestões", 
        acoes: [
          {
            titulo: "🔧 Aplicar SMED nos postos com setup alto",
            descricao: "Identificar e reduzir setup nos postos gargalo",
            prioridade: "ALTA",
            ferramenta: "SMED",
            ganho: "R$ 2.500/mês",
            esforco: "2-3 dias",
            investimento: "baixo"
          }
        ],
        projecoes: {
          novoOEE: "85%",
          ganhoMensal: "R$ 2.500",
          tempoEstimado: "2 meses",
          investimentoTotal: "baixo"
        }
      }
    });
  }
});

// ========================================
// 📋 ROTAS DO CHECKLIST
// ========================================

// Criar novo projeto
app.post("/api/checklist/projeto", autenticarToken, async (req, res) => {
  try {
    const { empresa_id, nome, data_inicio, data_previsao } = req.body;

    const result = await pool.query(
      `INSERT INTO projetos_checklist (empresa_id, nome, data_inicio, data_previsao)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [empresa_id, nome, data_inicio, data_previsao]
    );

    // Criar fases padrão
    const projetoId = result.rows[0].id;
    const fases = [
      { nome: 'Fase 1 - Diagnóstico', ordem: 1 },
      { nome: 'Fase 2 - Implantação', ordem: 2 },
      { nome: 'Fase 3 - Acompanhamento', ordem: 3 }
    ];

    for (const fase of fases) {
      await pool.query(
        `INSERT INTO fases_checklist (projeto_id, nome, ordem)
         VALUES ($1, $2, $3)`,
        [projetoId, fase.nome, fase.ordem]
      );
    }

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao criar projeto:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// Listar projetos de uma empresa
app.get("/api/checklist/projetos/:empresaId", autenticarToken, async (req, res) => {
  try {
    const { empresaId } = req.params;

    const result = await pool.query(
      `SELECT * FROM projetos_checklist 
       WHERE empresa_id = $1 
       ORDER BY created_at DESC`,
      [empresaId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar projetos:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// Buscar projeto completo com fases e itens
app.get("/api/checklist/projeto/:projetoId", autenticarToken, async (req, res) => {
  try {
    const { projetoId } = req.params;

    // Buscar projeto
    const projeto = await pool.query(
      `SELECT p.*, e.nome as empresa_nome 
       FROM projetos_checklist p
       JOIN empresa e ON e.id = p.empresa_id
       WHERE p.id = $1`,
      [projetoId]
    );

    if (projeto.rows.length === 0) {
      return res.status(404).json({ erro: "Projeto não encontrado" });
    }

    // Buscar fases com itens
    const fases = await pool.query(
      `SELECT f.*, 
        (SELECT json_agg(i ORDER BY i.ordem) FROM itens_checklist i WHERE i.fase_id = f.id) as itens
       FROM fases_checklist f
       WHERE f.projeto_id = $1
       ORDER BY f.ordem`,
      [projetoId]
    );

    res.json({
      projeto: projeto.rows[0],
      fases: fases.rows
    });
  } catch (error) {
    console.error("Erro ao buscar projeto:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// Adicionar item ao checklist
app.post("/api/checklist/item", autenticarToken, async (req, res) => {
  try {
    const { fase_id, descricao, ordem } = req.body;

    const result = await pool.query(
      `INSERT INTO itens_checklist (fase_id, descricao, ordem)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [fase_id, descricao, ordem]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao criar item:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// Atualizar item (concluir, editar)
app.put("/api/checklist/item/:itemId", autenticarToken, async (req, res) => {
  try {
    const { itemId } = req.params;
    const { concluido, observacoes } = req.body;

    const result = await pool.query(
      `UPDATE itens_checklist 
       SET concluido = COALESCE($1, concluido),
           observacoes = COALESCE($2, observacoes),
           data_conclusao = CASE WHEN $1 = true THEN CURRENT_TIMESTAMP ELSE data_conclusao END
       WHERE id = $3
       RETURNING *`,
      [concluido, observacoes, itemId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Item não encontrado" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao atualizar item:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// Atualizar fase
app.put("/api/checklist/fase/:faseId", autenticarToken, async (req, res) => {
  try {
    const { faseId } = req.params;
    const { data_inicio, data_previsao, data_conclusao, status, progresso } = req.body;

    const result = await pool.query(
      `UPDATE fases_checklist 
       SET data_inicio = COALESCE($1, data_inicio),
           data_previsao = COALESCE($2, data_previsao),
           data_conclusao = COALESCE($3, data_conclusao),
           status = COALESCE($4, status),
           progresso = COALESCE($5, progresso)
       WHERE id = $6
       RETURNING *`,
      [data_inicio, data_previsao, data_conclusao, status, progresso, faseId]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao atualizar fase:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 🧪 ROTA TEMPORÁRIA - CRIAR PROJETO DE TESTE
// ========================================
app.get("/checklist/criar-teste", async (req, res) => {
  try {
    // 1. Buscar empresa (prioridade para "Empresa Teste")
    let empresa = await pool.query(
      `SELECT id, nome FROM empresas 
       WHERE nome ILIKE '%teste%' 
       LIMIT 1`
    );
    
    // Se não encontrar, pega a primeira empresa
    if (empresa.rows.length === 0) {
      empresa = await pool.query("SELECT id, nome FROM empresas LIMIT 1");
    }

    // Se ainda não tiver empresa, erro
    if (empresa.rows.length === 0) {
      return res.status(400).json({ 
        erro: "Nenhuma empresa encontrada. Cadastre uma empresa primeiro." 
      });
    }

    const empresaId = empresa.rows[0].id;
    const empresaNome = empresa.rows[0].nome;

    // 2. Verificar se já existe projeto para não duplicar
    const projetoExistente = await pool.query(
      `SELECT id FROM projetos_checklist 
       WHERE empresa_id = $1 AND nome = 'Projeto Teste'`,
      [empresaId]
    );

    if (projetoExistente.rows.length > 0) {
      return res.json({ 
        mensagem: `✅ Projeto já existe para ${empresaNome}!`,
        projetoId: projetoExistente.rows[0].id,
        empresa: empresaNome,
        status: "existente"
      });
    }

    // 3. Criar o projeto
    const projeto = await pool.query(
      `INSERT INTO projetos_checklist 
       (empresa_id, nome, data_inicio, data_previsao, status)
       VALUES ($1, 'Projeto Teste', CURRENT_DATE, CURRENT_DATE + INTERVAL '3 months', 'em_andamento')
       RETURNING id`,
      [empresaId]
    );

    const projetoId = projeto.rows[0].id;

    // 4. Criar as 3 fases
    const fases = [
      { nome: 'Fase 1 - Diagnóstico', ordem: 1 },
      { nome: 'Fase 2 - Implantação', ordem: 2 },
      { nome: 'Fase 3 - Acompanhamento', ordem: 3 }
    ];

    for (const fase of fases) {
      const faseRes = await pool.query(
        `INSERT INTO fases_checklist (projeto_id, nome, ordem, status)
         VALUES ($1, $2, $3, 'pendente') 
         RETURNING id`,
        [projetoId, fase.nome, fase.ordem]
      );

      const faseId = faseRes.rows[0].id;

      // 5. Criar itens específicos para cada fase
      if (fase.ordem === 1) {
        // Fase 1 - Diagnóstico
        await pool.query(
          `INSERT INTO itens_checklist (fase_id, descricao, ordem) VALUES
           ($1, 'Mapear fluxo de valor (VSM) - identificar desperdícios', 1),
           ($1, 'Coletar tempos de ciclo de todos os postos (cronoanálise)', 2),
           ($1, 'Identificar gargalos por linha', 3),
           ($1, 'Calcular OEE atual por linha', 4),
           ($1, 'Quantificar perdas (setup, microparadas, refugo)', 5),
           ($1, 'Elaborar relatório de diagnóstico com oportunidades', 6)`,
          [faseId]
        );
      } else if (fase.ordem === 2) {
        // Fase 2 - Implantação
        await pool.query(
          `INSERT INTO itens_checklist (fase_id, descricao, ordem) VALUES
           ($1, 'Aplicar SMED nos postos gargalo (reduzir setup)', 1),
           ($1, 'Realizar 5S nos postos críticos', 2),
           ($1, 'Balancear linha de produção', 3),
           ($1, 'Criar procedimentos operacionais padrão (POP)', 4),
           ($1, 'Treinar operadores (20 horas)', 5),
           ($1, 'Implementar quadro de indicadores visuais', 6)`,
          [faseId]
        );
      } else {
        // Fase 3 - Acompanhamento
        await pool.query(
          `INSERT INTO itens_checklist (fase_id, descricao, ordem) VALUES
           ($1, 'Monitorar OEE semanalmente', 1),
           ($1, 'Realizar reuniões de acompanhamento (1h/semana)', 2),
           ($1, 'Gerar relatórios mensais de evolução', 3),
           ($1, 'Ajustar processos conforme necessário', 4),
           ($1, 'Documentar lições aprendidas', 5),
           ($1, 'Elaborar plano de sustentação', 6)`,
          [faseId]
        );
      }
    }

    // 6. Marcar alguns itens como concluídos para teste
    const fase1 = await pool.query(
      "SELECT id FROM fases_checklist WHERE projeto_id = $1 AND ordem = 1",
      [projetoId]
    );

    if (fase1.rows.length > 0) {
      const fase1Id = fase1.rows[0].id;
      
      // Concluir primeiros itens da fase 1
      await pool.query(
        `UPDATE itens_checklist 
         SET concluido = true, 
             data_conclusao = CURRENT_TIMESTAMP 
         WHERE fase_id = $1 AND ordem <= 2`, // Conclui os 2 primeiros itens
        [fase1Id]
      );

      // Atualizar progresso da fase 1
      const totalItens = await pool.query(
        "SELECT COUNT(*) as total FROM itens_checklist WHERE fase_id = $1",
        [fase1Id]
      );
      
      const itensConcluidos = await pool.query(
        "SELECT COUNT(*) as concluidos FROM itens_checklist WHERE fase_id = $1 AND concluido = true",
        [fase1Id]
      );

      const progresso = Math.round((itensConcluidos.rows[0].concluidos / totalItens.rows[0].total) * 100);

      await pool.query(
        `UPDATE fases_checklist 
         SET data_inicio = CURRENT_DATE,
             data_previsao = CURRENT_DATE + INTERVAL '2 weeks',
             status = 'em_andamento',
             progresso = $1
         WHERE id = $2`,
        [progresso, fase1Id]
      );
    }

    // 7. Retornar sucesso
    res.json({ 
      mensagem: `✅ Projeto de teste criado com sucesso para ${empresaNome}!`,
      projetoId,
      empresa: empresaNome,
      detalhes: {
        fases: 3,
        itens: 18,
        empresaId
      },
      proximoPasso: "Acesse o menu 'Checklist' no sistema e selecione esta empresa."
    });

  } catch (error) {
    console.error("❌ Erro ao criar projeto de teste:", error);
    res.status(500).json({ 
      erro: "Erro ao criar projeto: " + error.message 
    });
  }
});

// ========================================
// ✏️ ATUALIZAR EMPRESA
// ========================================
app.put("/empresas/:id", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      nome,
      cnpj,
      segmento,
      regime_tributario,
      turnos,
      dias_produtivos_mes,
      meta_mensal
    } = req.body;

    const result = await pool.query(
      `UPDATE empresa SET
        nome = COALESCE($1, nome),
        cnpj = COALESCE($2, cnpj),
        segmento = COALESCE($3, segmento),
        regime_tributario = COALESCE($4, regime_tributario),
        turnos = COALESCE($5, turnos),
        dias_produtivos_mes = COALESCE($6, dias_produtivos_mes),
        meta_mensal = COALESCE($7, meta_mensal)
      WHERE id = $8
      RETURNING *`,
      [nome, cnpj, segmento, regime_tributario, turnos, dias_produtivos_mes, meta_mensal, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Empresa não encontrada" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao atualizar empresa:", error);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

// ========================================
// 🗑️ EXCLUIR EMPRESA (CORRIGIDO)
// ========================================
app.delete("/empresas/:id", autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // ✅ Alterado para 'empresas' (plural)
    const result = await pool.query(
      "DELETE FROM empresas WHERE id = $1 RETURNING *", 
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Empresa não encontrada" });
    }

    res.json({ mensagem: "Empresa excluída com sucesso" });
  } catch (error) {
    console.error("Erro ao excluir empresa:", error);

    // Tratamento para restrição de chave estrangeira (FK)
    if (error.code === '23503') {
      return res.status(400).json({ 
        erro: "Não é possível excluir a empresa: existem funcionários, linhas ou outros registros vinculados a ela." 
      });
    }

    res.status(500).json({ erro: "Erro interno no servidor ao excluir empresa" });
  }
});

// ========================================
// 🚀 INICIAR SERVIDOR
// ========================================
app.listen(PORT, () => {
  console.log(`Servidor Hórus rodando na porta ${PORT}`);
});