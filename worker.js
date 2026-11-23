const PRODUTO_OFICIAL = "Placa Profissional 4 em 1 PRO";
const PRECO_OFICIAL_CENTAVOS = 990; // R$ 9,90 exatos
const PRECO_OFICIAL = 9.9;
const MOEDA_OFICIAL = "BRL";
const RATE_LIMIT_MAX_REQS = 8; // Máximo de criações de preferência por IP a cada janela
const RATE_LIMIT_WINDOW_SEC = 300; // Janela de 5 minutos

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // -------------------------------------------------------------------------
    // 1. ROTA: CRIAR PAGAMENTO (Checkout Pro + Registro Persistente em KV)
    // -------------------------------------------------------------------------
    if (url.pathname === "/api/criar-pagamento" && request.method === "POST") {
      if (!env.MP_ACCESS_TOKEN) {
        return jsonResponse({ error: "Serviço de pagamento indisponível no momento." }, 500);
      }

      if (!env.ORDERS_KV) {
        return jsonResponse({ error: "Armazenamento de pedidos não configurado." }, 500);
      }

      // Proteção básica contra requisições abusivas por IP
      const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      const rateAllowed = await checkRateLimit(env.ORDERS_KV, clientIp);
      if (!rateAllowed) {
        return jsonResponse(
          { error: "Muitas tentativas em sequência. Aguarde alguns minutos e tente novamente." },
          429
        );
      }

      try {
        // Ignora qualquer valor, moeda ou referência enviada pelo navegador
        const origem = url.origin;
        const externalReference = `sublibox_${crypto.randomUUID()}`;
        const createdAt = new Date().toISOString();

        const preferenciaPayload = {
          items: [
            {
              id: "placa-4em1-pro-6x4",
              title: PRODUTO_OFICIAL,
              quantity: 1,
              currency_id: MOEDA_OFICIAL,
              unit_price: PRECO_OFICIAL
            }
          ],
          back_urls: {
            success: `${origem}/?retorno=mp`,
            failure: `${origem}/?retorno=mp`,
            pending: `${origem}/?retorno=mp`
          },
          auto_return: "approved",
          external_reference: externalReference,
          metadata: {
            order_ref: externalReference,
            expected_amount_cents: PRECO_OFICIAL_CENTAVOS
          },
          notification_url: `${origem}/api/webhook`
        };

        const mpRes = await fetch("https://api.mercadopago.com/checkout/preferences", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${env.MP_ACCESS_TOKEN}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify(preferenciaPayload)
        });

        const mpData = await mpRes.json();

        if (!mpRes.ok || !mpData.id || !mpData.init_point) {
          return jsonResponse({ error: "Não foi possível iniciar o pagamento no Mercado Pago." }, 502);
        }

        // Registra o pedido no Cloudflare KV ANTES de devolver o link ao cliente
        const orderRecord = {
          external_reference: externalReference,
          preference_id: String(mpData.id),
          amount: PRECO_OFICIAL,
          amount_cents: PRECO_OFICIAL_CENTAVOS,
          currency_id: MOEDA_OFICIAL,
          product: PRODUTO_OFICIAL,
          status: "pending",
          payment_id: null,
          created_at: createdAt,
          updated_at: createdAt
        };

        // TTL de 30 dias (2592000 segundos)
        await env.ORDERS_KV.put(`order:${externalReference}`, JSON.stringify(orderRecord), {
          expirationTtl: 2592000
        });

        return jsonResponse({
          id: mpData.id,
          init_point: mpData.init_point,
          sandbox_init_point: mpData.sandbox_init_point
        });
      } catch (err) {
        return jsonResponse({ error: "Erro interno ao preparar o checkout." }, 500);
      }
    }

    // -------------------------------------------------------------------------
    // 2. ROTA: VERIFICAR PAGAMENTO (Validação Rigorosa no Servidor)
    // -------------------------------------------------------------------------
    if (url.pathname === "/api/verificar-pagamento" && request.method === "GET") {
      if (!env.MP_ACCESS_TOKEN || !env.ORDERS_KV) {
        return jsonResponse({ aprovado: false, error: "Serviço de verificação indisponível." }, 500);
      }

      const rawId = url.searchParams.get("payment_id") || url.searchParams.get("collection_id") || "";
      const paymentId = rawId.replace(/\D/g, "");
      const clientPreferenceId = (url.searchParams.get("preference_id") || "").trim();

      if (!paymentId || paymentId.length < 5 || paymentId.length > 25) {
        return jsonResponse({ aprovado: false, error: "ID do pagamento inválido." }, 400);
      }

      try {
        const validation = await validateAndSyncPayment(env, paymentId, clientPreferenceId);

        if (!validation.aprovado) {
          return jsonResponse(
            {
              aprovado: false,
              status: validation.status || "rejected",
              error: validation.error || "Pagamento não validado para este pedido."
            },
            validation.httpStatus || 200
          );
        }

        return jsonResponse({
          aprovado: true,
          status: "approved",
          payment_id: validation.payment_id
        });
      } catch (err) {
        return jsonResponse({ aprovado: false, error: "Falha ao validar pagamento no servidor." }, 500);
      }
    }

    // -------------------------------------------------------------------------
    // 3. ROTA: WEBHOOK OFICIAL MERCADO PAGO (Assinatura HMAC + Idempotência)
    // -------------------------------------------------------------------------
    if (url.pathname === "/api/webhook") {
      if (request.method === "GET") {
        return jsonResponse({ ok: true }, 200);
      }

      if (request.method === "POST") {
        if (!env.MP_ACCESS_TOKEN || !env.MP_WEBHOOK_SECRET || !env.ORDERS_KV) {
          return jsonResponse({ error: "Webhook não configurado." }, 500);
        }

        const rawBody = await request.text();
        let body = {};
        try {
          body = rawBody ? JSON.parse(rawBody) : {};
        } catch (e) {
          return jsonResponse({ error: "Payload inválido." }, 400);
        }

        // Extrai o ID do recurso da query string (data.id / id) ou do corpo
        const dataId =
          url.searchParams.get("data.id") ||
          url.searchParams.get("id") ||
          (body.data && body.data.id ? String(body.data.id) : "") ||
          (body.id ? String(body.id) : "");

        const xSignature = request.headers.get("x-signature") || "";
        const xRequestId = request.headers.get("x-request-id") || "";

        // Valida assinatura criptográfica HMAC-SHA256 conforme documentação oficial MP
        const isSignatureValid = await verifyMercadoPagoSignature({
          xSignature,
          xRequestId,
          dataId,
          secret: env.MP_WEBHOOK_SECRET
        });

        if (!isSignatureValid) {
          return jsonResponse({ error: "Assinatura inválida." }, 401);
        }

        const topic = body.type || body.topic || url.searchParams.get("topic") || "";
        const cleanPaymentId = String(dataId || "").replace(/\D/g, "");

        // Processa apenas eventos de pagamento
        if (topic !== "payment" || !cleanPaymentId) {
          return jsonResponse({ received: true, ignored: true }, 200);
        }

        // Idempotência: evita reprocessamento duplicado do mesmo evento/pagamento
        const webhookEventKey = `wh_evt:${cleanPaymentId}:${xRequestId || "no_req_id"}`;
        const alreadyProcessed = await env.ORDERS_KV.get(webhookEventKey);
        if (alreadyProcessed) {
          return jsonResponse({ received: true, duplicate: true }, 200);
        }

        try {
          const result = await validateAndSyncPayment(env, cleanPaymentId, "");

          // Marca evento como processado por 7 dias para evitar duplicidade
          await env.ORDERS_KV.put(
            webhookEventKey,
            JSON.stringify({
              processed_at: new Date().toISOString(),
              aprovado: result.aprovado,
              status: result.status || "unknown"
            }),
            { expirationTtl: 604800 }
          );

          return jsonResponse({ received: true, processed: true }, 200);
        } catch (err) {
          return jsonResponse({ error: "Erro ao processar notificação." }, 500);
        }
      }
    }

    // Servir arquivos estáticos (index.html, robots.txt, sitemap.xml, etc.)
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("Não encontrado", { status: 404 });
  }
};

// =============================================================================
// FUNÇÃO CENTRAL DE VALIDAÇÃO RIGOROSA DO PAGAMENTO E CRUZAMENTO COM O PEDIDO
// =============================================================================
async function validateAndSyncPayment(env, paymentId, clientPreferenceId = "") {
  const mpRes = await fetch(`https://api.mercadopago.com/v1/payments/${encodeURIComponent(paymentId)}`, {
    headers: {
      Authorization: `Bearer ${env.MP_ACCESS_TOKEN}`
    }
  });

  if (!mpRes.ok) {
    return {
      aprovado: false,
      httpStatus: mpRes.status === 404 ? 404 : 502,
      error: "Pagamento não encontrado no Mercado Pago."
    };
  }

  const mpData = await mpRes.json();

  // 1. Status deve ser exatamente "approved"
  if (mpData.status !== "approved") {
    return {
      aprovado: false,
      status: mpData.status,
      error: "Pagamento ainda não está aprovado."
    };
  }

  // 2. Valor deve ser EXATAMENTE R$ 9,90 (990 centavos) - rejeita R$ 5,00 ou R$ 10,00
  const amountCents = Math.round(Number(mpData.transaction_amount) * 100);
  if (!Number.isFinite(amountCents) || amountCents !== PRECO_OFICIAL_CENTAVOS) {
    return {
      aprovado: false,
      status: mpData.status,
      error: "O valor do pagamento não corresponde ao valor oficial da placa (R$ 9,90)."
    };
  }

  // 3. Moeda deve ser exatamente "BRL"
  if (mpData.currency_id !== MOEDA_OFICIAL) {
    return {
      aprovado: false,
      status: mpData.status,
      error: "Moeda do pagamento inválida."
    };
  }

  // 4. external_reference deve existir e corresponder a um pedido real criado pelo SubliBox QR
  const externalRef = String(mpData.external_reference || "").trim();
  if (!externalRef || !externalRef.startsWith("sublibox_")) {
    return {
      aprovado: false,
      status: mpData.status,
      error: "Pagamento não pertence a um pedido gerado pelo SubliBox QR."
    };
  }

  const storedOrderRaw = await env.ORDERS_KV.get(`order:${externalRef}`);
  if (!storedOrderRaw) {
    return {
      aprovado: false,
      status: mpData.status,
      error: "Pedido não localizado nos registros do servidor."
    };
  }

  let storedOrder;
  try {
    storedOrder = JSON.parse(storedOrderRaw);
  } catch (e) {
    return {
      aprovado: false,
      error: "Registro de pedido corrompido."
    };
  }

  // Confere integridade dos dados gravados no pedido
  if (
    storedOrder.external_reference !== externalRef ||
    storedOrder.amount_cents !== PRECO_OFICIAL_CENTAVOS ||
    storedOrder.currency_id !== MOEDA_OFICIAL ||
    !storedOrder.preference_id
  ) {
    return {
      aprovado: false,
      error: "Divergência nos dados internos do pedido."
    };
  }

  // 5. Validação da preference_id registrada
  // Verifica a preferência enviada no metadata/objeto do MP e, se enviada na URL, exige igualdade
  const mpPrefId = String(
    mpData.preference_id || (mpData.metadata && mpData.metadata.preference_id) || ""
  ).trim();

  if (mpPrefId && mpPrefId !== storedOrder.preference_id) {
    return {
      aprovado: false,
      error: "Preferência de pagamento divergente da registrada."
    };
  }

  if (clientPreferenceId && clientPreferenceId !== storedOrder.preference_id) {
    return {
      aprovado: false,
      error: "Preferência informada não corresponde ao pedido."
    };
  }

  // Impede que um pedido já vinculado a outro payment_id seja reutilizado indevidamente
  if (storedOrder.payment_id && String(storedOrder.payment_id) !== String(mpData.id)) {
    return {
      aprovado: false,
      error: "Este pedido já está vinculado a outra transação."
    };
  }

  // Atualiza o pedido no KV se ainda não estava marcado como aprovado
  if (storedOrder.status !== "approved" || !storedOrder.payment_id) {
    storedOrder.status = "approved";
    storedOrder.payment_id = String(mpData.id);
    storedOrder.updated_at = new Date().toISOString();

    await env.ORDERS_KV.put(`order:${externalRef}`, JSON.stringify(storedOrder), {
      expirationTtl: 2592000
    });
  }

  return {
    aprovado: true,
    status: "approved",
    payment_id: String(mpData.id),
    external_reference: externalRef
  };
}

// =============================================================================
// VALIDAÇÃO DA ASSINATURA HMAC-SHA256 DO WEBHOOK DO MERCADO PAGO
// =============================================================================
async function verifyMercadoPagoSignature({ xSignature, xRequestId, dataId, secret }) {
  if (!xSignature || !xRequestId || !dataId || !secret) {
    return false;
  }

  // Formato esperado de x-signature: "ts=1704908010,v1=618c85345248dd820d5fd456117c2ab2ef8eda45a0282ff693eac24131a5e839"
  const parts = xSignature.split(",");
  let ts = "";
  let v1 = "";

  for (const part of parts) {
    const [rawKey, ...rest] = part.trim().split("=");
    const val = rest.join("=").trim();
    if (rawKey === "ts") ts = val;
    if (rawKey === "v1") v1 = val;
  }

  if (!ts || !v1) {
    return false;
  }

  // Proteção contra replay antigo (tolerância de 15 minutos)
  const tsNum = Number(ts);
  if (Number.isFinite(tsNum)) {
    const nowSec = Math.floor(Date.now() / 1000);
    const tsSec = tsNum > 1e12 ? Math.floor(tsNum / 1000) : tsNum;
    if (Math.abs(nowSec - tsSec) > 900) {
      return false;
    }
  }

  // Template oficial do Mercado Pago (data.id em minúsculas se alfanumérico)
  const normalizedDataId = String(dataId).toLowerCase();
  const manifest = `id:${normalizedDataId};request-id:${xRequestId};ts:${ts};`;

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signatureBuffer = await crypto.subtle.sign("HMAC", key, encoder.encode(manifest));
  const computedHex = Array.from(new Uint8Array(signatureBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return timingSafeEqual(computedHex, v1.toLowerCase());
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// =============================================================================
// RATE LIMIT SIMPLES POR IP NO KV PARA EVITAR SPAM DE PREFERÊNCIAS
// =============================================================================
async function checkRateLimit(kv, ip) {
  try {
    const key = `rl:create:${ip}`;
    const currentRaw = await kv.get(key);
    const count = currentRaw ? Number(currentRaw) : 0;
    if (count >= RATE_LIMIT_MAX_REQS) {
      return false;
    }
    await kv.put(key, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW_SEC });
    return true;
  } catch (e) {
    return true; // Não bloqueia venda legítima em caso de falha pontual de leitura
  }
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8"
    }
  });
}
