const PRODUTO_OFICIAL = "Placa de Balcão 4 em 1 PRO (10x15cm)";
const PRODUTOS_ACEITOS = new Set([
  "Placa de Balcão 4 em 1 PRO (10x15cm)",
  "Placa Profissional 4 em 1 PRO"
]);
const ITEM_ID_OFICIAL = "placa-4em1-pro-10x15";
const QUANTIDADE_OFICIAL = 1;
const PRECO_OFICIAL_CENTAVOS = 990; // R$ 9,90 exatos
const PRECO_OFICIAL = 9.9;
const MOEDA_OFICIAL = "BRL";
const RATE_LIMIT_MAX_REQS = 8; // Máx. 8 criações de checkout por IP a cada 5 min
const RATE_LIMIT_WINDOW_SEC = 300;
const MAX_CREATE_BODY_BYTES = 2048;

const PAYMENT_ID_REGEX = /^\d{5,25}$/;
const PREFERENCE_ID_REGEX = /^[a-zA-Z0-9_-]{8,100}$/;
const QUERY_DATA_ID_REGEX = /^[a-zA-Z0-9_-]{1,64}$/;

const memoryRateMap = new Map();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // -------------------------------------------------------------------------
    // 1. ROTA: CRIAR PAGAMENTO (Checkout Pro + Registro Persistente em D1)
    // -------------------------------------------------------------------------
    if (url.pathname === "/api/criar-pagamento") {
      if (request.method !== "POST") {
        return jsonResponse({ error: "Método não permitido." }, 405, { Allow: "POST" });
      }

      if (!env.MP_ACCESS_TOKEN || !env.ORDERS_DB) {
        return jsonResponse({ error: "Serviço de pagamento indisponível no momento." }, 500);
      }

      const contentType = (request.headers.get("Content-Type") || "").toLowerCase();
      if (!contentType.includes("application/json")) {
        return jsonResponse({ error: "Formato de requisição inválido." }, 415);
      }

      const contentLength = Number(request.headers.get("Content-Length") || 0);
      if (contentLength > MAX_CREATE_BODY_BYTES) {
        return jsonResponse({ error: "Payload excede o limite permitido." }, 413);
      }

      const rawReqText = await request.text();
      if (rawReqText.length > MAX_CREATE_BODY_BYTES) {
        return jsonResponse({ error: "Payload excede o limite permitido." }, 413);
      }

      try {
        if (rawReqText) JSON.parse(rawReqText);
      } catch (e) {
        return jsonResponse({ error: "JSON inválido." }, 400);
      }

      const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      const rateStatus = await checkRateLimitD1(env.ORDERS_DB, clientIp);
      if (!rateStatus.allowed) {
        return jsonResponse(
          { error: "Muitas tentativas em sequência. Aguarde alguns minutos e tente novamente." },
          429,
          { "Retry-After": String(rateStatus.retryAfterSec || RATE_LIMIT_WINDOW_SEC) }
        );
      }

      try {
        const origem = url.origin;
        const externalReference = `sublibox_${crypto.randomUUID()}`;
        const orderNonce = crypto.randomUUID();
        const createdAt = new Date().toISOString();

        const preferenciaPayload = {
          items: [
            {
              id: ITEM_ID_OFICIAL,
              title: PRODUTO_OFICIAL,
              quantity: QUANTIDADE_OFICIAL,
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
            order_nonce: orderNonce,
            expected_amount_cents: PRECO_OFICIAL_CENTAVOS,
            format: "10x15cm"
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

        const preferenceId = String(mpData.id).trim();
        if (!PREFERENCE_ID_REGEX.test(preferenceId)) {
          return jsonResponse({ error: "Identificador de preferência inválido recebido." }, 502);
        }

        await env.ORDERS_DB.prepare(
          `INSERT INTO orders (
            external_reference, order_nonce, preference_id, product, quantity,
            amount_cents, currency_id, status, payment_id, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', NULL, ?, ?)`
        )
          .bind(
            externalReference,
            orderNonce,
            preferenceId,
            PRODUTO_OFICIAL,
            QUANTIDADE_OFICIAL,
            PRECO_OFICIAL_CENTAVOS,
            MOEDA_OFICIAL,
            createdAt,
            createdAt
          )
          .run();

        return jsonResponse({
          id: preferenceId,
          init_point: mpData.init_point,
          sandbox_init_point: mpData.sandbox_init_point
        });
      } catch (err) {
        return jsonResponse({ error: "Erro interno ao preparar o checkout." }, 500);
      }
    }

    // -------------------------------------------------------------------------
    // 2. ROTA: VERIFICAR PAGAMENTO (Validação Estrita + D1 Atômico)
    // -------------------------------------------------------------------------
    if (url.pathname === "/api/verificar-pagamento") {
      if (request.method !== "GET") {
        return jsonResponse({ aprovado: false, error: "Método não permitido." }, 405, { Allow: "GET" });
      }

      if (!env.MP_ACCESS_TOKEN || !env.ORDERS_DB) {
        return jsonResponse({ aprovado: false, error: "Serviço de verificação indisponível." }, 500);
      }

      const rawPaymentId = (
        url.searchParams.get("payment_id") ||
        url.searchParams.get("collection_id") ||
        ""
      ).trim();

      if (!PAYMENT_ID_REGEX.test(rawPaymentId)) {
        return jsonResponse({ aprovado: false, error: "Formato de ID do pagamento inválido." }, 400);
      }

      const rawClientPrefId = (url.searchParams.get("preference_id") || "").trim();
      if (rawClientPrefId && !PREFERENCE_ID_REGEX.test(rawClientPrefId)) {
        return jsonResponse({ aprovado: false, error: "Formato de preferência inválido." }, 400);
      }

      try {
        const validation = await validateAndSyncPayment(env, rawPaymentId, rawClientPrefId);

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
        return jsonResponse(
          { aprovado: false, error: "Falha temporária ao validar pagamento no servidor." },
          503
        );
      }
    }

    // -------------------------------------------------------------------------
    // 3. ROTA: WEBHOOK OFICIAL MERCADO PAGO (data.id na Query String + HMAC)
    // -------------------------------------------------------------------------
    if (url.pathname === "/api/webhook") {
      if (request.method === "GET") {
        return jsonResponse({ ok: true }, 200);
      }

      if (request.method !== "POST") {
        return jsonResponse({ error: "Método não permitido." }, 405, { Allow: "GET, POST" });
      }

      if (!env.MP_ACCESS_TOKEN || !env.MP_WEBHOOK_SECRET || !env.ORDERS_DB) {
        return jsonResponse({ error: "Webhook não configurado." }, 500);
      }

      const rawBody = await request.text();
      let body = {};
      try {
        body = rawBody ? JSON.parse(rawBody) : {};
      } catch (e) {
        return jsonResponse({ error: "Payload inválido." }, 400);
      }

      const queryDataId = (
        url.searchParams.get("data.id") ||
        url.searchParams.get("id") ||
        ""
      ).trim();

      if (!QUERY_DATA_ID_REGEX.test(queryDataId)) {
        return jsonResponse({ error: "Parâmetro data.id ausente ou inválido na URL." }, 401);
      }

      const xSignature = request.headers.get("x-signature") || "";
      const xRequestId = request.headers.get("x-request-id") || "";

      const isSignatureValid = await verifyMercadoPagoSignature({
        xSignature,
        xRequestId,
        queryDataId,
        secret: env.MP_WEBHOOK_SECRET
      });

      if (!isSignatureValid) {
        return jsonResponse({ error: "Assinatura inválida." }, 401);
      }

      const topic = String(body.type || body.topic || url.searchParams.get("topic") || "").toLowerCase();
      if (topic !== "payment") {
        return jsonResponse({ received: true, ignored: true }, 200);
      }

      if (!PAYMENT_ID_REGEX.test(queryDataId)) {
        return jsonResponse({ error: "Identificador de pagamento inválido." }, 400);
      }

      const webhookEventKey = `wh:${queryDataId}:${xRequestId || "no_req_id"}`;
      const existingEvent = await env.ORDERS_DB.prepare(
        "SELECT event_key FROM webhook_events WHERE event_key = ?"
      )
        .bind(webhookEventKey)
        .first();

      if (existingEvent) {
        return jsonResponse({ received: true, duplicate: true }, 200);
      }

      try {
        const result = await validateAndSyncPayment(env, queryDataId, "");

        if (result.transientError) {
          return jsonResponse({ error: "Falha temporária ao consultar pagamento." }, 503);
        }

        await env.ORDERS_DB.prepare(
          `INSERT OR IGNORE INTO webhook_events (event_key, payment_id, status, processed_at)
           VALUES (?, ?, ?, ?)`
        )
          .bind(webhookEventKey, queryDataId, result.status || "rejected", new Date().toISOString())
          .run();

        return jsonResponse({ received: true, processed: true }, 200);
      } catch (err) {
        return jsonResponse({ error: "Erro temporário ao processar notificação." }, 503);
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
// VALIDAÇÃO RIGOROSA DO PAGAMENTO + CONSULTA OBRIGATÓRIA À PREFERÊNCIA + D1
// =============================================================================
async function validateAndSyncPayment(env, paymentId, clientPreferenceId = "") {
  const paymentFetch = await fetchMercadoPagoJson(
    `https://api.mercadopago.com/v1/payments/${encodeURIComponent(paymentId)}`,
    env.MP_ACCESS_TOKEN
  );

  if (paymentFetch.transientError) {
    return {
      aprovado: false,
      transientError: true,
      httpStatus: 503,
      error: "Falha temporária de comunicação com o Mercado Pago."
    };
  }

  if (!paymentFetch.ok) {
    return {
      aprovado: false,
      httpStatus: paymentFetch.status === 404 ? 404 : 400,
      error: "Pagamento não encontrado no Mercado Pago."
    };
  }

  const mpData = paymentFetch.data;

  if (mpData.status !== "approved") {
    return {
      aprovado: false,
      status: mpData.status,
      error: "Pagamento ainda não está aprovado."
    };
  }

  const amountCents = Math.round(Number(mpData.transaction_amount) * 100);
  if (!Number.isFinite(amountCents) || amountCents !== PRECO_OFICIAL_CENTAVOS) {
    return {
      aprovado: false,
      status: mpData.status,
      error: "O valor do pagamento não corresponde ao valor oficial da placa (R$ 9,90)."
    };
  }

  if (mpData.currency_id !== MOEDA_OFICIAL) {
    return {
      aprovado: false,
      status: mpData.status,
      error: "Moeda do pagamento inválida."
    };
  }

  const externalRef = String(mpData.external_reference || "").trim();
  if (!externalRef || !externalRef.startsWith("sublibox_")) {
    return {
      aprovado: false,
      status: mpData.status,
      error: "Pagamento não pertence a um pedido gerado pelo SubliBox QR."
    };
  }

  const storedOrder = await env.ORDERS_DB.prepare(
    `SELECT external_reference, order_nonce, preference_id, product, quantity,
            amount_cents, currency_id, status, payment_id
     FROM orders WHERE external_reference = ?`
  )
    .bind(externalRef)
    .first();

  if (!storedOrder) {
    return {
      aprovado: false,
      status: mpData.status,
      error: "Pedido não localizado nos registros do servidor."
    };
  }

  if (
    storedOrder.amount_cents !== PRECO_OFICIAL_CENTAVOS ||
    storedOrder.currency_id !== MOEDA_OFICIAL ||
    !PRODUTOS_ACEITOS.has(String(storedOrder.product || "").trim()) ||
    storedOrder.quantity !== QUANTIDADE_OFICIAL ||
    !storedOrder.preference_id
  ) {
    return {
      aprovado: false,
      error: "Divergência nos dados internos do pedido."
    };
  }

  if (clientPreferenceId && clientPreferenceId !== storedOrder.preference_id) {
    return {
      aprovado: false,
      error: "Preferência informada não corresponde ao pedido."
    };
  }

  if (mpData.metadata && mpData.metadata.order_nonce !== undefined && mpData.metadata.order_nonce !== null) {
    if (String(mpData.metadata.order_nonce).trim() !== storedOrder.order_nonce) {
      return {
        aprovado: false,
        error: "Metadados do pagamento divergem do pedido registrado."
      };
    }
  }

  const prefFetch = await fetchMercadoPagoJson(
    `https://api.mercadopago.com/checkout/preferences/${encodeURIComponent(storedOrder.preference_id)}`,
    env.MP_ACCESS_TOKEN
  );

  if (prefFetch.transientError) {
    return {
      aprovado: false,
      transientError: true,
      httpStatus: 503,
      error: "Falha temporária ao confirmar a preferência no Mercado Pago."
    };
  }

  if (!prefFetch.ok) {
    return {
      aprovado: false,
      error: "Preferência registrada não encontrada no Mercado Pago."
    };
  }

  const prefData = prefFetch.data;
  const firstItem = Array.isArray(prefData.items) && prefData.items.length > 0 ? prefData.items[0] : null;
  const prefAmountCents = firstItem ? Math.round(Number(firstItem.unit_price) * 100) : NaN;

  const isPreferenceValid =
    String(prefData.id || "").trim() === storedOrder.preference_id &&
    String(prefData.external_reference || "").trim() === storedOrder.external_reference &&
    firstItem &&
    PRODUTOS_ACEITOS.has(String(firstItem.title || "").trim()) &&
    Number(firstItem.quantity) === QUANTIDADE_OFICIAL &&
    prefAmountCents === PRECO_OFICIAL_CENTAVOS &&
    String(firstItem.currency_id || "").trim() === MOEDA_OFICIAL;

  if (!isPreferenceValid) {
    return {
      aprovado: false,
      error: "Os dados da preferência no Mercado Pago não conferem com o pedido."
    };
  }

  if (prefData.metadata && prefData.metadata.order_nonce) {
    if (String(prefData.metadata.order_nonce).trim() !== storedOrder.order_nonce) {
      return {
        aprovado: false,
        error: "Identificador interno da preferência inválido."
      };
    }
  }

  let linkedPreferenceId = String(mpData.preference_id || "").trim();
  let merchantOrderLinked = false;

  if (!linkedPreferenceId && mpData.order && mpData.order.id) {
    const moFetch = await fetchMercadoPagoJson(
      `https://api.mercadopago.com/merchant_orders/${encodeURIComponent(String(mpData.order.id))}`,
      env.MP_ACCESS_TOKEN
    );

    if (moFetch.transientError) {
      return {
        aprovado: false,
        transientError: true,
        httpStatus: 503,
        error: "Falha temporária ao consultar ordem de pagamento."
      };
    }

    if (moFetch.ok && moFetch.data) {
      linkedPreferenceId = String(moFetch.data.preference_id || "").trim();
      const moPayments = Array.isArray(moFetch.data.payments) ? moFetch.data.payments : [];
      const hasPaymentInOrder = moPayments.some((p) => String(p.id) === String(mpData.id));
      const sameExternalRef = String(moFetch.data.external_reference || "").trim() === externalRef;
      merchantOrderLinked = hasPaymentInOrder && sameExternalRef;
    }
  } else if (linkedPreferenceId) {
    merchantOrderLinked = true;
  }

  if (!linkedPreferenceId || linkedPreferenceId !== storedOrder.preference_id || !merchantOrderLinked) {
    return {
      aprovado: false,
      error: "Não foi possível comprovar a vinculação deste pagamento com a preferência do pedido."
    };
  }

  const normalizedPaymentId = String(mpData.id);
  const nowIso = new Date().toISOString();

  if (storedOrder.status === "approved" && storedOrder.payment_id === normalizedPaymentId) {
    return {
      aprovado: true,
      status: "approved",
      payment_id: normalizedPaymentId
    };
  }

  if (storedOrder.payment_id && storedOrder.payment_id !== normalizedPaymentId) {
    return {
      aprovado: false,
      error: "Este pedido já foi pago por outra transação."
    };
  }

  try {
    const updateResult = await env.ORDERS_DB.prepare(
      `UPDATE orders
       SET status = 'approved', payment_id = ?, updated_at = ?
       WHERE external_reference = ?
         AND preference_id = ?
         AND status = 'pending'
         AND payment_id IS NULL`
    )
      .bind(normalizedPaymentId, nowIso, externalRef, storedOrder.preference_id)
      .run();

    const changedRows = updateResult && updateResult.meta ? Number(updateResult.meta.changes || 0) : 0;

    if (changedRows === 1) {
      return {
        aprovado: true,
        status: "approved",
        payment_id: normalizedPaymentId
      };
    }

    const latestOrder = await env.ORDERS_DB.prepare(
      "SELECT status, payment_id FROM orders WHERE external_reference = ?"
    )
      .bind(externalRef)
      .first();

    if (latestOrder && latestOrder.status === "approved" && latestOrder.payment_id === normalizedPaymentId) {
      return {
        aprovado: true,
        status: "approved",
        payment_id: normalizedPaymentId
      };
    }

    return {
      aprovado: false,
      error: "Conflito de pagamento detectado para este pedido."
    };
  } catch (dbErr) {
    return {
      aprovado: false,
      error: "Esta transação já está vinculada a outro pedido."
    };
  }
}

async function fetchMercadoPagoJson(endpointUrl, accessToken) {
  try {
    const res = await fetch(endpointUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    if (res.status >= 500 || res.status === 429) {
      return { ok: false, transientError: true, status: res.status };
    }

    const data = await res.json().catch(() => null);
    if (!res.ok || !data) {
      return { ok: false, transientError: false, status: res.status };
    }

    return { ok: true, transientError: false, status: res.status, data };
  } catch (err) {
    return { ok: false, transientError: true, status: 503 };
  }
}

async function verifyMercadoPagoSignature({ xSignature, xRequestId, queryDataId, secret }) {
  if (!xSignature || !xRequestId || !queryDataId || !secret) {
    return false;
  }

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

  const normalizedDataId = String(queryDataId).toLowerCase();
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

async function checkRateLimitD1(db, ip) {
  const nowSec = Math.floor(Date.now() / 1000);
  const windowBucket = Math.floor(nowSec / RATE_LIMIT_WINDOW_SEC);
  const bucketKey = `create:${ip}:${windowBucket}`;
  const expiresAt = (windowBucket + 1) * RATE_LIMIT_WINDOW_SEC;

  try {
    await db
      .prepare(
        `INSERT INTO rate_limits (bucket_key, request_count, expires_at)
         VALUES (?, 1, ?)
         ON CONFLICT(bucket_key) DO UPDATE SET request_count = request_count + 1`
      )
      .bind(bucketKey, expiresAt)
      .run();

    const row = await db
      .prepare("SELECT request_count FROM rate_limits WHERE bucket_key = ?")
      .bind(bucketKey)
      .first();

    const count = row ? Number(row.request_count) : 1;
    if (count > RATE_LIMIT_MAX_REQS) {
      return {
        allowed: false,
        retryAfterSec: Math.max(1, expiresAt - nowSec)
      };
    }

    return { allowed: true };
  } catch (e) {
    const memEntry = memoryRateMap.get(bucketKey) || { count: 0, expiresAt };
    if (nowSec > memEntry.expiresAt) {
      memEntry.count = 0;
      memEntry.expiresAt = expiresAt;
    }
    if (memEntry.count >= RATE_LIMIT_MAX_REQS) {
      return { allowed: false, retryAfterSec: Math.max(1, memEntry.expiresAt - nowSec) };
    }
    memEntry.count += 1;
    memoryRateMap.set(bucketKey, memEntry);
    return { allowed: true };
  }
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders
    }
  });
}
