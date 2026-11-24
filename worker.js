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

const RATE_LIMIT_CREATE_MAX = 8; // Máx. 8 criações de checkout por IP a cada 5 min
const RATE_LIMIT_VERIFY_MAX = 30; // Máx. 30 verificações por IP a cada 5 min
const RATE_LIMIT_WINDOW_SEC = 300;
const MEMORY_RATE_MAX_KEYS = 2000;
const MAX_CREATE_BODY_BYTES = 2048;

const PAYMENT_ID_REGEX = /^\d{5,25}$/;
const PREFERENCE_ID_REGEX = /^[a-zA-Z0-9_-]{8,100}$/;
const QUERY_DATA_ID_REGEX = /^[a-zA-Z0-9_-]{1,64}$/;
const SESSION_TOKEN_REGEX = /^[a-f0-9]{64}$/;
const CUSTOMIZATION_HASH_REGEX = /^[a-f0-9]{64}$/;
const ORDER_REF_REGEX = /^sublibox_[0-9a-f-]{36}$/i;

// Fallback em memória apenas por isolate (não substitui proteção distribuída D1/WAF)
const memoryRateMap = new Map();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // -------------------------------------------------------------------------
    // 1. ROTA: CRIAR PAGAMENTO (Checkout Pro + Credencial de Sessão + D1)
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

      let reqBody = {};
      try {
        reqBody = rawReqText ? JSON.parse(rawReqText) : {};
      } catch (e) {
        return jsonResponse({ error: "JSON inválido." }, 400);
      }

      const customizationHash = String(reqBody.customization_hash || "").trim().toLowerCase();
      if (!CUSTOMIZATION_HASH_REGEX.test(customizationHash)) {
        return jsonResponse({ error: "Assinatura da personalização ausente ou inválida." }, 400);
      }

      const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      const rateStatus = await checkRateLimitD1(
        env.ORDERS_DB,
        `create:${clientIp}`,
        RATE_LIMIT_CREATE_MAX,
        ctx
      );
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
        const buyerSessionToken = await generateSecureTokenHex(32);
        const buyerSessionTokenHash = await sha256Hex(buyerSessionToken);
        const createdAt = new Date().toISOString();

        const backUrl = `${origem}/?retorno=mp&order_ref=${encodeURIComponent(externalReference)}`;

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
            success: backUrl,
            failure: backUrl,
            pending: backUrl
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

        const mpData = await mpRes.json().catch(() => null);

        if (!mpRes.ok || !mpData || !mpData.id || !mpData.init_point) {
          return jsonResponse({ error: "Não foi possível iniciar o pagamento no Mercado Pago." }, 502);
        }

        const preferenceId = String(mpData.id).trim();
        if (!PREFERENCE_ID_REGEX.test(preferenceId)) {
          return jsonResponse({ error: "Identificador de preferência inválido recebido." }, 502);
        }

        await env.ORDERS_DB.prepare(
          `INSERT INTO orders (
            external_reference, order_nonce, preference_id, product, quantity,
            amount_cents, currency_id, status, payment_id,
            buyer_session_hash, customization_hash, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', NULL, ?, ?, ?, ?)`
        )
          .bind(
            externalReference,
            orderNonce,
            preferenceId,
            PRODUTO_OFICIAL,
            QUANTIDADE_OFICIAL,
            PRECO_OFICIAL_CENTAVOS,
            MOEDA_OFICIAL,
            buyerSessionTokenHash,
            customizationHash,
            createdAt,
            createdAt
          )
          .run();

        const cookieHeader = buildSessionCookie(buyerSessionToken, url.protocol === "https:");

        return jsonResponse(
          {
            id: preferenceId,
            order_ref: externalReference,
            session_token: buyerSessionToken,
            init_point: mpData.init_point,
            sandbox_init_point: mpData.sandbox_init_point
          },
          200,
          { "Set-Cookie": cookieHeader }
        );
      } catch (err) {
        const dbKind = classifyD1Error(err);
        if (dbKind === "transient" || dbKind === "unavailable") {
          return jsonResponse({ error: "Banco de dados temporariamente indisponível. Tente novamente." }, 503);
        }
        return jsonResponse({ error: "Erro interno ao preparar o checkout." }, 500);
      }
    }

    // -------------------------------------------------------------------------
    // 2. ROTA: VERIFICAR PAGAMENTO (Sessão Vinculada + Hash da Placa + D1)
    // -------------------------------------------------------------------------
    if (url.pathname === "/api/verificar-pagamento") {
      if (request.method !== "POST") {
        return jsonResponse({ aprovado: false, error: "Método não permitido." }, 405, { Allow: "POST" });
      }

      if (!env.MP_ACCESS_TOKEN || !env.ORDERS_DB) {
        return jsonResponse({ aprovado: false, error: "Serviço de verificação indisponível." }, 500);
      }

      const contentType = (request.headers.get("Content-Type") || "").toLowerCase();
      if (!contentType.includes("application/json")) {
        return jsonResponse({ aprovado: false, error: "Formato de requisição inválido." }, 415);
      }

      const rawBody = await request.text();
      if (rawBody.length > MAX_CREATE_BODY_BYTES) {
        return jsonResponse({ aprovado: false, error: "Payload excede o limite permitido." }, 413);
      }

      let reqBody = {};
      try {
        reqBody = rawBody ? JSON.parse(rawBody) : {};
      } catch (e) {
        return jsonResponse({ aprovado: false, error: "JSON inválido." }, 400);
      }

      const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      const rateStatus = await checkRateLimitD1(
        env.ORDERS_DB,
        `verify:${clientIp}`,
        RATE_LIMIT_VERIFY_MAX,
        ctx
      );
      if (!rateStatus.allowed) {
        return jsonResponse(
          { aprovado: false, error: "Muitas consultas em sequência. Aguarde um instante e tente novamente." },
          429,
          { "Retry-After": String(rateStatus.retryAfterSec || RATE_LIMIT_WINDOW_SEC) }
        );
      }

      const rawPaymentId = String(reqBody.payment_id || reqBody.collection_id || "").trim();
      const rawOrderRef = String(reqBody.order_ref || "").trim();
      const rawClientPrefId = String(reqBody.preference_id || "").trim();
      const customizationHash = String(reqBody.customization_hash || "").trim().toLowerCase();

      if (!rawPaymentId && !rawOrderRef) {
        return jsonResponse({ aprovado: false, error: "Informe o identificador do pagamento ou pedido." }, 400);
      }

      if (rawPaymentId && !PAYMENT_ID_REGEX.test(rawPaymentId)) {
        return jsonResponse({ aprovado: false, error: "Formato de ID do pagamento inválido." }, 400);
      }

      if (rawOrderRef && !ORDER_REF_REGEX.test(rawOrderRef)) {
        return jsonResponse({ aprovado: false, error: "Referência de pedido inválida." }, 400);
      }

      if (rawClientPrefId && !PREFERENCE_ID_REGEX.test(rawClientPrefId)) {
        return jsonResponse({ aprovado: false, error: "Formato de preferência inválido." }, 400);
      }

      if (!CUSTOMIZATION_HASH_REGEX.test(customizationHash)) {
        return jsonResponse({ aprovado: false, error: "Dados da placa inválidos para verificação." }, 400);
      }

      const cookieToken = getCookieValue(request.headers.get("Cookie") || "", "sublibox_order_session");
      const headerToken = String(request.headers.get("X-Order-Session") || reqBody.session_token || "").trim();
      const candidateTokens = [cookieToken, headerToken].filter((t) => SESSION_TOKEN_REGEX.test(t));

      if (candidateTokens.length === 0) {
        return jsonResponse(
          {
            aprovado: false,
            error: "Sessão do pedido não identificada nesta aba. Use o mesmo navegador em que iniciou a compra."
          },
          401
        );
      }

      try {
        const validation = await validateAndSyncPayment(env, {
          paymentId: rawPaymentId,
          orderRef: rawOrderRef,
          clientPreferenceId: rawClientPrefId,
          candidateSessionTokens: candidateTokens,
          customizationHash
        });

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

        const downloadGrant = await signDownloadGrant(
          env,
          validation.order_ref,
          validation.payment_id,
          customizationHash
        );

        return jsonResponse({
          aprovado: true,
          status: "approved",
          payment_id: validation.payment_id,
          order_ref: validation.order_ref,
          download_grant: downloadGrant
        });
      } catch (err) {
        return jsonResponse(
          { aprovado: false, error: "Falha temporária ao validar pagamento no servidor." },
          503
        );
      }
    }

    // -------------------------------------------------------------------------
    // 3. ROTA: AUTORIZAR EXPORTAÇÃO FINAL (Validação Server-Side por Download)
    // -------------------------------------------------------------------------
    if (url.pathname === "/api/autorizar-download") {
      if (request.method !== "POST") {
        return jsonResponse({ authorized: false, error: "Método não permitido." }, 405, { Allow: "POST" });
      }

      if (!env.ORDERS_DB) {
        return jsonResponse({ authorized: false, error: "Serviço indisponível." }, 500);
      }

      const contentType = (request.headers.get("Content-Type") || "").toLowerCase();
      if (!contentType.includes("application/json")) {
        return jsonResponse({ authorized: false, error: "Formato de requisição inválido." }, 415);
      }

      const rawBody = await request.text();
      if (rawBody.length > MAX_CREATE_BODY_BYTES) {
        return jsonResponse({ authorized: false, error: "Payload excede o limite permitido." }, 413);
      }

      let reqBody = {};
      try {
        reqBody = rawBody ? JSON.parse(rawBody) : {};
      } catch (e) {
        return jsonResponse({ authorized: false, error: "JSON inválido." }, 400);
      }

      const orderRef = String(reqBody.order_ref || "").trim();
      const paymentId = String(reqBody.payment_id || "").trim();
      const customizationHash = String(reqBody.customization_hash || "").trim().toLowerCase();
      const downloadGrant = String(reqBody.download_grant || "").trim();

      const cookieToken = getCookieValue(request.headers.get("Cookie") || "", "sublibox_order_session");
      const headerToken = String(request.headers.get("X-Order-Session") || reqBody.session_token || "").trim();
      const candidateTokens = [cookieToken, headerToken].filter((t) => SESSION_TOKEN_REGEX.test(t));

      if (
        !ORDER_REF_REGEX.test(orderRef) ||
        !PAYMENT_ID_REGEX.test(paymentId) ||
        !CUSTOMIZATION_HASH_REGEX.test(customizationHash) ||
        candidateTokens.length === 0
      ) {
        return jsonResponse({ authorized: false, error: "Credenciais de exportação inválidas." }, 401);
      }

      try {
        const order = await env.ORDERS_DB.prepare(
          `SELECT external_reference, status, payment_id, buyer_session_hash, customization_hash,
                  amount_cents, currency_id, product, quantity
           FROM orders WHERE external_reference = ?`
        )
          .bind(orderRef)
          .first();

        if (!order || order.status !== "approved" || order.payment_id !== paymentId) {
          return jsonResponse({ authorized: false, error: "Pedido não aprovado." }, 403);
        }

        if (
          order.amount_cents !== PRECO_OFICIAL_CENTAVOS ||
          order.currency_id !== MOEDA_OFICIAL ||
          !PRODUTOS_ACEITOS.has(String(order.product || "").trim()) ||
          order.quantity !== QUANTIDADE_OFICIAL
        ) {
          return jsonResponse({ authorized: false, error: "Dados do pedido inválidos." }, 403);
        }

        const isSessionValid = await verifyAnySessionToken(candidateTokens, order.buyer_session_hash);
        if (!isSessionValid) {
          return jsonResponse({ authorized: false, error: "Sessão não autorizada para este pedido." }, 403);
        }

        if (order.customization_hash !== customizationHash) {
          return jsonResponse(
            {
              authorized: false,
              error: "Os dados da placa foram alterados após o pagamento. Cada compra libera apenas a arte original paga."
            },
            403
          );
        }

        const isGrantValid = await verifyDownloadGrant(
          env,
          downloadGrant,
          orderRef,
          paymentId,
          customizationHash
        );
        if (!isGrantValid) {
          return jsonResponse({ authorized: false, error: "Token de autorização expirado ou inválido." }, 403);
        }

        const refreshedGrant = await signDownloadGrant(env, orderRef, paymentId, customizationHash);
        return jsonResponse({
          authorized: true,
          download_grant: refreshedGrant
        });
      } catch (err) {
        const dbKind = classifyD1Error(err);
        if (dbKind === "transient" || dbKind === "unavailable") {
          return jsonResponse({ authorized: false, error: "Falha temporária no servidor. Tente novamente." }, 503);
        }
        return jsonResponse({ authorized: false, error: "Não foi possível autorizar o download." }, 500);
      }
    }

    // -------------------------------------------------------------------------
    // 4. ROTA: WEBHOOK OFICIAL MERCADO PAGO (Idempotência por Status + HMAC)
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

      try {
        const result = await validateAndSyncPayment(env, {
          paymentId: queryDataId,
          orderRef: "",
          clientPreferenceId: "",
          candidateSessionTokens: [],
          customizationHash: "",
          isWebhook: true
        });

        if (result.transientError) {
          return jsonResponse({ error: "Falha temporária ao consultar pagamento." }, 503);
        }

        const effectiveStatus = String(result.status || "rejected").toLowerCase();
        const isFinalStatus =
          effectiveStatus === "approved" || effectiveStatus === "rejected" || effectiveStatus === "cancelled";

        // Só grava idempotência definitiva se o status for terminal (approved/rejected/cancelled).
        // Pagamentos pendentes (pending / in_process) retornam 200 sem travar futuras notificações de aprovação.
        if (isFinalStatus) {
          const webhookEventKey = `wh:${queryDataId}:${effectiveStatus}`;
          await env.ORDERS_DB.prepare(
            `INSERT OR IGNORE INTO webhook_events (event_key, payment_id, status, processed_at)
             VALUES (?, ?, ?, ?)`
          )
            .bind(webhookEventKey, queryDataId, effectiveStatus, new Date().toISOString())
            .run();
        }

        return jsonResponse(
          {
            received: true,
            processed: isFinalStatus,
            status: effectiveStatus
          },
          200
        );
      } catch (err) {
        const dbKind = classifyD1Error(err);
        if (dbKind === "transient" || dbKind === "unavailable") {
          return jsonResponse({ error: "Banco de dados temporariamente indisponível." }, 503);
        }
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
// VALIDAÇÃO RIGOROSA DO PAGAMENTO + SESSÃO + HASH DA PLACA + PREFERÊNCIA + D1
// =============================================================================
async function validateAndSyncPayment(env, opts) {
  const {
    paymentId = "",
    orderRef = "",
    clientPreferenceId = "",
    candidateSessionTokens = [],
    customizationHash = "",
    isWebhook = false
  } = opts;

  let resolvedPaymentId = paymentId;

  // Se o comprador voltou do checkout apenas com order_ref e sem payment_id na URL,
  // verifica primeiro se o webhook já registrou o payment_id aprovado no D1.
  if (!resolvedPaymentId && orderRef) {
    let preOrder = null;
    try {
      preOrder = await env.ORDERS_DB.prepare(
        "SELECT payment_id, status FROM orders WHERE external_reference = ?"
      )
        .bind(orderRef)
        .first();
    } catch (dbErr) {
      return {
        aprovado: false,
        transientError: true,
        httpStatus: 503,
        error: "Falha temporária ao consultar pedido no banco de dados."
      };
    }

    if (!preOrder) {
      return {
        aprovado: false,
        httpStatus: 404,
        error: "Pedido não encontrado."
      };
    }

    if (!preOrder.payment_id) {
      // Fallback seguro: busca pagamentos associados à external_reference no Mercado Pago
      const searchFetch = await fetchMercadoPagoJson(
        `https://api.mercadopago.com/v1/payments/search?external_reference=${encodeURIComponent(orderRef)}&sort=date_created&criteria=desc`,
        env.MP_ACCESS_TOKEN
      );

      if (searchFetch.transientError) {
        return {
          aprovado: false,
          transientError: true,
          httpStatus: 503,
          error: "Falha temporária de comunicação com o Mercado Pago."
        };
      }

      if (searchFetch.ok && searchFetch.data && Array.isArray(searchFetch.data.results)) {
        const approvedCandidate = searchFetch.data.results.find((p) => p && p.status === "approved");
        const firstCandidate = approvedCandidate || searchFetch.data.results[0];
        if (firstCandidate && firstCandidate.id) {
          resolvedPaymentId = String(firstCandidate.id).trim();
        }
      }

      if (!resolvedPaymentId) {
        return {
          aprovado: false,
          status: preOrder.status || "pending",
          error: "Pagamento ainda não confirmado pelo Mercado Pago. Aguarde alguns segundos e clique novamente."
        };
      }
    } else {
      resolvedPaymentId = String(preOrder.payment_id).trim();
    }
  }

  const paymentFetch = await fetchMercadoPagoJson(
    `https://api.mercadopago.com/v1/payments/${encodeURIComponent(resolvedPaymentId)}`,
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
  const mpStatus = String(mpData.status || "").trim().toLowerCase();

  if (mpStatus !== "approved") {
    return {
      aprovado: false,
      status: mpStatus || "pending",
      error:
        mpStatus === "pending" || mpStatus === "in_process"
          ? "Pagamento pendente de compensação no Mercado Pago."
          : "Pagamento não aprovado."
    };
  }

  const amountCents = Math.round(Number(mpData.transaction_amount) * 100);
  if (!Number.isFinite(amountCents) || amountCents !== PRECO_OFICIAL_CENTAVOS) {
    return {
      aprovado: false,
      status: mpStatus,
      error: "O valor do pagamento não corresponde ao valor oficial da placa (R$ 9,90)."
    };
  }

  if (mpData.currency_id !== MOEDA_OFICIAL) {
    return {
      aprovado: false,
      status: mpStatus,
      error: "Moeda do pagamento inválida."
    };
  }

  const externalRef = String(mpData.external_reference || "").trim();
  if (!externalRef || !ORDER_REF_REGEX.test(externalRef)) {
    return {
      aprovado: false,
      status: mpStatus,
      error: "Pagamento não pertence a um pedido gerado pelo SubliBox QR."
    };
  }

  if (orderRef && orderRef !== externalRef) {
    return {
      aprovado: false,
      status: mpStatus,
      error: "O pagamento informado não pertence a este pedido."
    };
  }

  let storedOrder = null;
  try {
    storedOrder = await env.ORDERS_DB.prepare(
      `SELECT external_reference, order_nonce, preference_id, product, quantity,
              amount_cents, currency_id, status, payment_id,
              buyer_session_hash, customization_hash
       FROM orders WHERE external_reference = ?`
    )
      .bind(externalRef)
      .first();
  } catch (dbErr) {
    return {
      aprovado: false,
      transientError: true,
      httpStatus: 503,
      error: "Banco de dados temporariamente indisponível."
    };
  }

  if (!storedOrder) {
    return {
      aprovado: false,
      status: mpStatus,
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

  // Exige vinculação criptográfica da sessão e da personalização nas chamadas do comprador
  if (!isWebhook) {
    const isSessionValid = await verifyAnySessionToken(
      candidateSessionTokens,
      storedOrder.buyer_session_hash
    );
    if (!isSessionValid) {
      return {
        aprovado: false,
        httpStatus: 403,
        error: "Este pagamento pertence a outra sessão de compra e não pode ser reutilizado aqui."
      };
    }

    if (storedOrder.customization_hash && storedOrder.customization_hash !== customizationHash) {
      return {
        aprovado: false,
        httpStatus: 403,
        error: "Os dados da placa atual são diferentes da placa vinculada a este pagamento."
      };
    }
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
      payment_id: normalizedPaymentId,
      order_ref: externalRef
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
        payment_id: normalizedPaymentId,
        order_ref: externalRef
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
        payment_id: normalizedPaymentId,
        order_ref: externalRef
      };
    }

    return {
      aprovado: false,
      error: "Conflito de pagamento detectado para este pedido."
    };
  } catch (dbErr) {
    const dbKind = classifyD1Error(dbErr);

    if (dbKind === "unique_constraint") {
      // Verifica se o próprio pedido atual já foi atualizado concorrentemente pelo webhook com o mesmo payment_id
      try {
        const concurrentOrder = await env.ORDERS_DB.prepare(
          "SELECT status, payment_id FROM orders WHERE external_reference = ?"
        )
          .bind(externalRef)
          .first();

        if (
          concurrentOrder &&
          concurrentOrder.status === "approved" &&
          concurrentOrder.payment_id === normalizedPaymentId
        ) {
          return {
            aprovado: true,
            status: "approved",
            payment_id: normalizedPaymentId,
            order_ref: externalRef
          };
        }
      } catch (e) {}

      return {
        aprovado: false,
        httpStatus: 409,
        error: "Esta transação já está vinculada a outro pedido."
      };
    }

    if (dbKind === "transient" || dbKind === "unavailable") {
      return {
        aprovado: false,
        transientError: true,
        httpStatus: 503,
        error: "Falha temporária no banco de dados. Tente novamente em instantes."
      };
    }

    return {
      aprovado: false,
      httpStatus: 500,
      error: "Erro interno ao registrar confirmação do pedido."
    };
  }
}

// =============================================================================
// CLASSIFICAÇÃO DE ERROS DO CLOUDFLARE D1
// =============================================================================
function classifyD1Error(err) {
  const msg = String(err && err.message ? err.message : err || "").toLowerCase();

  if (
    msg.includes("unique constraint failed") ||
    msg.includes("sqlite_constraint_unique") ||
    msg.includes("sqlite_constraint_primarykey")
  ) {
    return "unique_constraint";
  }

  if (msg.includes("sqlite_constraint")) {
    return "integrity_conflict";
  }

  if (
    msg.includes("sqlite_busy") ||
    msg.includes("sqlite_locked") ||
    msg.includes("database is locked") ||
    msg.includes("timeout") ||
    msg.includes("timed out") ||
    msg.includes("network") ||
    msg.includes("connection") ||
    msg.includes("overloaded")
  ) {
    return "transient";
  }

  if (
    msg.includes("no such table") ||
    msg.includes("unavailable") ||
    msg.includes("d1_error")
  ) {
    return "unavailable";
  }

  return "unexpected";
}

// =============================================================================
// CRIPTOGRAFIA DE SESSÃO E GRANT DE DOWNLOAD
// =============================================================================
async function generateSecureTokenHex(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(String(text));
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function verifyAnySessionToken(candidateTokens, expectedHash) {
  if (!expectedHash || !Array.isArray(candidateTokens) || candidateTokens.length === 0) {
    return false;
  }
  for (const token of candidateTokens) {
    const hashed = await sha256Hex(token);
    if (timingSafeEqual(hashed, String(expectedHash))) {
      return true;
    }
  }
  return false;
}

function getSigningSecret(env) {
  return String(env.DOWNLOAD_SIGNING_SECRET || env.MP_WEBHOOK_SECRET || env.MP_ACCESS_TOKEN || "");
}

async function signDownloadGrant(env, orderRef, paymentId, customizationHash) {
  const secret = getSigningSecret(env);
  const exp = Math.floor(Date.now() / 1000) + 3600; // Válido por 1 hora (renovável pelo servidor)
  const payload = `${orderRef}.${paymentId}.${customizationHash}.${exp}`;
  const sig = await hmacSha256Hex(secret, payload);
  return `${exp}.${sig}`;
}

async function verifyDownloadGrant(env, grant, orderRef, paymentId, customizationHash) {
  if (!grant || typeof grant !== "string") return false;
  const parts = grant.split(".");
  if (parts.length !== 2) return false;
  const exp = Number(parts[0]);
  const sig = parts[1];
  if (!Number.isFinite(exp) || exp < Math.floor(Date.now() / 1000)) return false;

  const secret = getSigningSecret(env);
  const payload = `${orderRef}.${paymentId}.${customizationHash}.${exp}`;
  const expectedSig = await hmacSha256Hex(secret, payload);
  return timingSafeEqual(sig, expectedSig);
}

async function hmacSha256Hex(secret, message) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return Array.from(new Uint8Array(sigBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function buildSessionCookie(token, isHttps) {
  const secureFlag = isHttps ? " Secure;" : "";
  return `sublibox_order_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000;${secureFlag}`;
}

function getCookieValue(cookieHeader, name) {
  if (!cookieHeader) return "";
  const parts = cookieHeader.split(";");
  for (const part of parts) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=").trim();
  }
  return "";
}

// =========================================================================
// INTEGRAÇÃO MERCADO PAGO & ASSINATURA WEBHOOK
// =========================================================================
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
  const computedHex = await hmacSha256Hex(secret, manifest);

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

// =========================================================================
// RATE LIMIT (D1 DISTRIBUÍDO + LIMPEZA DE EXPIRADOS + FALLBACK LIMITADO)
// =========================================================================
async function checkRateLimitD1(db, scopeKey, maxReqs, ctx) {
  const nowSec = Math.floor(Date.now() / 1000);
  const windowBucket = Math.floor(nowSec / RATE_LIMIT_WINDOW_SEC);
  const bucketKey = `${scopeKey}:${windowBucket}`;
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

    // Limpeza assíncrona probabilística (10% das requisições) dos registros expirados no D1
    if (Math.random() < 0.1) {
      const cleanupPromise = db
        .prepare("DELETE FROM rate_limits WHERE expires_at <= ?")
        .bind(nowSec)
        .run()
        .catch(() => {});
      if (ctx && typeof ctx.waitUntil === "function") {
        ctx.waitUntil(cleanupPromise);
      }
    }

    const count = row ? Number(row.request_count) : 1;
    if (count > maxReqs) {
      return {
        allowed: false,
        retryAfterSec: Math.max(1, expiresAt - nowSec)
      };
    }

    return { allowed: true };
  } catch (e) {
    // Limpa entradas expiradas e limita o tamanho máximo do Map em memória
    for (const [k, v] of memoryRateMap.entries()) {
      if (nowSec > v.expiresAt) memoryRateMap.delete(k);
    }
    if (memoryRateMap.size >= MEMORY_RATE_MAX_KEYS) {
      const oldestKey = memoryRateMap.keys().next().value;
      if (oldestKey) memoryRateMap.delete(oldestKey);
    }

    const memEntry = memoryRateMap.get(bucketKey) || { count: 0, expiresAt };
    if (nowSec > memEntry.expiresAt) {
      memEntry.count = 0;
      memEntry.expiresAt = expiresAt;
    }
    if (memEntry.count >= maxReqs) {
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
      "Cache-Control": "no-store, no-cache, must-revalidate, private",
      Pragma: "no-cache",
      ...extraHeaders
    }
  });
}
