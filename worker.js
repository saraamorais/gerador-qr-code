export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Rota para criar pagamento no Checkout Pro do Mercado Pago
    if (url.pathname === "/api/criar-pagamento" && request.method === "POST") {
      if (!env.MP_ACCESS_TOKEN) {
        return jsonResponse({ error: "MP_ACCESS_TOKEN não configurado na Cloudflare." }, 500);
      }

      try {
        const body = await request.json().catch(() => ({}));
        const origem = url.origin;

        const preferenciaPayload = {
          items: [
            {
              title: body.titulo || "Placa de Balcao 4-em-1 PRO",
              quantity: 1,
              currency_id: "BRL",
              unit_price: Number(body.valor) > 0 ? Number(body.valor) : 9.9
            }
          ],
          back_urls: {
            success: `${origem}/?status=approved`,
            failure: `${origem}/?status=failure`,
            pending: `${origem}/?status=pending`
          },
          auto_return: "approved",
          external_reference: body.referencia || `sublibox_${Date.now()}`
        };

        const mpRes = await fetch("https://api.mercadopago.com/checkout/preferences", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.MP_ACCESS_TOKEN}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify(preferenciaPayload)
        });

        const mpData = await mpRes.json();

        if (!mpRes.ok) {
          return jsonResponse({ error: "Falha ao criar preferência no Mercado Pago.", detalhes: mpData }, mpRes.status);
        }

        return jsonResponse({
          id: mpData.id,
          init_point: mpData.init_point,
          sandbox_init_point: mpData.sandbox_init_point
        });
      } catch (err) {
        return jsonResponse({ error: "Erro interno ao comunicar com o Mercado Pago." }, 500);
      }
    }

    // Rota para verificar se um pagamento específico está aprovado
    if (url.pathname === "/api/verificar-pagamento" && request.method === "GET") {
      if (!env.MP_ACCESS_TOKEN) {
        return jsonResponse({ error: "MP_ACCESS_TOKEN não configurado na Cloudflare." }, 500);
      }

      const paymentId = url.searchParams.get("payment_id") || url.searchParams.get("collection_id");
      if (!paymentId) {
        return jsonResponse({ error: "payment_id não informado." }, 400);
      }

      try {
        const mpRes = await fetch(`https://api.mercadopago.com/v1/payments/${encodeURIComponent(paymentId)}`, {
          headers: {
            "Authorization": `Bearer ${env.MP_ACCESS_TOKEN}`
          }
        });

        const mpData = await mpRes.json();

        if (!mpRes.ok) {
          return jsonResponse({ aprovado: false, error: "Pagamento não encontrado." }, mpRes.status);
        }

        return jsonResponse({
          aprovado: mpData.status === "approved",
          status: mpData.status,
          payment_id: mpData.id
        });
      } catch (err) {
        return jsonResponse({ aprovado: false, error: "Erro ao consultar pagamento." }, 500);
      }
    }

    // Rota para receber notificações de Webhook do Mercado Pago
    if (url.pathname === "/api/webhook" && (request.method === "POST" || request.method === "GET")) {
      return jsonResponse({ received: true }, 200);
    }

    // Para todas as outras rotas, deixa a Cloudflare servir os ficheiros estáticos (index.html, etc.)
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("Não encontrado", { status: 404 });
  }
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8"
    }
  });
}