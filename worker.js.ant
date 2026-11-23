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
        const precoOficial = 9.9;

        const preferenciaPayload = {
          items: [
            {
              title: body.titulo || "Placa de Balcao 4-em-1 PRO (6x4cm)",
              quantity: 1,
              currency_id: "BRL",
              unit_price: precoOficial
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

    // Rota para verificar se um pagamento específico está aprovado e com valor válido
    if (url.pathname === "/api/verificar-pagamento" && request.method === "GET") {
      if (!env.MP_ACCESS_TOKEN) {
        return jsonResponse({ error: "MP_ACCESS_TOKEN não configurado na Cloudflare." }, 500);
      }

      const rawId = url.searchParams.get("payment_id") || url.searchParams.get("collection_id") || "";
      const paymentId = rawId.replace(/\D/g, "");

      if (!paymentId) {
        return jsonResponse({ aprovado: false, error: "ID do pagamento inválido ou não informado." }, 400);
      }

      try {
        const mpRes = await fetch(`https://api.mercadopago.com/v1/payments/${encodeURIComponent(paymentId)}`, {
          headers: {
            "Authorization": `Bearer ${env.MP_ACCESS_TOKEN}`
          }
        });

        const mpData = await mpRes.json();

        if (!mpRes.ok) {
          return jsonResponse({ aprovado: false, error: "Pagamento não encontrado no Mercado Pago." }, 404);
        }

        const isApproved = mpData.status === "approved";
        const isValidAmount = Number(mpData.transaction_amount) >= 9.9;

        if (!isApproved || !isValidAmount) {
          return jsonResponse({
            aprovado: false,
            status: mpData.status,
            error: "Pagamento ainda não aprovado ou valor inferior ao da placa."
          }, 200);
        }

        return jsonResponse({
          aprovado: true,
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
