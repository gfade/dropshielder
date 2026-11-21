// Dropshielder shop page. Talks to the backend routes listed in backend/server.py.
// Supports both Live Shopify Purchase mode (`/`) and Interactive Demo mode (`/demo`).
// All text from the server is inserted with textContent, never innerHTML.

const $ = (id) => document.getElementById(id);
const ICONS = { pending: "·", running: "●", done: "✓", skipped: "–", failed: "✕" };
const IS_DEMO_ROUTE = window.location.pathname.startsWith("/demo") || new URLSearchParams(window.location.search).get("mode") === "demo";

let config = null;
let selected = null;
let useShopifyCatalog = false;

function el(tag, props = {}, ...children) {
  const node = Object.assign(document.createElement(tag), props);
  for (const child of children) node.append(child);
  return node;
}

async function api(path, body) {
  const res = await fetch(path, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : undefined);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

async function init() {
  $("tab-live").className = IS_DEMO_ROUTE ? "" : "active";
  $("tab-demo").className = IS_DEMO_ROUTE ? "active" : "";

  config = await api(IS_DEMO_ROUTE ? "/api/config?mode=demo" : "/api/config");
  $("addon-price").textContent = (config.scan_addon_cents / 100).toFixed(2);

  useShopifyCatalog = !IS_DEMO_ROUTE && Array.isArray(config.shopify_products) && config.shopify_products.length > 0;
  const catalog = useShopifyCatalog ? config.shopify_products : config.products;

  if (useShopifyCatalog) {
    $("shop-subtitle").textContent = `live Shopify checkout (${config.shopify_domain})`;
    $("pick-heading").textContent = "1. Pick a real Shopify sticker";
    $("buy").textContent = "Scan & Proceed to Real Shopify Purchase";
  } else {
    $("shop-subtitle").textContent = IS_DEMO_ROUTE ? "interactive demo ($0.50 stickers)" : "sticker shop";
  }

  for (const p of catalog) {
    const imgSrc = p.image_url ? p.image_url : `/static/stickers/${p.image}`;
    const btn = el("button", { type: "button", className: "product" },
      el("img", { src: imgSrc, alt: "" }),
      el("span", { textContent: p.title }),
      el("small", { textContent: `$${(p.price_cents / 100).toFixed(2)}` }));
    btn.setAttribute("aria-pressed", "false");
    btn.addEventListener("click", () => select(p, btn));
    $("products").append(btn);
    if (!selected) select(p, btn);
  }

  // Scenario picker is shown in Demo Version or whenever at least one step runs on mock data.
  if (IS_DEMO_ROUTE || config.steps.some((s) => s.source === "mock")) {
    for (const [id, label] of Object.entries(config.scenarios)) $("scenario").append(el("option", { value: id, textContent: label }));
    $("demo-bar").hidden = false;
  }
  $("checkout").addEventListener("submit", buy);
}

function select(item, btn) {
  selected = item;
  for (const b of document.querySelectorAll(".product")) b.setAttribute("aria-pressed", String(b === btn));
}

async function buy(event) {
  event.preventDefault();
  $("buy").disabled = true;
  $("idle").hidden = true;
  $("steps").replaceChildren();
  $("verdict").hidden = true;
  try {
    const payload = {
      product_id: selected.id,
      buyer_name: $("buyer").value,
      want_scan: $("want-scan").checked,
      scenario: $("scenario").value || "clean",
      force_mock: IS_DEMO_ROUTE,
    };
    if (useShopifyCatalog && selected.variant_id) {
      payload.checkout_mode = "shopify";
      payload.variant_id = selected.variant_id;
      payload.title = selected.title;
      payload.price_cents = selected.price_cents;
      payload.image_url = selected.image_url || "";
      payload.product_url = selected.product_url || "";
    }
    const order = await api("/api/orders", payload);
    if (order.status === "AWAITING_SCAN") streamScan(order);
    else { showNoScan(order); $("buy").disabled = false; }
  } catch (err) {
    showError(err.message);
    $("buy").disabled = false;
  }
}

function streamScan(order) {
  for (const s of config.steps) $("steps").append(stepRow({ ...s, status: "pending" }));
  const es = new EventSource(`/api/orders/${order.order_id}/scan`);
  es.addEventListener("step", (e) => {
    const step = JSON.parse(e.data);
    $(`step-${step.id}`).replaceWith(stepRow(step));
  });
  es.addEventListener("report", (e) => {
    es.close();
    const { report, order: updated } = JSON.parse(e.data);
    showReport(report, updated);
    $("buy").disabled = false;
  });
  es.onerror = () => {
    es.close(); // do not let EventSource auto-reconnect and restart the stream
    showError("Lost connection to the scan. Refresh and check the order.");
    $("buy").disabled = false;
  };
}

function stepRow(step) {
  const text = el("div", {}, el("div", { textContent: step.title }));
  if (step.summary) text.append(el("div", { className: "summary", textContent: step.summary }));
  return el("li", { id: `step-${step.id}`, className: step.status },
    el("span", { className: "icon", textContent: ICONS[step.status] || "·" }),
    text,
    el("span", { className: `badge ${step.source}`, textContent: step.source }));
}

function table(headers, rows) {
  const t = el("table", {}, el("tr", {}, ...headers.map((h) => el("th", { textContent: h }))));
  for (const row of rows) t.append(el("tr", {}, ...row.map((cell) => el("td", {}, cell instanceof Node ? cell : document.createTextNode(String(cell ?? ""))))));
  return el("div", { className: "table-wrap" }, t);
}

function showReport(report, order) {
  const box = $("verdict");
  box.className = report.verdict;
  box.replaceChildren(
    el("h3", { textContent: report.verdict }),
    el("div", { textContent: report.headline }));

  if (report.reasons.length) box.append(el("ul", {}, ...report.reasons.map((r) => el("li", { textContent: r }))));

  if (report.new_cves.length) {
    box.append(el("strong", { textContent: "New CVEs" }), table(
      ["CVE", "Package", "Severity", "Reachable", "Exploited in wild", "What it means"],
      report.new_cves.map((c) => [
        c.id, `${c.package}@${c.version}`, c.severity,
        c.reachable === true ? "Yes" : c.reachable === false ? "No" : "Not assessed",
        c.known_exploited ? "Yes" : "No",
        c.plain_summary || c.summary,
      ])));
  }
  if (report.signals.length) {
    box.append(el("strong", { textContent: "Signs of exploitation" }), table(
      ["Kind", "Route", "Requests", "Example", "Looks like"],
      report.signals.map((s) => [s.kind, s.path, s.count, el("code", { textContent: s.sample }), s.matched_cve || "–"])));
  }

  const meta = [`Order ${order.order_id}`, `status ${order.status}`, `scanned ${report.scanned_at}`];
  if (report.mock_steps.length) meta.push(`${report.mock_steps.length} of ${report.steps.length} steps used mock data`);
  box.append(el("div", { className: "meta", textContent: meta.join(" · ") }));

  box.append(actions(report, order));
  box.hidden = false;
}

function primaryFulfillmentLinks(order) {
  const out = [];
  if (order.shopify_checkout_url) {
    out.push(el("a", {
      href: order.shopify_checkout_url,
      target: "_blank",
      rel: "noopener noreferrer",
      className: "btn-link",
      textContent: `Complete Real Purchase on Shop Pay (${order.product.shop_domain || "Shopify"}) →`,
    }));
    if (order.shopify_web_checkout_url && order.shopify_web_checkout_url !== order.shopify_checkout_url) {
      out.push(el("a", {
        href: order.shopify_web_checkout_url,
        target: "_blank",
        rel: "noopener noreferrer",
        className: "btn-link secondary",
        textContent: "Standard Shopify Card Checkout →",
      }));
    }
  } else if (order.download_url) {
    out.push(el("a", { href: order.download_url, className: "btn-link", textContent: "Download sticker" }));
  }
  return out;
}

function actions(report, order) {
  const row = el("div", { className: "actions" });
  for (const link of primaryFulfillmentLinks(order)) row.append(link);

  if (order.status === "HELD") {
    for (const [action, label] of [["release", "Merchant: release order"], ["refund", "Merchant: refund"]]) {
      const b = el("button", { type: "button", className: "secondary", textContent: label });
      b.addEventListener("click", async () => {
        try { showReport(report, await api(`/api/orders/${order.order_id}/resolve`, { action })); }
        catch (err) { showError(err.message); }
      });
      row.append(b);
    }
  }
  if (report.new_cves.length) {
    const b = el("button", { type: "button", className: "secondary", textContent: "Merchant: mark CVEs as reviewed" });
    b.addEventListener("click", async () => {
      try {
        await api("/api/acknowledge", { cve_ids: report.new_cves.map((c) => c.id) });
        b.textContent = "Marked as reviewed";
        b.disabled = true;
      } catch (err) { showError(err.message); }
    });
    row.append(b);
  }
  return row;
}

function showNoScan(order) {
  const box = $("verdict");
  box.className = "NOSCAN";
  box.replaceChildren(
    el("h3", { textContent: "Purchased without a scan" }),
    el("div", { className: "meta", textContent: `Order ${order.order_id} · this page was not checked.` }),
    el("div", { className: "actions" }, ...primaryFulfillmentLinks(order)));
  box.hidden = false;
}

function showError(message) {
  const box = $("verdict");
  box.className = "HOLD";
  box.replaceChildren(el("h3", { textContent: "Something went wrong" }), el("div", { textContent: message }));
  box.hidden = false;
}

init().catch((err) => showError(err.message));
