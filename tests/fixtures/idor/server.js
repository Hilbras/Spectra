const http = require("http");

// In-memory "database"
const users = [
  { id: "user-a", name: "Alice", role: "customer" },
  { id: "user-b", name: "Bob", role: "customer" },
  { id: "admin-1", name: "Admin", role: "admin" },
];

const orders = [
  { id: 1, userId: "user-a", item: "Laptop", price: 999, status: "shipped" },
  { id: 2, userId: "user-b", item: "Phone", price: 699, status: "pending" },
  { id: 3, userId: "user-a", item: "Tablet", price: 499, status: "processing" },
];

const server = http.createServer((req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method;

  res.setHeader("Content-Type", "application/json");

  // ─── Orders API (VULNERABLE: no authorization checks) ──────────────────────

  if (parsedUrl.pathname === "/api/orders" && method === "GET") {
    // VULNERABLE: returns ALL orders, no filter by user
    res.writeHead(200);
    res.end(JSON.stringify(orders));
  }

  if (parsedUrl.pathname.match(/^\/api\/orders\/\d+$/) && method === "GET") {
    const orderId = parseInt(parsedUrl.pathname.split("/").pop(), 10);
    const order = orders.find((o) => o.id === orderId);

    // VULNERABLE: no ownership check — anyone can fetch any order
    if (order) {
      res.writeHead(200);
      res.end(JSON.stringify(order));
    } else {
      res.writeHead(404);
      res.end(JSON.stringify({ error: "Not found" }));
    }
  }

  if (parsedUrl.pathname.match(/^\/api\/orders\/\d+$/) && method === "DELETE") {
    const orderId = parseInt(parsedUrl.pathname.split("/").pop(), 10);
    const idx = orders.findIndex((o) => o.id === orderId);

    // VULNERABLE: no auth at all — any unauthenticated request can delete
    if (idx !== -1) {
      orders.splice(idx, 1);
      res.writeHead(200);
      res.end(JSON.stringify({ deleted: true, id: orderId }));
    } else {
      res.writeHead(404);
      res.end(JSON.stringify({ error: "Not found" }));
    }
  }

  // ─── User API ──────────────────────────────────────────────────────────────

  if (parsedUrl.pathname === "/api/users" && method === "GET") {
    res.writeHead(200);
    res.end(JSON.stringify(users));
  }

  if (parsedUrl.pathname.match(/^\/api\/users\/[\w-]+$/) && method === "GET") {
    const userId = parsedUrl.pathname.split("/").pop();
    const user = users.find((u) => u.id === userId);

    // VULNERABLE: returns full user profile including internal fields
    if (user) {
      res.writeHead(200);
      res.end(JSON.stringify({
        ...user,
        // Leaked sensitive field
        ssn: "XXX-XX-XXXX",
        address: "123 Main St",
        creditCard: "4111-****-****-1234",
      }));
    } else {
      res.writeHead(404);
      res.end(JSON.stringify({ error: "Not found" }));
    }
  }

  // ─── Admin API (VULNERABLE: no role check) ─────────────────────────────────

  if (parsedUrl.pathname === "/api/admin/users" && method === "GET") {
    // VULNERABLE: no authentication or authorization — anyone can list users
    res.writeHead(200);
    res.end(JSON.stringify(users.map((u) => ({ ...u, passwordHash: "hashed_pw_" + u.id }))));
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: "Not found" }));
});

const PORT = Number(process.env.PORT ?? 3459);
server.listen(PORT, () => console.log(`IDOR fixture on http://localhost:${PORT}`));
