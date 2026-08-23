const http = require("http");
const url = require("url");

const comments = [];

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  res.setHeader("Content-Type", "text/html; charset=utf-8");

  if (pathname === "/") {
    // VULNERABLE: user input echoed back without escaping
    const q = parsed.query.q || "";
    res.end(`
      <!DOCTYPE html>
      <html>
      <body>
        <h1>Search</h1>
        <p>You searched for: ${q}</p>
        <form method="GET">
          <input name="q" value="${q}">
          <button type="submit">Search</button>
        </form>
      </body>
      </html>
    `);
  } else if (pathname === "/comment") {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      const { text } = JSON.parse(body);
      comments.push(text);
      // VULNERABLE: storing raw HTML in comments
      res.writeHead(200);
      res.end(JSON.stringify({ saved: true, comment: text }));
    });
  } else if (pathname === "/comments") {
    // VULNERABLE: rendering stored comments without sanitization
    res.end(`
      <!DOCTYPE html>
      <html>
      <body>
        <h1>Comments</h1>
        ${comments.map(c => `<div>${c}</div>`).join("")}
      </body>
      </html>
    `);
  } else if (pathname === "/jsonp") {
    const callback = parsed.query.callback || "callback";
    // VULNERABLE: unsanitized JSONP callback name
    res.setHeader("Content-Type", "application/javascript");
    res.end(`${callback}({"data":"hello"});`);
  } else {
    res.writeHead(404);
    res.end("Not found");
  }
});

const PORT = Number(process.env.PORT ?? 3457);
server.listen(PORT, () => console.log(`XSS fixture running on http://localhost:${PORT}`));
