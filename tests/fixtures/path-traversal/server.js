const http = require("http");
const fs = require("fs");
const path = require("path");

const STATIC_DIR = path.join(__dirname, "public");

// Ensure public dir exists
if (!fs.existsSync(STATIC_DIR)) {
  fs.mkdirSync(STATIC_DIR, { recursive: true });
  fs.writeFileSync(path.join(STATIC_DIR, "hello.txt"), "Hello world\n");
}

const server = http.createServer((req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);

  if (parsedUrl.pathname === "/files") {
    const filename = parsedUrl.searchParams.get("name");
    if (!filename) {
      res.writeHead(400);
      res.end("Missing 'name' parameter");
      return;
    }

    // VULNERABLE: no sanitization of filename
    // User can pass "../../../etc/passwd" to read arbitrary files
    const filePath = path.join(STATIC_DIR, filename);

    try {
      const content = fs.readFileSync(filePath, "utf-8");
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(content);
    } catch (err) {
      // VULNERABLE: exposes internal path structure in error
      res.writeHead(500);
      res.end(`Error reading file: ${err.message}\nPath: ${filePath}`);
    }
  } else if (parsedUrl.pathname === "/list") {
    // VULNERABLE: directory listing without restrictions
    const dir = parsedUrl.searchParams.get("dir") || ".";
    const fullPath = path.join(STATIC_DIR, dir);
    try {
      const entries = fs.readdirSync(fullPath);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ files: entries }));
    } catch {
      res.writeHead(404);
      res.end("Directory not found");
    }
  } else if (parsedUrl.pathname === "/download") {
    const name = parsedUrl.searchParams.get("file");
    // VULNERABLE: allows downloading any file
    const filePath = path.join(STATIC_DIR, "..", "..", name || "");
    try {
      res.writeHead(200, {
        "Content-Disposition": `attachment; filename="${name}"`,
        "Content-Type": "application/octet-stream",
      });
      fs.createReadStream(filePath).pipe(res);
    } catch {
      res.writeHead(404);
      res.end("File not found");
    }
  } else {
    res.writeHead(404);
    res.end("Not found");
  }
});

const PORT = Number(process.env.PORT ?? 3458);
server.listen(PORT, () => console.log(`Path traversal fixture on http://localhost:${PORT}`));
