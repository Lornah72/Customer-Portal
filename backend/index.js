// backend/index.js
// Customer ordering backend using OAuth (BC cloud) + simple JWT login

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fetch from "node-fetch";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

// -------------------- CONFIG --------------------

const BC_TENANT_ID = process.env.BC_TENANT_ID;
const BC_CLIENT_ID = process.env.BC_CLIENT_ID;
const BC_CLIENT_SECRET = process.env.BC_CLIENT_SECRET;
const BC_ENV = process.env.BC_ENV;
const BC_COMPANY_ID = process.env.BC_COMPANY_ID;
const BC_SCOPE =
  process.env.BC_SCOPE || "https://api.businesscentral.dynamics.com/.default";
const JWT_SECRET = process.env.JWT_SECRET || "change-me";

if (
  !BC_TENANT_ID ||
  !BC_CLIENT_ID ||
  !BC_CLIENT_SECRET ||
  !BC_ENV ||
  !BC_COMPANY_ID
) {
  console.error(
    "❌ Missing one of BC_TENANT_ID / BC_CLIENT_ID / BC_CLIENT_SECRET / BC_ENV / BC_COMPANY_ID in .env"
  );
}

const BC_BASE_URL = `https://api.businesscentral.dynamics.com/v2.0/${BC_TENANT_ID}/${BC_ENV}/api/v2.0`;
const COMPANY_URL = `${BC_BASE_URL}/companies(${BC_COMPANY_ID})`;

// Demo portal users (map to real BC customers)
const PORTAL_USERS = [
  {
    id: 1,
    email: "Robertos-Rest",
    password: "Rest1234",
    bcCustomerNo: "CUST-00466",
  },
  {
    id: 2,
    email: "Robertos-Roslyn",
    password: "Ros1234",
    bcCustomerNo: "CUST-00232",
  },
];

// -------------------- OAUTH TOKEN HELPER --------------------

let cachedToken = null;
let cachedTokenExpiresAt = 0;

async function getAccessToken() {
  const now = Date.now();

  if (cachedToken && now < cachedTokenExpiresAt) {
    return cachedToken;
  }

  const tokenUrl = `https://login.microsoftonline.com/${BC_TENANT_ID}/oauth2/v2.0/token`;

  const body = new URLSearchParams();
  body.append("grant_type", "client_credentials");
  body.append("client_id", BC_CLIENT_ID);
  body.append("client_secret", BC_CLIENT_SECRET);
  body.append("scope", BC_SCOPE);

  const res = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!res.ok) {
    const text = await res.text();
    console.error("❌ Error getting access token from Azure:", text);
    throw new Error(
      "Failed to get access token from Azure. Check BC_TENANT_ID / BC_CLIENT_ID / BC_CLIENT_SECRET."
    );
  }

  const data = await res.json();
  cachedToken = data.access_token;
  const expiresInSec = data.expires_in || 3600;
  cachedTokenExpiresAt = now + (expiresInSec - 60) * 1000; // refresh 1 min early

  return cachedToken;
}

async function getBcAuthHeader() {
  const token = await getAccessToken();
  return `Bearer ${token}`;
}

// -------------------- AUTH MIDDLEWARE --------------------

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    console.error("JWT error:", err);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// -------------------- ROUTES --------------------

// Health check
app.get("/", (req, res) => {
  res.send("Customer portal backend is running (BC OAuth).");
});

// POST /login  → returns JWT
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const user = PORTAL_USERS.find(
    (u) => u.email === email && u.password === password
  );

  if (!user) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const payload = {
    id: user.id,
    email: user.email,
    bcCustomerNo: user.bcCustomerNo,
  };

  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "8h" });

  res.json({
    token,
    user: { email: user.email },
  });
});

// GET /items - list items for portal (no auth)
app.get("/items", async (req, res) => {
  try {
    const url = `${COMPANY_URL}/items`;
    const authHeader = await getBcAuthHeader();

    const response = await fetch(url, {
      method: "GET",
      headers: {
        Authorization: authHeader,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      const text = await response.text();
      console.error("❌ BC /items error:", text);
      return res.status(500).json({ error: "Failed to load items from BC." });
    }

    const data = await response.json();

    const items = data.value.map((item) => ({
      id: item.id,                 // GUID – used as itemId when adding lines
      no: item.number,
      name: item.displayName,
      price: item.unitPrice,
      inventory: item.inventory,
      // 👉 GTIN / Barcode from BC (adjust if your field name is different)
      gtin:
        item.gtin ||
        item.GTIN ||
        item.gtinCode ||
        item.GTINCode ||
        null,
    }));

    res.json(items);
  } catch (err) {
    console.error("❌ Error in /items:", err);
    res.status(500).json({ error: "Server error loading items." });
  }
});

// POST /order - create sales order (auth)
// Body: { lines: [ { id, no, quantity }, ... ] }
app.post("/order", authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    const customerNo =
      user && user.bcCustomerNo
        ? user.bcCustomerNo
        : process.env.BC_PORTAL_CUSTOMER_NO || "C00010";

    const { lines } = req.body;

    if (!lines || !Array.isArray(lines) || lines.length === 0) {
      return res.status(400).json({ error: "No order lines provided." });
    }

    const authHeader = await getBcAuthHeader();

    // 1. Look up customer by number → get GUID
    const customerUrl = `${COMPANY_URL}/customers?$filter=number eq '${customerNo}'`;
    const custRes = await fetch(customerUrl, {
      method: "GET",
      headers: {
        Authorization: authHeader,
        "Content-Type": "application/json",
      },
    });

    if (!custRes.ok) {
      const text = await custRes.text();
      console.error("❌ BC customer lookup error:", text);
      return res
        .status(500)
        .json({ error: "Failed to look up customer in BC." });
    }

    const custData = await custRes.json();
    if (!custData.value || custData.value.length === 0) {
      console.error("❌ Customer not found by number:", customerNo);
      return res.status(400).json({
        error: `Customer number ${customerNo} not found in this company.`,
      });
    }

    const customerId = custData.value[0].id; // GUID

    // 2. Create order header using customerId
    const orderBody = {
      customerId: customerId,
      orderDate: new Date().toISOString().slice(0, 10),
      externalDocumentNumber: `WEB-${Date.now()}`,
    };

    const createOrderUrl = `${COMPANY_URL}/salesOrders`;

    const orderRes = await fetch(createOrderUrl, {
      method: "POST",
      headers: {
        Authorization: authHeader,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(orderBody),
    });

    if (!orderRes.ok) {
      const text = await orderRes.text();
      console.error("❌ BC create order error:", text);
      return res
        .status(500)
        .json({ error: "Failed to create order header in BC." });
    }

    const order = await orderRes.json();
    const orderId = order.id;

    // 3. Add lines – use itemId (GUID)
    const lineUrl = `${COMPANY_URL}/salesOrderLines`;

    for (const line of lines) {
      if (!line.id || !line.quantity) continue;

      const lineBody = {
        documentId: orderId,
        lineType: "Item",
        itemId: line.id,
        quantity: line.quantity,
      };

      const lineRes = await fetch(lineUrl, {
        method: "POST",
        headers: {
          Authorization: authHeader,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(lineBody),
      });

      if (!lineRes.ok) {
        const text = await lineRes.text();
        console.error("❌ BC add line error:", text);
        return res
          .status(500)
          .json({ error: "Failed to add an order line in BC." });
      }
    }

    res.json({
      success: true,
      bcOrderNo: order.number,
      message: `Order ${order.number} created in BC.`,
    });
  } catch (err) {
    console.error("❌ Error in /order:", err);
    res.status(500).json({ error: "Server error creating order." });
  }
});

// GET /orders - list sales orders for logged-in customer
app.get("/orders", authMiddleware, async (req, res) => {
  try {
    const customerNo = req.user.bcCustomerNo;
    const authHeader = await getBcAuthHeader();

    const url =
      `${COMPANY_URL}/salesOrders?$filter=customerNumber eq '${customerNo}'&$orderby=orderDate desc`;

    const response = await fetch(url, {
      method: "GET",
      headers: {
        Authorization: authHeader,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      const text = await response.text();
      console.error("❌ BC /orders error:", text);
      return res
        .status(500)
        .json({ error: "Failed to load orders from BC." });
    }

    const data = await response.json();

    const orders = data.value.map((o) => ({
      number: o.number,
      orderDate: o.orderDate,
      status: o.status,
      totalAmount: o.totalAmountIncludingTax,
    }));

    res.json(orders);
  } catch (err) {
    console.error("❌ Error in /orders:", err);
    res.status(500).json({ error: "Server error loading orders." });
  }
});

// -------------------- START SERVER --------------------

app.listen(PORT, () => {
  console.log(`✅ Customer portal backend running on http://localhost:${PORT}`);
});
