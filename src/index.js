import "dotenv/config";
import express from "express";
import cors from "cors";
import { z } from "zod";
import { supabaseAdmin } from "./supabase.js";
import { requireAuth, requireRole } from "./auth.js";

const app = express();

/**
 * CORS
 * - Supports comma-separated CORS_ORIGIN env
 * - Supports "*" for dev
 * - Allows StackBlitz/WebContainer preview domains
 */
const envOrigins = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (envOrigins.includes("*")) return cb(null, true);
    if (envOrigins.includes(origin)) return cb(null, true);

    if (origin.includes(".webcontainer.io") || origin.includes(".stackblitz.io")) {
      return cb(null, true);
    }

    return cb(new Error(`CORS blocked: ${origin}`), false);
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));
app.use(express.json());

const toNum = (v) => (v === null || v === undefined ? 0 : Number(v));

app.get("/", (req, res) => res.send("DBMS-backend running"));
app.get("/health", (req, res) => res.json({ ok: true }));

/**
 * Common
 */
app.get("/me", requireAuth, async (req, res) => {
  res.json({
    id: req.user.id,
    role: req.user.role,
    full_name: req.user.full_name,
    officer_title: req.user.officer_title ?? null
  });
});

/**
 * ACCOUNTS
 * Dean -> create Officer/President accounts (with officer_title)
 * Officer OR President -> create Student accounts
 */
const OfficerTitleEnum = z.enum([
  "President",
  "VP Internal",
  "VP External",
  "Secretary",
  "PIO",
  "Auditor",
  "Treasurer"
]);

app.post("/accounts/officers", requireAuth, requireRole("dean"), async (req, res) => {
  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
    full_name: z.string().min(2),
    officer_title: OfficerTitleEnum
  });

  const body = schema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  const role = body.data.officer_title === "President" ? "president" : "officer";

  // Create user in Supabase Auth (Admin API)
  const created = await supabaseAdmin.auth.admin.createUser({
    email: body.data.email,
    password: body.data.password,
    email_confirm: true
  });

  if (created.error) return res.status(400).json({ error: created.error.message });

  const userId = created.data.user.id;

  // IMPORTANT: use UPSERT (because profiles row may already be created by a DB trigger)
  const prof = await supabaseAdmin
    .from("profiles")
    .upsert(
      {
        id: userId,
        role,
        full_name: body.data.full_name,
        officer_title: body.data.officer_title
      },
      { onConflict: "id" }
    );

  if (prof.error) {
    // rollback auth user if profile update fails
    await supabaseAdmin.auth.admin.deleteUser(userId);
    return res.status(400).json({ error: prof.error.message });
  }

  res.json({
    id: userId,
    email: body.data.email,
    role,
    full_name: body.data.full_name,
    officer_title: body.data.officer_title
  });
});

app.post("/accounts/students", requireAuth, requireRole("officer", "president"), async (req, res) => {
  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
    full_name: z.string().min(2)
  });

  const body = schema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  const created = await supabaseAdmin.auth.admin.createUser({
    email: body.data.email,
    password: body.data.password,
    email_confirm: true
  });

  if (created.error) return res.status(400).json({ error: created.error.message });

  const userId = created.data.user.id;

  // IMPORTANT: use UPSERT here too
  const prof = await supabaseAdmin
    .from("profiles")
    .upsert(
      {
        id: userId,
        role: "student",
        full_name: body.data.full_name,
        created_by: req.user.id
      },
      { onConflict: "id" }
    );

  if (prof.error) {
    await supabaseAdmin.auth.admin.deleteUser(userId);
    return res.status(400).json({ error: prof.error.message });
  }

  res.json({
    id: userId,
    email: body.data.email,
    role: "student",
    full_name: body.data.full_name
  });
});

/**
 * PROPOSALS
 */
app.get("/proposals", requireAuth, async (req, res) => {
  const status = req.query.status; // pending/approved/rejected

  let q = supabaseAdmin.from("proposals").select("*").order("created_at", { ascending: false });

  if (req.user.role === "student") q = q.eq("status", "approved");
  if (req.user.role === "officer") q = q.eq("created_by", req.user.id);
  if ((req.user.role === "dean" || req.user.role === "president") && status) {
    q = q.eq("status", status);
  }

  const { data, error } = await q;
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

/**
 * Officer: create proposal
 */
app.post("/proposals", requireAuth, requireRole("officer"), async (req, res) => {
  const schema = z.object({
    title: z.string().min(3),
    description: z.string().optional(),
    budget_total: z.number().nonnegative(),
    required_per_student: z.number().nonnegative()
  });
  const body = schema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  const { data, error } = await supabaseAdmin
    .from("proposals")
    .insert({
      created_by: req.user.id,
      title: body.data.title,
      description: body.data.description ?? null,
      budget_total: body.data.budget_total,
      required_per_student: body.data.required_per_student,
      status: "pending"
    })
    .select("*")
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

/**
 * Officer: edit own proposal ONLY if still pending
 */
app.patch("/proposals/:id", requireAuth, requireRole("officer"), async (req, res) => {
  const schema = z.object({
    title: z.string().min(3).optional(),
    description: z.string().optional(),
    budget_total: z.number().nonnegative().optional(),
    required_per_student: z.number().nonnegative().optional()
  });
  const body = schema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  const current = await supabaseAdmin
    .from("proposals")
    .select("id, created_by, status")
    .eq("id", req.params.id)
    .single();

  if (current.error) return res.status(400).json({ error: current.error.message });
  if (current.data.created_by !== req.user.id) return res.status(403).json({ error: "Not your proposal" });
  if (current.data.status !== "pending") return res.status(400).json({ error: "Only pending proposals can be edited" });

  const { data, error } = await supabaseAdmin
    .from("proposals")
    .update(body.data)
    .eq("id", req.params.id)
    .select("*")
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

/**
 * Dean: approve / reject proposal
 */
app.patch("/proposals/:id/status", requireAuth, requireRole("dean"), async (req, res) => {
  const schema = z.object({
    status: z.enum(["approved", "rejected"]),
    dean_comment: z.string().optional()
  });
  const body = schema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  const { data, error } = await supabaseAdmin
    .from("proposals")
    .update({
      status: body.data.status,
      dean_comment: body.data.dean_comment ?? null,
      reviewed_by: req.user.id,
      reviewed_at: new Date().toISOString()
    })
    .eq("id", req.params.id)
    .select("*")
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

/**
 * EVENTS alias (for students): approved proposals
 */
app.get("/events", requireAuth, async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from("proposals")
    .select("*")
    .eq("status", "approved")
    .order("created_at", { ascending: false });

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

/**
 * PAYMENTS
 */
app.post("/payments", requireAuth, requireRole("student"), async (req, res) => {
  const schema = z.object({
    proposal_id: z.string().uuid(),
    amount: z.number().positive(),
    method: z.string().optional(),
    reference_no: z.string().optional()
  });
  const body = schema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  const proposal = await supabaseAdmin
    .from("proposals")
    .select("id, status, required_per_student")
    .eq("id", body.data.proposal_id)
    .single();

  if (proposal.error) return res.status(400).json({ error: proposal.error.message });
  if (proposal.data.status !== "approved") return res.status(400).json({ error: "Event not available (not approved)" });

  const required = toNum(proposal.data.required_per_student);

  const paid = await supabaseAdmin
    .from("payments")
    .select("amount")
    .eq("proposal_id", body.data.proposal_id)
    .eq("student_id", req.user.id);

  if (paid.error) return res.status(400).json({ error: paid.error.message });

  const totalPaid = (paid.data || []).reduce((s, r) => s + toNum(r.amount), 0);
  const remaining = required > 0 ? Math.max(required - totalPaid, 0) : null;

  if (remaining !== null && body.data.amount > remaining) {
    return res.status(400).json({ error: `Amount exceeds remaining balance (${remaining})` });
  }

  const payment = await supabaseAdmin
    .from("payments")
    .insert({
      proposal_id: body.data.proposal_id,
      student_id: req.user.id,
      amount: body.data.amount,
      method: body.data.method ?? "manual",
      reference_no: body.data.reference_no ?? null
    })
    .select("*")
    .single();

  if (payment.error) return res.status(400).json({ error: payment.error.message });

  const rno = await supabaseAdmin.rpc("generate_receipt_no");
  if (rno.error) return res.status(400).json({ error: rno.error.message });

  const receipt = await supabaseAdmin
    .from("receipts")
    .insert({
      payment_id: payment.data.id,
      receipt_no: rno.data
    })
    .select("*")
    .single();

  if (receipt.error) return res.status(400).json({ error: receipt.error.message });

  res.json({ payment: payment.data, receipt: receipt.data });
});

/**
 * Student: payment history + receipts
 */
app.get("/my/payments", requireAuth, requireRole("student"), async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from("payments")
    .select("*, receipts(*)")
    .eq("student_id", req.user.id)
    .order("paid_at", { ascending: false });

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

/**
 * Officer: view payments for own proposal
 */
app.get("/officer/proposals/:id/payments", requireAuth, requireRole("officer"), async (req, res) => {
  const pr = await supabaseAdmin
    .from("proposals")
    .select("id, created_by")
    .eq("id", req.params.id)
    .single();

  if (pr.error) return res.status(400).json({ error: pr.error.message });
  if (pr.data.created_by !== req.user.id) return res.status(403).json({ error: "Not your proposal" });

  const { data, error } = await supabaseAdmin
    .from("payments")
    .select("*, receipts(*)")
    .eq("proposal_id", req.params.id)
    .order("paid_at", { ascending: false });

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

/**
 * REPORTS
 * Dean: department-level totals
 */
app.get("/reports/department", requireAuth, requireRole("dean", "president"), async (req, res) => {
  const proposals = await supabaseAdmin
    .from("proposals")
    .select("id, title, status, budget_total, required_per_student");

  if (proposals.error) return res.status(400).json({ error: proposals.error.message });

  const payments = await supabaseAdmin.from("payments").select("proposal_id, amount");
  if (payments.error) return res.status(400).json({ error: payments.error.message });

  const collectedByProposal = new Map();
  for (const p of payments.data || []) {
    const k = p.proposal_id;
    collectedByProposal.set(k, (collectedByProposal.get(k) || 0) + toNum(p.amount));
  }

  const rows = (proposals.data || []).map((pr) => {
    const collected = collectedByProposal.get(pr.id) || 0;
    const budgetTotal = toNum(pr.budget_total);
    return {
      proposal_id: pr.id,
      title: pr.title,
      status: pr.status,
      budget_total: budgetTotal,
      collected_total: collected,
      remaining_budget: Math.max(budgetTotal - collected, 0),
      required_per_student: toNum(pr.required_per_student)
    };
  });

  res.json(rows);
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`DBMS-backend running on port ${PORT}`));