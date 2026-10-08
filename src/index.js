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
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));
app.use(express.json());

const toNum = (v) => (v === null || v === undefined ? 0 : Number(v));

/**
 * Profile helpers/schema
 */
const CourseEnum = z.enum(["IT", "CS"]);

function buildFullName({ first_name, middle_name, last_name }) {
  return [first_name, middle_name, last_name].filter(Boolean).join(" ").trim();
}

function calcAge(dobStr) {
  if (!dobStr) return null;
  const dob = new Date(dobStr);
  if (Number.isNaN(dob.getTime())) return null;

  const today = new Date();
  let age = today.getFullYear() - dob.getFullYear();
  const m = today.getMonth() - dob.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < dob.getDate())) age--;
  return age;
}

const baseProfileSchema = z.object({
  first_name: z.string().min(1),
  middle_name: z.string().optional(),
  last_name: z.string().min(1),
  date_of_birth: z.string().regex(/^\d{4}-\d{2}-\d{2}$/), // YYYY-MM-DD
  address: z.string().min(3),
  mobile_number: z.string().min(7),
  course: CourseEnum,
  year_level: z.number().int().min(1).max(5),
});

/**
 * Officer titles (President included, but only Dean may create President accounts)
 */
const OfficerTitleEnum = z.enum([
  "President",
  "VP Internal",
  "VP External",
  "Secretary",
  "PIO",
  "Auditor",
  "Treasurer",
]);

app.get("/", (req, res) => res.send("DBMS-backend running"));
app.get("/health", (req, res) => res.json({ ok: true }));

/**
 * Common
 */
app.get("/me", requireAuth, async (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email ?? null,
    role: req.user.role,
    full_name: req.user.full_name,
    officer_title: req.user.officer_title ?? null,

    first_name: req.user.first_name ?? null,
    middle_name: req.user.middle_name ?? null,
    last_name: req.user.last_name ?? null,

    date_of_birth: req.user.date_of_birth ?? null,
    age: req.user.age ?? null,
    address: req.user.address ?? null,
    mobile_number: req.user.mobile_number ?? null,

    course: req.user.course ?? null,
    year_level: req.user.year_level ?? null,
  });
});

/**
 * ACCOUNTS RULES
 * - Dean can create: Dean, Student, Officer, President
 * - President can create: Student, Officer (NOT Dean, NOT President)
 */

/**
 * Dean-only: create Dean account
 */
app.post("/accounts/deans", requireAuth, requireRole("dean"), async (req, res) => {
  const schema = z
    .object({
      email: z.string().email(),
      password: z.string().min(6),
    })
    .and(baseProfileSchema);

  const body = schema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  const full_name = buildFullName(body.data);
  const age = calcAge(body.data.date_of_birth);

  const created = await supabaseAdmin.auth.admin.createUser({
    email: body.data.email,
    password: body.data.password,
    email_confirm: true,
  });

  if (created.error) return res.status(400).json({ error: created.error.message });

  const userId = created.data.user.id;

  const prof = await supabaseAdmin.from("profiles").upsert(
    {
      id: userId,
      role: "dean",
      full_name,
      first_name: body.data.first_name,
      middle_name: body.data.middle_name ?? null,
      last_name: body.data.last_name,
      date_of_birth: body.data.date_of_birth,
      age,
      address: body.data.address,
      mobile_number: body.data.mobile_number,
      course: body.data.course,
      year_level: body.data.year_level,
    },
    { onConflict: "id" }
  );

  if (prof.error) {
    await supabaseAdmin.auth.admin.deleteUser(userId);
    return res.status(400).json({ error: prof.error.message });
  }

  res.json({ id: userId, email: body.data.email, role: "dean", full_name });
});

/**
 * Dean/President: create Student account
 */
app.post(
  "/accounts/students",
  requireAuth,
  requireRole("dean", "president"),
  async (req, res) => {
    const schema = z
      .object({
        email: z.string().email(),
        password: z.string().min(6),
      })
      .and(baseProfileSchema);

    const body = schema.safeParse(req.body);
    if (!body.success) return res.status(400).json(body.error);

    const full_name = buildFullName(body.data);
    const age = calcAge(body.data.date_of_birth);

    const created = await supabaseAdmin.auth.admin.createUser({
      email: body.data.email,
      password: body.data.password,
      email_confirm: true,
    });

    if (created.error) return res.status(400).json({ error: created.error.message });

    const userId = created.data.user.id;

    const prof = await supabaseAdmin.from("profiles").upsert(
      {
        id: userId,
        role: "student",
        full_name,
        first_name: body.data.first_name,
        middle_name: body.data.middle_name ?? null,
        last_name: body.data.last_name,
        date_of_birth: body.data.date_of_birth,
        age,
        address: body.data.address,
        mobile_number: body.data.mobile_number,
        course: body.data.course,
        year_level: body.data.year_level,
        created_by: req.user.id,
      },
      { onConflict: "id" }
    );

    if (prof.error) {
      await supabaseAdmin.auth.admin.deleteUser(userId);
      return res.status(400).json({ error: prof.error.message });
    }

    res.json({ id: userId, email: body.data.email, role: "student", full_name });
  }
);

/**
 * Dean/President: create Officer accounts
 * - If officer_title === "President" => role = "president" BUT ONLY DEAN can do that
 */
app.post(
  "/accounts/officers",
  requireAuth,
  requireRole("dean", "president"),
  async (req, res) => {
    const schema = z
      .object({
        email: z.string().email(),
        password: z.string().min(6),
        officer_title: OfficerTitleEnum,
      })
      .and(baseProfileSchema);

    const body = schema.safeParse(req.body);
    if (!body.success) return res.status(400).json(body.error);

    // BLOCK: President cannot create President accounts
    if (req.user.role === "president" && body.data.officer_title === "President") {
      return res.status(403).json({ error: "President cannot create another President account." });
    }

    // Only dean may create a President role (president creation already blocked above)
    const role = body.data.officer_title === "President" ? "president" : "officer";

    const full_name = buildFullName(body.data);
    const age = calcAge(body.data.date_of_birth);

    const created = await supabaseAdmin.auth.admin.createUser({
      email: body.data.email,
      password: body.data.password,
      email_confirm: true,
    });

    if (created.error) return res.status(400).json({ error: created.error.message });

    const userId = created.data.user.id;

    const prof = await supabaseAdmin.from("profiles").upsert(
      {
        id: userId,
        role,
        full_name,
        officer_title: body.data.officer_title,
        first_name: body.data.first_name,
        middle_name: body.data.middle_name ?? null,
        last_name: body.data.last_name,
        date_of_birth: body.data.date_of_birth,
        age,
        address: body.data.address,
        mobile_number: body.data.mobile_number,
        course: body.data.course,
        year_level: body.data.year_level,
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
      role,
      full_name,
      officer_title: body.data.officer_title,
    });
  }
);

/**
 * LIST ACCOUNTS
 * - Dean: can see all roles
 * - President: can see student + officer only
 * Returns profiles + email (email fetched from Supabase Auth)
 */
app.get("/accounts", requireAuth, requireRole("dean", "president"), async (req, res) => {
  try {
    const roleFilter = (req.query.role || "").toString(); // optional
    const qText = (req.query.q || "").toString().trim();  // optional

    let q = supabaseAdmin
      .from("profiles")
      .select(`
        id,
        role,
        full_name,
        first_name,
        middle_name,
        last_name,
        officer_title,
        date_of_birth,
        age,
        address,
        mobile_number,
        course,
        year_level,
        created_by
      `)
      .order("full_name", { ascending: true });

    // President sees only student + officer
    if (req.user.role === "president") {
      q = q.in("role", ["student", "officer"]);
    }

    if (roleFilter && roleFilter !== "all") {
      if (req.user.role === "president" && !["student", "officer"].includes(roleFilter)) {
        return res.status(403).json({ error: "Not allowed to view this role." });
      }
      q = q.eq("role", roleFilter);
    }

    // basic server-side name search
    if (qText) {
      q = q.ilike("full_name", `%${qText}%`);
    }

    const { data: profiles, error } = await q;
    if (error) return res.status(400).json({ error: error.message });

    // Attach emails from Supabase Auth; hide accounts whose auth user was deleted
    const withEmail = await Promise.all(
      (profiles || []).map(async (p) => {
        const r = await supabaseAdmin.auth.admin.getUserById(p.id);
        const email = r?.data?.user?.email ?? null;
        if (!email) return null; // treat missing auth user as deleted
        return { ...p, email };
      })
    );

    res.json(withEmail.filter(Boolean));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/**
 * UPDATE ACCOUNT (profile + optional password reset)
 * - Dean: can edit anyone
 * - President: can edit student + officer only
 * - Prevent president from setting officer_title = "President"
 */
app.patch("/accounts/:id", requireAuth, requireRole("dean", "president"), async (req, res) => {
  const patchSchema = z.object({
    first_name: z.string().min(1).optional(),
    middle_name: z.string().nullable().optional(),
    last_name: z.string().min(1).optional(),

    date_of_birth: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).nullable().optional(),
    address: z.string().min(3).nullable().optional(),
    mobile_number: z.string().min(7).nullable().optional(),

    course: z.union([CourseEnum, z.null()]).optional(),
    year_level: z.union([z.number().int().min(1).max(5), z.null()]).optional(),

    officer_title: z.union([OfficerTitleEnum, z.null()]).optional(),

    // Optional password reset
    new_password: z.string().min(6).optional(),
  });

  const body = patchSchema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  try {
    const id = req.params.id;

    // Load target
    const current = await supabaseAdmin
      .from("profiles")
      .select(`
        id, role,
        first_name, middle_name, last_name,
        date_of_birth,
        officer_title
      `)
      .eq("id", id)
      .single();

    if (current.error) return res.status(400).json({ error: current.error.message });

    const targetRole = current.data.role;

    // Permission: President can only edit student/officer
    if (req.user.role === "president" && !["student", "officer"].includes(targetRole)) {
      return res.status(403).json({ error: "President can only edit Student and Officer accounts." });
    }

    // Prevent president from setting President title
    if (req.user.role === "president" && body.data.officer_title === "President") {
      return res.status(403).json({ error: "President cannot set officer_title to President." });
    }

    // Build profiles update payload
    const updatePayload = { ...body.data };
    delete updatePayload.new_password;

    // Recompute full_name if any name part changed
    const nextName = {
      first_name: body.data.first_name ?? current.data.first_name,
      middle_name:
        body.data.middle_name !== undefined ? body.data.middle_name : current.data.middle_name,
      last_name: body.data.last_name ?? current.data.last_name,
    };

    if (
      body.data.first_name !== undefined ||
      body.data.middle_name !== undefined ||
      body.data.last_name !== undefined
    ) {
      updatePayload.full_name = buildFullName(nextName);
    }

    // Recompute age if DOB changed
    const nextDob =
      body.data.date_of_birth !== undefined ? body.data.date_of_birth : current.data.date_of_birth;

    if (body.data.date_of_birth !== undefined) {
      updatePayload.age = calcAge(nextDob);
    }

    // officer_title ↔ role consistency (Dean-only promotion/demotion)
    if (body.data.officer_title !== undefined) {
      const newTitle = body.data.officer_title;

      // If set to President => only dean allowed, role becomes 'president'
      if (newTitle === "President") {
        if (req.user.role !== "dean") {
          return res.status(403).json({ error: "Only Dean can assign President officer_title." });
        }
        updatePayload.role = "president";
      }

      // If target was president and title changed away from President (or cleared) => demote to officer (Dean only)
      if (targetRole === "president" && newTitle !== "President") {
        if (req.user.role !== "dean") {
          return res.status(403).json({ error: "Only Dean can modify President account title/role." });
        }
        updatePayload.role = "officer";
      }
    }

    // Update profiles row
    const updated = await supabaseAdmin
      .from("profiles")
      .update(updatePayload)
      .eq("id", id)
      .select("*")
      .single();

    if (updated.error) return res.status(400).json({ error: updated.error.message });

    // Optional password reset
    if (body.data.new_password) {
      const pw = await supabaseAdmin.auth.admin.updateUserById(id, {
        password: body.data.new_password,
      });
      if (pw.error) return res.status(400).json({ error: pw.error.message });
    }

    // Attach email for convenience
    const authUser = await supabaseAdmin.auth.admin.getUserById(id);

    res.json({
      ...updated.data,
      email: authUser?.data?.user?.email ?? null,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/**
 * DELETE ACCOUNT (safe)
 * - Deletes Supabase Auth user (removes login access)
 * - Keeps profiles row to preserve history (payments/proposals foreign keys)
 *
 * Permissions:
 * - Dean: can delete anyone
 * - President: can delete student/officer only
 * - Cannot delete self
 */
app.delete("/accounts/:id", requireAuth, requireRole("dean", "president"), async (req, res) => {
  try {
    const id = req.params.id;

    if (id === req.user.id) {
      return res.status(400).json({ error: "You cannot delete your own account." });
    }

    const target = await supabaseAdmin
      .from("profiles")
      .select("id, role")
      .eq("id", id)
      .single();

    if (target.error) return res.status(400).json({ error: target.error.message });

    const targetRole = target.data.role;

    if (req.user.role === "president" && !["student", "officer"].includes(targetRole)) {
      return res
        .status(403)
        .json({ error: "President can only delete Student and Officer accounts." });
    }

    const del = await supabaseAdmin.auth.admin.deleteUser(id);
    if (del.error) return res.status(400).json({ error: del.error.message });

    res.json({ ok: true, deleted_user_id: id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/**
 * PROPOSALS
 */
app.get("/proposals", requireAuth, async (req, res) => {
  const status = req.query.status;

  let q = supabaseAdmin.from("proposals").select("*").order("created_at", {
    ascending: false,
  });

  if (req.user.role === "student") q = q.eq("status", "approved");

  // officer sees own only
  if (req.user.role === "officer") q = q.eq("created_by", req.user.id);

  // dean/president see all (optional status filter)
  if ((req.user.role === "dean" || req.user.role === "president") && status) {
    q = q.eq("status", status);
  }

  const { data, error } = await q;

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

/**
 * Officer/President: create proposal with breakdown
 */
app.post("/proposals", requireAuth, requireRole("officer", "president"), async (req, res) => {
  const itemSchema = z.object({
    name: z.string().min(1),
    amount: z.number().nonnegative(),
  });

  const schema = z.object({
    title: z.string().min(3),
    description: z.string().optional(),
    breakdown: z.array(itemSchema).min(1),
  });

  const body = schema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  const requiredPerStudent = body.data.breakdown.reduce(
    (sum, it) => sum + Number(it.amount || 0),
    0
  );

  const { data, error } = await supabaseAdmin
    .from("proposals")
    .insert({
      created_by: req.user.id,
      title: body.data.title,
      description: body.data.description ?? null,
      breakdown: body.data.breakdown,
      required_per_student: requiredPerStudent,
      budget_total: requiredPerStudent,
      status: "pending",
    })
    .select("*")
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

/**
 * Officer/President: edit own proposal ONLY if pending
 */
app.patch("/proposals/:id", requireAuth, requireRole("officer", "president"), async (req, res) => {
  const itemSchema = z.object({
    name: z.string().min(1),
    amount: z.number().nonnegative(),
  });

  const schema = z.object({
    title: z.string().min(3).optional(),
    description: z.string().optional(),
    breakdown: z.array(itemSchema).min(1).optional(),
  });

  const body = schema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  const current = await supabaseAdmin
    .from("proposals")
    .select("id, created_by, status")
    .eq("id", req.params.id)
    .single();

  if (current.error) return res.status(400).json({ error: current.error.message });
  if (current.data.created_by !== req.user.id)
    return res.status(403).json({ error: "Not your proposal" });
  if (current.data.status !== "pending")
    return res.status(400).json({ error: "Only pending proposals can be edited" });

  const updatePayload = { ...body.data };

  if (body.data.breakdown) {
    const requiredPerStudent = body.data.breakdown.reduce(
      (sum, it) => sum + Number(it.amount || 0),
      0
    );
    updatePayload.required_per_student = requiredPerStudent;
    updatePayload.budget_total = requiredPerStudent;
  }

  const { data, error } = await supabaseAdmin
    .from("proposals")
    .update(updatePayload)
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
    dean_comment: z.string().optional(),
  });

  const body = schema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  const { data, error } = await supabaseAdmin
    .from("proposals")
    .update({
      status: body.data.status,
      dean_comment: body.data.dean_comment ?? null,
      reviewed_by: req.user.id,
      reviewed_at: new Date().toISOString(),
    })
    .eq("id", req.params.id)
    .select("*")
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

/**
 * EVENTS (for students): approved proposals
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
    reference_no: z.string().optional(),
  });

  const body = schema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  const proposal = await supabaseAdmin
    .from("proposals")
    .select("id, status, required_per_student")
    .eq("id", body.data.proposal_id)
    .single();

  if (proposal.error) return res.status(400).json({ error: proposal.error.message });
  if (proposal.data.status !== "approved")
    return res.status(400).json({ error: "Event not available (not approved)" });

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
      reference_no: body.data.reference_no ?? null,
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
      receipt_no: rno.data,
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
 * Officer/President: view payments for a proposal
 * - Officer: only own proposals
 * - President: can view any proposal payments
 */
app.get(
  "/officer/proposals/:id/payments",
  requireAuth,
  requireRole("officer", "president"),
  async (req, res) => {
    if (req.user.role === "officer") {
      const pr = await supabaseAdmin
        .from("proposals")
        .select("id, created_by")
        .eq("id", req.params.id)
        .single();

      if (pr.error) return res.status(400).json({ error: pr.error.message });
      if (pr.data.created_by !== req.user.id)
        return res.status(403).json({ error: "Not your proposal" });
    }

    const { data, error } = await supabaseAdmin
      .from("payments")
      .select(`
        id, proposal_id, student_id, amount, method, reference_no, paid_at,
        receipts ( receipt_no ),
        student:profiles!payments_student_id_fkey (
          id, full_name, first_name, middle_name, last_name, course, year_level
        )
      `)
      .eq("proposal_id", req.params.id)
      .order("paid_at", { ascending: false });

    if (error) return res.status(400).json({ error: error.message });
    res.json(data);
  }
);

/**
 * REPORTS
 * Dean/President: department-level totals
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
      required_per_student: toNum(pr.required_per_student),
    };
  });

  res.json(rows);
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`DBMS-backend running on port ${PORT}`));