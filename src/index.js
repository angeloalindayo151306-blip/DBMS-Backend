import "dotenv/config";
import express from "express";
import cors from "cors";
import multer from "multer";
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
 * Upload (receipt image) - Option 1 (multer)
 */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const ok =
      file.mimetype === "image/jpeg" ||
      file.mimetype === "image/png" ||
      file.mimetype === "image/webp";
    if (!ok) return cb(new Error("Only JPG/PNG/WEBP images are allowed."));
    cb(null, true);
  },
});

// Multer error handler (so errors return JSON)
app.use((err, req, res, next) => {
  if (err?.message?.includes("Only JPG/PNG/WEBP")) {
    return res.status(400).json({ error: err.message });
  }
  if (err?.code === "LIMIT_FILE_SIZE") {
    return res.status(400).json({ error: "File too large. Max 5MB." });
  }
  next(err);
});

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
 * Officer titles
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
  res.json(req.user);
});

/**
 * ACCOUNTS
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
      created_by: req.user.id,
    },
    { onConflict: "id" }
  );

  if (prof.error) {
    await supabaseAdmin.auth.admin.deleteUser(userId);
    return res.status(400).json({ error: prof.error.message });
  }

  res.json({ id: userId, email: body.data.email, role: "dean", full_name });
});

app.post("/accounts/students", requireAuth, requireRole("dean", "president"), async (req, res) => {
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
});

app.post("/accounts/officers", requireAuth, requireRole("dean", "president"), async (req, res) => {
  const schema = z
    .object({
      email: z.string().email(),
      password: z.string().min(6),
      officer_title: OfficerTitleEnum,
    })
    .and(baseProfileSchema);

  const body = schema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  if (req.user.role === "president" && body.data.officer_title === "President") {
    return res.status(403).json({ error: "President cannot create another President account." });
  }

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
      created_by: req.user.id,
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
});

/**
 * LIST ACCOUNTS
 */
app.get("/accounts", requireAuth, requireRole("dean", "president"), async (req, res) => {
  try {
    const roleFilter = (req.query.role || "").toString();
    const qText = (req.query.q || "").toString().trim();
    const includeDisabled = String(req.query.include_disabled || "") === "true";

    let q = supabaseAdmin
      .from("profiles")
      .select(
        `
        id,
        ccs_id_no,
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
      `
      )
      .order("full_name", { ascending: true });

    if (req.user.role === "president") {
      q = q.in("role", ["student", "officer"]);
    }

    if (roleFilter && roleFilter !== "all") {
      if (req.user.role === "president" && !["student", "officer"].includes(roleFilter)) {
        return res.status(403).json({ error: "Not allowed to view this role." });
      }
      q = q.eq("role", roleFilter);
    }

    if (qText) q = q.ilike("full_name", `%${qText}%`);

    const { data: profiles, error } = await q;
    if (error) return res.status(400).json({ error: error.message });

    const withEmail = await Promise.all(
      (profiles || []).map(async (p) => {
        const r = await supabaseAdmin.auth.admin.getUserById(p.id);
        const user = r?.data?.user;
        if (!user?.email) return null;

        const bannedUntil = user.banned_until ? new Date(user.banned_until) : null;
        const isBanned = bannedUntil && bannedUntil > new Date();

        if (isBanned && !includeDisabled) return null;

        return {
          ...p,
          email: user.email,
          disabled: !!isBanned,
          banned_until: user.banned_until ?? null,
        };
      })
    );

    res.json(withEmail.filter(Boolean));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/**
 * UPDATE ACCOUNT
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

    new_password: z.string().min(6).optional(),
  });

  const body = patchSchema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  try {
    const id = req.params.id;

    const current = await supabaseAdmin
      .from("profiles")
      .select(`id, role, first_name, middle_name, last_name, date_of_birth, officer_title`)
      .eq("id", id)
      .single();

    if (current.error) return res.status(400).json({ error: current.error.message });

    const targetRole = current.data.role;

    if (req.user.role === "president" && !["student", "officer"].includes(targetRole)) {
      return res.status(403).json({ error: "President can only edit Student and Officer accounts." });
    }

    if (req.user.role === "president" && body.data.officer_title === "President") {
      return res.status(403).json({ error: "President cannot set officer_title to President." });
    }

    const updatePayload = { ...body.data };
    delete updatePayload.new_password;

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

    const nextDob =
      body.data.date_of_birth !== undefined ? body.data.date_of_birth : current.data.date_of_birth;

    if (body.data.date_of_birth !== undefined) {
      updatePayload.age = calcAge(nextDob);
    }

    if (body.data.officer_title !== undefined) {
      const newTitle = body.data.officer_title;

      if (newTitle === "President") {
        if (req.user.role !== "dean") {
          return res.status(403).json({ error: "Only Dean can assign President officer_title." });
        }
        updatePayload.role = "president";
      }

      if (targetRole === "president" && newTitle !== "President") {
        if (req.user.role !== "dean") {
          return res.status(403).json({ error: "Only Dean can modify President account title/role." });
        }
        updatePayload.role = "officer";
      }
    }

    const updated = await supabaseAdmin.from("profiles").update(updatePayload).eq("id", id).select("*").single();
    if (updated.error) return res.status(400).json({ error: updated.error.message });

    if (body.data.new_password) {
      const pw = await supabaseAdmin.auth.admin.updateUserById(id, { password: body.data.new_password });
      if (pw.error) return res.status(400).json({ error: pw.error.message });
    }

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
 * DISABLE / ENABLE
 */
app.delete("/accounts/:id", requireAuth, requireRole("dean", "president"), async (req, res) => {
  try {
    const id = req.params.id;

    if (id === req.user.id) {
      return res.status(400).json({ error: "You cannot disable your own account." });
    }

    const target = await supabaseAdmin.from("profiles").select("id, role").eq("id", id).single();
    if (target.error) return res.status(400).json({ error: target.error.message });

    const targetRole = target.data.role;

    if (req.user.role === "president" && !["student", "officer"].includes(targetRole)) {
      return res.status(403).json({ error: "President can only disable Student and Officer accounts." });
    }

    const ban = await supabaseAdmin.auth.admin.updateUserById(id, { ban_duration: "876000h" });
    if (ban.error) return res.status(400).json({ error: ban.error.message });

    res.json({
      ok: true,
      disabled_user_id: id,
      banned_until: ban.data?.user?.banned_until ?? null,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch("/accounts/:id/enable", requireAuth, requireRole("dean", "president"), async (req, res) => {
  try {
    const id = req.params.id;

    const target = await supabaseAdmin.from("profiles").select("id, role").eq("id", id).single();
    if (target.error) return res.status(400).json({ error: target.error.message });

    const targetRole = target.data.role;

    if (req.user.role === "president" && !["student", "officer"].includes(targetRole)) {
      return res.status(403).json({ error: "President can only enable Student and Officer accounts." });
    }

    const unban = await supabaseAdmin.auth.admin.updateUserById(id, { ban_duration: "none" });
    if (unban.error) return res.status(400).json({ error: unban.error.message });

    res.json({ ok: true, enabled_user_id: id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/**
 * PROPOSALS (with creator info)
 */
app.get("/proposals", requireAuth, async (req, res) => {
  const status = req.query.status;

  let q = supabaseAdmin
    .from("proposals")
    .select("*")
    .order("created_at", { ascending: false });

  // Students see approved only
  if (req.user.role === "student") {
    q = q.eq("status", "approved");
  } else {
    // Officer/President/Dean can optionally filter by status
    if (status) q = q.eq("status", status);
  }

  const { data, error } = await q;
  if (error) return res.status(400).json({ error: error.message });

  const proposals = data || [];

  // Collect unique created_by IDs
  const creatorIds = [...new Set(proposals.map((p) => p.created_by).filter(Boolean))];

  // Fetch creator profiles (names/titles)
  let creatorsMap = new Map();
  if (creatorIds.length) {
    const creators = await supabaseAdmin
      .from("profiles")
      .select("id, full_name, first_name, middle_name, last_name, role, officer_title, ccs_id_no")
      .in("id", creatorIds);

    if (creators.error) return res.status(400).json({ error: creators.error.message });

    creatorsMap = new Map((creators.data || []).map((c) => [c.id, c]));
  }

  // Attach creator object
  const enriched = proposals.map((p) => ({
    ...p,
    creator: p.created_by ? creatorsMap.get(p.created_by) || null : null,
  }));

  res.json(enriched);
});

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

  const requiredPerStudent = body.data.breakdown.reduce((sum, it) => sum + Number(it.amount || 0), 0);

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
  if (current.data.created_by !== req.user.id) return res.status(403).json({ error: "Not your proposal" });
  if (current.data.status !== "pending") return res.status(400).json({ error: "Only pending proposals can be edited" });

  const updatePayload = { ...body.data };

  if (body.data.breakdown) {
    const requiredPerStudent = body.data.breakdown.reduce((sum, it) => sum + Number(it.amount || 0), 0);
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
 * EVENTS (students)
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
 * Officer/President: proposal payments (includes student.ccs_id_no)
 */
app.get("/officer/proposals/:id/payments", requireAuth, requireRole("officer", "president"), async (req, res) => {
  const proposalId = req.params.id;

  const { data, error } = await supabaseAdmin
    .from("payments")
    .select(
      `
      id,
      proposal_id,
      student_id,
      amount,
      method,
      reference_no,
      paid_at,
      receipts(*),
      student:profiles (
        id,
        ccs_id_no,
        first_name,
        middle_name,
        last_name,
        full_name,
        course,
        year_level
      )
    `
    )
    .eq("proposal_id", proposalId)
    .order("paid_at", { ascending: false });

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});


// =======================================================
// EXPENSES (NEW MODULE) - record-only + receipt + dean approval
// =======================================================

/**
 * Create expense (Officer/President)
 * record-only: no edit/delete endpoints
 */
app.post("/expenses", requireAuth, requireRole("officer", "president"), async (req, res) => {
  const schema = z.object({
    proposal_id: z.string().uuid().nullable().optional(),
    item_name: z.string().min(2),
    qty: z.number().int().positive().nullable().optional(),
    amount: z.number().positive(),
    spent_at: z.string().datetime().optional(), // optional
    notes: z.string().nullable().optional(),
  });

  const body = schema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  const { data, error } = await supabaseAdmin
    .from("expenses")
    .insert({
      proposal_id: body.data.proposal_id ?? null,
      spent_by: req.user.id,
      item_name: body.data.item_name,
      qty: body.data.qty ?? null,
      amount: body.data.amount,
      spent_at: body.data.spent_at ?? new Date().toISOString(),
      notes: body.data.notes ?? null,
      status: "pending",
    })
    .select("*")
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

/**
 * Upload receipt image (Officer/President)
 * - only the creator (spent_by) can upload
 * - only allowed while status is pending
 */
app.post(
  "/expenses/:id/receipt",
  requireAuth,
  requireRole("officer", "president"),
  upload.single("receipt"),
  async (req, res) => {
    try {
      const expenseId = req.params.id;

      if (!req.file) return res.status(400).json({ error: "Missing receipt file (field name: receipt)" });

      const exp = await supabaseAdmin
        .from("expenses")
        .select("id, spent_by, status")
        .eq("id", expenseId)
        .single();

      if (exp.error) return res.status(400).json({ error: exp.error.message });
      if (!exp.data) return res.status(404).json({ error: "Expense not found" });

      if (String(exp.data.spent_by) !== String(req.user.id)) {
        return res.status(403).json({ error: "Only the expense creator can upload the receipt." });
      }

      if (exp.data.status !== "pending") {
        return res.status(400).json({ error: "Receipt upload is only allowed while expense is pending." });
      }

      const ext =
        req.file.mimetype === "image/png" ? "png" :
        req.file.mimetype === "image/webp" ? "webp" : "jpg";

      const path = `${expenseId}/${Date.now()}.${ext}`;

      const up = await supabaseAdmin.storage
        .from("expense-receipts")
        .upload(path, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: true,
        });

      if (up.error) return res.status(400).json({ error: up.error.message });

      const updated = await supabaseAdmin
        .from("expenses")
        .update({ receipt_path: path })
        .eq("id", expenseId)
        .select("*")
        .single();

      if (updated.error) return res.status(400).json({ error: updated.error.message });

      res.json({ ok: true, expense: updated.data });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
);

/**
 * List expenses (Officer/President/Dean)
 * Supports filters:
 * - ?proposal_id=UUID   (optional)
 * - ?status=pending|approved|rejected (optional)
 */
app.get("/expenses", requireAuth, requireRole("officer", "president", "dean"), async (req, res) => {
  try {
    const proposal_id = (req.query.proposal_id || "").toString().trim();
    const status = (req.query.status || "").toString().trim();

    let q = supabaseAdmin.from("expenses").select("*").order("spent_at", { ascending: false });

    if (proposal_id) q = q.eq("proposal_id", proposal_id);
    if (status) q = q.eq("status", status);

    const { data, error } = await q;
    if (error) return res.status(400).json({ error: error.message });

    // Attach spender/reviewer/proposal info (without relying on ambiguous embedded joins)
    const rows = data || [];

    const spenderIds = [...new Set(rows.map((r) => r.spent_by).filter(Boolean))];
    const reviewerIds = [...new Set(rows.map((r) => r.reviewed_by).filter(Boolean))];
    const proposalIds = [...new Set(rows.map((r) => r.proposal_id).filter(Boolean))];

    const profilesMap = new Map();
    if (spenderIds.length || reviewerIds.length) {
      const allIds = [...new Set([...spenderIds, ...reviewerIds])];
      const prof = await supabaseAdmin
        .from("profiles")
        .select("id, ccs_id_no, role, full_name, officer_title, first_name, middle_name, last_name")
        .in("id", allIds);

      if (!prof.error) {
        for (const p of prof.data || []) profilesMap.set(p.id, p);
      }
    }

    const proposalsMap = new Map();
    if (proposalIds.length) {
      const prs = await supabaseAdmin.from("proposals").select("id, title, status").in("id", proposalIds);
      if (!prs.error) {
        for (const p of prs.data || []) proposalsMap.set(p.id, p);
      }
    }

    const out = rows.map((r) => ({
      ...r,
      spender: profilesMap.get(r.spent_by) || null,
      reviewer: r.reviewed_by ? profilesMap.get(r.reviewed_by) || null : null,
      proposal: r.proposal_id ? proposalsMap.get(r.proposal_id) || null : null,
    }));

    res.json(out);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/**
 * Dean approves/rejects expense
 */
app.patch("/expenses/:id/status", requireAuth, requireRole("dean"), async (req, res) => {
  const schema = z.object({
    status: z.enum(["approved", "rejected"]),
    dean_comment: z.string().optional(),
  });

  const body = schema.safeParse(req.body);
  if (!body.success) return res.status(400).json(body.error);

  const expenseId = req.params.id;

  const { data, error } = await supabaseAdmin
    .from("expenses")
    .update({
      status: body.data.status,
      dean_comment: body.data.dean_comment ?? null,
      reviewed_by: req.user.id,
      reviewed_at: new Date().toISOString(),
    })
    .eq("id", expenseId)
    .select("*")
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

/**
 * Get signed URL for receipt
 */
app.get("/expenses/:id/receipt-url", requireAuth, requireRole("officer", "president", "dean"), async (req, res) => {
  const expenseId = req.params.id;

  const exp = await supabaseAdmin.from("expenses").select("id, receipt_path").eq("id", expenseId).single();
  if (exp.error) return res.status(400).json({ error: exp.error.message });
  if (!exp.data) return res.status(404).json({ error: "Expense not found" });

  if (!exp.data.receipt_path) {
    return res.json({ signedUrl: null });
  }

  const signed = await supabaseAdmin.storage
    .from("expense-receipts")
    .createSignedUrl(exp.data.receipt_path, 60 * 30); // 30 minutes

  if (signed.error) return res.status(400).json({ error: signed.error.message });
  res.json({ signedUrl: signed.data.signedUrl });
});


// =======================================================
// REPORTS (UPDATED to include spending + net)
// =======================================================

/**
 * Department report per event
 * - student_count based on profiles.role='student'
 * - expected_total = required_per_student * student_count  (approved only)
 * - outstanding = expected_total - collected_total
 * - spent_total = sum(approved expenses with proposal_id)
 * - net_total = collected_total - spent_total
 */
app.get("/reports/department", requireAuth, requireRole("dean", "president"), async (req, res) => {
  // Count students
  const studentCountRes = await supabaseAdmin
    .from("profiles")
    .select("id", { count: "exact", head: true })
    .eq("role", "student");

  if (studentCountRes.error) {
    return res.status(400).json({ error: studentCountRes.error.message });
  }
  const student_count = studentCountRes.count || 0;

  // Proposals (include breakdown for details panel)
  const proposals = await supabaseAdmin
    .from("proposals")
    .select("id, title, status, description, breakdown, required_per_student, created_at, created_by, reviewed_at, reviewed_by, dean_comment")
    .order("created_at", { ascending: false });

  if (proposals.error) return res.status(400).json({ error: proposals.error.message });

  // Payments
  const payments = await supabaseAdmin.from("payments").select("proposal_id, amount");
  if (payments.error) return res.status(400).json({ error: payments.error.message });

  const collectedByProposal = new Map();
  for (const p of payments.data || []) {
    collectedByProposal.set(p.proposal_id, (collectedByProposal.get(p.proposal_id) || 0) + toNum(p.amount));
  }

  // Approved expenses per proposal
  const exp = await supabaseAdmin
    .from("expenses")
    .select("proposal_id, amount, status")
    .eq("status", "approved");

  if (exp.error) return res.status(400).json({ error: exp.error.message });

  const spentByProposal = new Map();
  let generalSpentApproved = 0;

  for (const e of exp.data || []) {
    const amt = toNum(e.amount);
    if (e.proposal_id) {
      spentByProposal.set(e.proposal_id, (spentByProposal.get(e.proposal_id) || 0) + amt);
    } else {
      generalSpentApproved += amt;
    }
  }

  const rows = (proposals.data || []).map((pr) => {
    const collected_total = collectedByProposal.get(pr.id) || 0;

    const fee_per_student = toNum(pr.required_per_student);
    const expected_total = pr.status === "approved" ? fee_per_student * student_count : 0;
    const remaining_budget = Math.max(expected_total - collected_total, 0);

    const spent_total = spentByProposal.get(pr.id) || 0;
    const net_total = collected_total - spent_total;

    return {
      proposal_id: pr.id,
      title: pr.title,
      status: pr.status,
      description: pr.description,
      breakdown: pr.breakdown,
      created_at: pr.created_at,
      created_by: pr.created_by,
      reviewed_at: pr.reviewed_at,
      reviewed_by: pr.reviewed_by,
      dean_comment: pr.dean_comment,

      student_count,

      // naming clarity:
      required_per_student: fee_per_student,

      // keep these keys for your existing UI:
      budget_total: expected_total,
      collected_total,
      remaining_budget,

      // NEW fields:
      spent_total,
      net_total,
    };
  });

  res.json(rows);
});

/**
 * Summary totals (ALL events) including general spending
 * Useful for Dean dashboard cards.
 */
app.get("/reports/summary", requireAuth, requireRole("dean", "president"), async (req, res) => {
  // Count students
  const studentCountRes = await supabaseAdmin
    .from("profiles")
    .select("id", { count: "exact", head: true })
    .eq("role", "student");

  if (studentCountRes.error) return res.status(400).json({ error: studentCountRes.error.message });
  const student_count = studentCountRes.count || 0;

  const payments = await supabaseAdmin.from("payments").select("amount");
  if (payments.error) return res.status(400).json({ error: payments.error.message });

  const total_collected_all = (payments.data || []).reduce((s, r) => s + toNum(r.amount), 0);

  const expensesApproved = await supabaseAdmin.from("expenses").select("proposal_id, amount, status").eq("status", "approved");
  if (expensesApproved.error) return res.status(400).json({ error: expensesApproved.error.message });

  let total_spent_event = 0;
  let total_spent_general = 0;

  for (const e of expensesApproved.data || []) {
    if (e.proposal_id) total_spent_event += toNum(e.amount);
    else total_spent_general += toNum(e.amount);
  }

  const cash_on_hand = total_collected_all - total_spent_event - total_spent_general;

  // pending expenses count
  const pendingExpensesRes = await supabaseAdmin
    .from("expenses")
    .select("id", { count: "exact", head: true })
    .eq("status", "pending");

  const pending_expenses = pendingExpensesRes.count || 0;

  res.json({
    student_count,
    total_collected_all,
    total_spent_event,
    total_spent_general,
    cash_on_hand,
    pending_expenses,
  });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`DBMS-backend running on port ${PORT}`));