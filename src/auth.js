import { supabaseAdmin } from "./supabase.js";

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

export async function requireAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing bearer token" });

    const { data, error } = await supabaseAdmin.auth.getUser(token);
    if (error || !data?.user) return res.status(401).json({ error: "Invalid token" });

    const userId = data.user.id;

    const prof = await supabaseAdmin
      .from("profiles")
      .select(`
        role,
        full_name,
        officer_title,
        first_name,
        middle_name,
        last_name,
        date_of_birth,
        age,
        address,
        mobile_number,
        course,
        year_level
      `)
      .eq("id", userId)
      .single();

    if (prof.error || !prof.data) return res.status(403).json({ error: "Profile not found" });

    // If age is missing but DOB exists, compute it (helps old rows)
    const computedAge = prof.data.age ?? calcAge(prof.data.date_of_birth);

    req.user = {
      id: userId,
      email: data.user.email ?? null,

      role: prof.data.role,
      full_name: prof.data.full_name,
      officer_title: prof.data.officer_title ?? null,

      first_name: prof.data.first_name ?? null,
      middle_name: prof.data.middle_name ?? null,
      last_name: prof.data.last_name ?? null,

      date_of_birth: prof.data.date_of_birth ?? null,
      age: computedAge ?? null,
      address: prof.data.address ?? null,
      mobile_number: prof.data.mobile_number ?? null,

      course: prof.data.course ?? null,
      year_level: prof.data.year_level ?? null,
    };

    next();
  } catch (e) {
    res.status(500).json({ error: "Auth failed" });
  }
}

export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user?.role || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}