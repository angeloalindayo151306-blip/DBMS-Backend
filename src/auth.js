import { supabaseAdmin } from "./supabase.js";

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
      .select("role, full_name, officer_title")
      .eq("id", userId)
      .single();

    if (prof.error || !prof.data) {
      return res.status(403).json({ error: "Profile not found" });
    }

    req.user = {
      id: userId,
      role: prof.data.role,
      full_name: prof.data.full_name,
      officer_title: prof.data.officer_title ?? null
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