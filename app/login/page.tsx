"use client";

import { FormEvent, useState } from "react";

// Constante pour la maintenabilité (à synchroniser avec le backend si possible)
const MAGIC_LINK_EXPIRY_MINUTES = 10;

// Validation d'email robuste côté client
const isValidEmail = (email: string): boolean => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");

    const cleanEmail = email.trim().toLowerCase();

    if (!cleanEmail || !isValidEmail(cleanEmail)) {
      setError("Veuillez entrer une adresse e-mail professionnelle valide.");
      return;
    }

    setLoading(true);

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

      const response = await fetch(`${apiUrl}/api/auth/magic-link`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: cleanEmail,
        }),
      });

      if (!response.ok) {
        throw new Error("Impossible d'envoyer le lien de connexion.");
      }

      setSent(true);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Une erreur est survenue. Veuillez réessayer."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#07090d] text-white">
      <div className="flex min-h-screen">

        {/* LEFT — PRODUCT / BRAND */}
        <section className="relative hidden w-1/2 overflow-hidden border-r border-white/10 lg:flex">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,rgba(239,68,68,0.13),transparent_35%),radial-gradient(circle_at_70%_80%,rgba(255,255,255,0.04),transparent_35%)]" />

          <div className="relative z-10 flex w-full flex-col justify-between p-12 xl:p-16">

            {/* Logo */}
            <div>
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-red-500/30 bg-red-500/10">
                  <span className="text-lg" aria-hidden="true">🛡</span>
                </div>

                <span className="text-lg font-semibold tracking-tight">
                  CERBERE
                </span>
              </div>
            </div>

            {/* Main message */}
            <div className="max-w-xl">
              <div className="mb-5 inline-flex items-center rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-gray-400">
                AI Runtime Security
              </div>

              <h1 className="text-4xl font-semibold leading-tight tracking-tight xl:text-5xl">
                Control what your
                <br />
                AI agents can do.
              </h1>

              <p className="mt-6 max-w-lg text-base leading-7 text-gray-400">
                Observe agent activity, detect threats, enforce policies,
                and audit every critical action before it reaches your tools
                and APIs.
              </p>

              {/* Security flow */}
              <div className="mt-10 flex flex-wrap items-center gap-2 text-xs">
                {[
                  "IDENTITY",
                  "CONTEXT",
                  "DETECTION",
                  "RISK",
                  "POLICY",
                  "ENFORCEMENT",
                ].map((item, index) => (
                  <div key={item} className="flex items-center gap-2">
                    <span className="rounded-md border border-white/10 bg-white/[0.03] px-2.5 py-1.5 text-gray-400">
                      {item}
                    </span>

                    {index < 5 && (
                      <span className="text-gray-700" aria-hidden="true">→</span>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Footer */}
            <div className="text-xs text-gray-600">
              © {new Date().getFullYear()} Cerbere
            </div>
          </div>
        </section>

        {/* RIGHT — LOGIN */}
        <section className="flex w-full items-center justify-center px-6 py-12 lg:w-1/2">
          <div className="w-full max-w-md">

            {/* Mobile logo */}
            <div className="mb-12 flex items-center justify-center lg:hidden">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-red-500/30 bg-red-500/10">
                  <span className="text-lg" aria-hidden="true">🛡</span>
                </div>

                <span className="text-lg font-semibold">
                  CERBERE
                </span>
              </div>
            </div>

            {!sent ? (
              <>
                <div className="mb-8">
                  <h2 className="text-3xl font-semibold tracking-tight">
                    Sign in to Cerbere
                  </h2>

                  <p className="mt-3 text-sm leading-6 text-gray-500">
                    Access your security control plane and monitor your
                    AI agents.
                  </p>
                </div>

                <form onSubmit={handleSubmit} className="space-y-5" noValidate>
                  <div>
                    <label
                      htmlFor="email"
                      className="mb-2 block text-sm font-medium text-gray-300"
                    >
                      Work email
                    </label>

                    <input
                      id="email"
                      name="email"
                      type="email"
                      autoComplete="email"
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck={false}
                      placeholder="you@company.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      disabled={loading}
                      aria-invalid={!!error}
                      aria-describedby={error ? "email-error" : undefined}
                      className="h-12 w-full rounded-lg border border-white/10 bg-white/[0.03] px-4 text-sm text-white outline-none transition placeholder:text-gray-600 focus:border-red-500/60 focus:bg-white/[0.05] disabled:cursor-not-allowed disabled:opacity-50"
                    />
                  </div>

                  {error && (
                    <div 
                      id="email-error"
                      role="alert" 
                      aria-live="polite"
                      className="rounded-lg border border-red-500/20 bg-red-500/5 px-4 py-3 text-sm text-red-400"
                    >
                      {error}
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={loading}
                    aria-busy={loading}
                    className="h-12 w-full rounded-lg bg-white px-4 text-sm font-semibold text-black transition hover:bg-gray-200 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {loading ? (
                      <span className="flex items-center justify-center gap-2">
                        <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                        </svg>
                        Sending link...
                      </span>
                    ) : (
                      "Continue with email"
                    )}
                  </button>
                </form>

                <div className="my-8 flex items-center gap-4">
                  <div className="h-px flex-1 bg-white/10" />
                  <span className="text-xs text-gray-600">
                    Enterprise
                  </span>
                  <div className="h-px flex-1 bg-white/10" />
                </div>

                <button
                  type="button"
                  className="h-12 w-full rounded-lg border border-white/10 bg-transparent px-4 text-sm font-medium text-gray-300 transition hover:bg-white/[0.04]"
                >
                  Sign in with SSO
                </button>

                <p className="mt-8 text-center text-xs leading-5 text-gray-600">
                  By continuing, you agree to Cerbere&apos;s terms and
                  security policies.
                </p>
              </>
            ) : (
              /* MAGIC LINK SENT */
              <div className="text-center">
                <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full border border-white/10 bg-white/[0.03]">
                  <span className="text-2xl" aria-hidden="true">✉</span>
                </div>

                <h2 className="text-3xl font-semibold tracking-tight">
                  Check your inbox
                </h2>

                <p className="mx-auto mt-4 max-w-sm text-sm leading-6 text-gray-500">
                  We sent a secure sign-in link to
                </p>

                <p className="mt-2 break-all text-sm font-medium text-white">
                  {email}
                </p>

                <div className="mt-8 rounded-lg border border-white/10 bg-white/[0.03] p-4 text-left">
                  <p className="text-xs leading-5 text-gray-500">
                    The link is single-use and expires in{" "}
                    <span className="font-medium text-gray-300">
                      {MAGIC_LINK_EXPIRY_MINUTES} minutes
                    </span>
                    .
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => {
                    setSent(false);
                    setError("");
                    setEmail(""); // Reset email for better UX
                  }}
                  className="mt-8 text-sm text-gray-500 transition hover:text-white"
                >
                  Use another email
                </button>
              </div>
            )}

            {/* Security indicator */}
            <div className="mt-12 flex items-center justify-center gap-2 text-xs text-gray-600">
              <span className="h-1.5 w-1.5 rounded-full bg-green-500" aria-hidden="true" />
              Secure authentication
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
