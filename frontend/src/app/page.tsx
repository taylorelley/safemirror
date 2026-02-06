"use client";

import { useEffect, useState } from "react";

interface HealthStatus {
  status: string;
  version: string;
}

export default function Home() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${process.env.NEXT_PUBLIC_API_URL ?? ""}/health`)
      .then((res) => res.json())
      .then(setHealth)
      .catch((e) => setError(e.message));
  }, []);

  return (
    <main style={{ padding: "2rem", fontFamily: "system-ui, sans-serif" }}>
      <h1>SafeMirror</h1>
      <p>Enterprise package security scanning platform</p>
      {error && <p style={{ color: "red" }}>API error: {error}</p>}
      {health && (
        <p>
          API status: <strong>{health.status}</strong> (v{health.version})
        </p>
      )}
    </main>
  );
}
