import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "SafeMirror",
  description: "Enterprise package security scanning platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
