import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Aegis • Privacy-Preserving Identity & Security Engine",
  description:
    "High-assurance Privacy-Preserving Identity and Security engine with zero PII retention, Merkle receipts, and SIMD Blake3 evaluation. Engineered by Rony M. (@ronderins).",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,400;0,500;0,700;1,400&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="bg-zinc-950 text-zinc-100 antialiased font-sans">
        {children}
      </body>
    </html>
  );
}
