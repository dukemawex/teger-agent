import type { Metadata, Viewport } from "next";
import { Inter, Space_Grotesk } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" });
const grotesk = Space_Grotesk({ subsets: ["latin"], variable: "--font-grotesk", weight: ["500", "700"], display: "swap" });

export const metadata: Metadata = {
  title: "Teger Agent: phishing & social-engineering defense, built on SERV Reasoning",
  description: "An autonomous agent that investigates suspicious emails with SERV Reasoning and a deterministic security engine. Built by DUKERS LTD for the OpenServ SERV Hackathon 02 (Open Track).",
  openGraph: { title: "Teger Agent", description: "Autonomous phishing & social-engineering defense, built on SERV Reasoning." },
};

export const viewport: Viewport = { themeColor: [{ media: "(prefers-color-scheme: light)", color: "#fbf7f0" }, { media: "(prefers-color-scheme: dark)", color: "#12100e" }] };

const themeScript = `try{var t=localStorage.getItem('teger_theme');if(!t){t=matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'}document.documentElement.dataset.theme=t}catch(e){}`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${grotesk.variable}`} suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
