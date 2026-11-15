/** Original Teger mark: a pixel shield with an ember gradient check. */
export function Mark({ size = 28 }: { size?: number }) {
  const px: [number, number, string][] = [];
  const rows = ["0111110", "1111111", "1111111", "1111111", "0111110", "0011100", "0001000"];
  const colors = ["#ef3b0b", "#ff6b00", "#ff9500", "#ffb703", "#ffd43b", "#ffb703", "#ff9500"];
  rows.forEach((r, y) => [...r].forEach((c, x) => { if (c === "1") px.push([x, y, colors[y]]); }));
  return (
    <svg width={size} height={size} viewBox="-0.5 -0.5 8 8" aria-hidden>
      {px.map(([x, y, c]) => <rect key={`${x}-${y}`} x={x} y={y} width="0.9" height="0.9" fill={c} />)}
      <path d="M1.9 3.2 L3 4.2 L5.2 1.9" fill="none" stroke="#1a1714" strokeWidth="0.75" strokeLinecap="square" />
    </svg>
  );
}

export function Logo({ href = "/" }: { href?: string }) {
  return (
    <a href={href} className="logo"><Mark /> Teger <small>Agent</small></a>
  );
}

export function Pixels({ sm }: { sm?: boolean }) {
  return <span className={`pixels ${sm ? "sm" : ""}`} aria-hidden><i /><i /><i /><i /><i /></span>;
}

/** Large animated pixel shield for hero/sign-in art. */
export function PixelShield() {
  const rows = [
    "000111111000", "011111111110", "111111111111", "111111111111", "111111111111", "111111111111",
    "011111111110", "011111111110", "001111111100", "000111111000", "000011110000", "000001100000",
  ];
  const colors = ["#ef3b0b", "#f4490a", "#ff6b00", "#ff7f00", "#ff9500", "#ffa600", "#ffb703", "#ffc61f", "#ffd43b", "#ffc61f", "#ffb703", "#ff9500"];
  const checkPx = new Set(["3-5", "4-6", "5-7", "6-6", "7-5", "8-4", "9-3", "4-5", "5-6", "6-5", "7-4", "8-3"]);
  return (
    <svg className="px-shield hero-art" viewBox="-1 -1 14 14" role="img" aria-label="Teger pixel shield">
      {rows.flatMap((r, y) => [...r].map((c, x) => c === "1" ? (
        <rect key={`${x}-${y}`} x={x} y={y} width="0.88" height="0.88" rx="0.08" fill={checkPx.has(`${x}-${y}`) ? "var(--ink)" : colors[y]} style={{ animationDelay: `${(x + y) * 28}ms` }} />
      ) : null))}
    </svg>
  );
}
