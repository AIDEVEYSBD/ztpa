/**
 * Grain and cast, applied once behind the entire app and never per panel.
 * Both layers are achromatic: a single top-down light cast plus a fractal
 * noise texture. No hue, no bloom, no gradient you could point at.
 */
export function Material() {
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 z-0 select-none">
      <div className="material-cast absolute inset-0" />
      <svg className="material-grain absolute inset-0 h-full w-full">
        <filter id="af-grain">
          <feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="4" stitchTiles="stitch" />
          <feColorMatrix type="saturate" values="0" />
        </filter>
        <rect width="100%" height="100%" filter="url(#af-grain)" />
      </svg>
    </div>
  );
}

/**
 * Denser, steel-tinted grain for the 48px header bar only. Text sitting over
 * it uses `text-on-grain` (pure black or white), never a ramp value.
 */
export function SurfaceGrain() {
  return (
    <svg aria-hidden className="material-grain-chrome pointer-events-none absolute inset-0 h-full w-full select-none">
      <filter id="af-grain-chrome">
        <feTurbulence type="fractalNoise" baseFrequency="0.45" numOctaves="2" stitchTiles="stitch" />
        <feColorMatrix
          type="matrix"
          values="0.945 0 0 0 0  0 0.965 0 0 0  0 0 1 0 0  0 0 0 1 0"
        />
        <feComponentTransfer>
          <feFuncR type="linear" slope="2.2" intercept="-0.6" />
          <feFuncG type="linear" slope="2.2" intercept="-0.6" />
          <feFuncB type="linear" slope="2.2" intercept="-0.6" />
        </feComponentTransfer>
      </filter>
      <rect width="100%" height="100%" filter="url(#af-grain-chrome)" />
    </svg>
  );
}
