export default function NotFound() {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex items-center justify-center p-6">
      <div className="text-center space-y-4 max-w-md">
        <h1 className="text-4xl font-mono font-bold text-emerald-400">404</h1>
        <h2 className="text-lg font-semibold">Endpoint Not Found</h2>
        <p className="text-sm text-zinc-400">
          The requested path does not exist on this cryptographic verification workbench.
        </p>
        <a
          href="/"
          className="inline-block px-4 py-2 text-xs font-mono rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/20"
        >
          Return to Workbench
        </a>
      </div>
    </div>
  );
}
