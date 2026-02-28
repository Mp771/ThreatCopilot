export default function Timeline({ events }) {

  if (!events || events.length === 0) return null;

  return (
    <div className="mt-6 border border-cyber-green/30 rounded p-4 bg-black/40">
      <h2 className="text-cyber-green font-mono mb-4">Attack Timeline</h2>

      <div className="space-y-3">
        {events.map((e, i) => (
          <div key={i} className="flex gap-4 font-mono text-sm">
            <span className="text-cyber-cyan">{e.time}</span>

            <span className="text-white">{e.event}</span>

            {e.ip && (
              <span className="text-red-400">
                {e.ip}
              </span>
            )}

            {e.mitre && (
              <span className="text-yellow-400">
                {e.mitre}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}