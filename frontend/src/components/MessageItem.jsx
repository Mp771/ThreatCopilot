export default function MessageItem({ role, text, timestamp }) {
  const isUser = role === 'user';
  const timeStr = timestamp
    ? new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : '';

  return (
    <div
      className={`animate-fade-in flex ${isUser ? 'justify-end' : 'justify-start'} mb-4`}
    >
      <div
        className={`max-w-[80%] rounded px-4 py-3 font-mono text-sm ${
          isUser
            ? 'bg-cyber-green/10 border border-cyber-green/30 text-cyber-green/90'
            : 'bg-slate-800/60 border border-cyber-cyan/20 text-slate-200'
        }`}
      >
        {!isUser && (
          <span className="text-cyber-cyan text-xs block mb-1 font-medium">
            ANALYST
          </span>
        )}
        <div className="whitespace-pre-wrap break-words">{text}</div>
        {timeStr && (
          <span className={`text-xs mt-2 block ${isUser ? 'text-cyber-green/60' : 'text-slate-500'}`}>
            {timeStr}
          </span>
        )}
      </div>
    </div>
  );
}
