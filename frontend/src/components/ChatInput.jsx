import { useState, useCallback } from 'react';

export default function ChatInput({ onSend, disabled }) {
  const [message, setMessage] = useState('');

  const handleSubmit = useCallback(() => {
    const trimmed = message.trim();
    if (!trimmed || disabled) return;
    onSend(trimmed);
    setMessage('');
  }, [message, onSend, disabled]);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const handleChange = (e) => {
    setMessage(e.target.value);
    // Auto-resize textarea
    const textarea = e.target;
    textarea.style.height = 'auto';
    textarea.style.height = `${Math.min(textarea.scrollHeight, 120)}px`;
  };

  return (
    <div className="flex items-end gap-2 p-4 bg-cyber-bg/80 border-t border-cyber-green/20">
      <div className="flex-1 relative">
        <span className="absolute left-3 top-3 font-mono text-cyber-green text-sm pointer-events-none flex items-center">
          &gt;_{message ? '' : <span className="animate-blink ml-0.5">|</span>}
        </span>
        <textarea
          value={message}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          placeholder="Ask about threats..."
          disabled={disabled}
          rows={1}
          className="w-full pl-10 pr-4 py-3 bg-black/40 border border-cyber-green/30 rounded 
            font-mono text-sm text-slate-200 placeholder-slate-500 resize-none
            focus:outline-none focus:border-cyber-green/60 focus:shadow-neon-sm
            disabled:opacity-50 disabled:cursor-not-allowed
            transition-all duration-200 min-h-[48px] max-h-[120px]"
          style={{ caretColor: '#00ff88' }}
        />
      </div>
      <button
        type="button"
        onClick={handleSubmit}
        disabled={!message.trim() || disabled}
        className="px-6 py-3 font-mono text-sm font-medium bg-cyber-green/20 text-cyber-green 
          border border-cyber-green/50 rounded hover:bg-cyber-green/30 hover:shadow-neon-sm
          disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-cyber-green/20
          transition-all duration-200"
      >
        SEND
      </button>
    </div>
  );
}
