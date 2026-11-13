import { useState } from 'react';
import ChatContainer from './components/ChatContainer';
import './App.css';

function App() {
  const [soundEnabled, setSoundEnabled] = useState(false);

  return (
    <div className="h-screen flex flex-col bg-cyber-bg bg-grid-pattern noise-overlay scanline-overlay font-mono">
      {/* Header */}
      <header className="flex-shrink-0 flex items-center justify-between px-6 py-4 border-b border-cyber-green/20 bg-black/30">
        <h1 className="text-lg font-semibold tracking-wider text-cyber-green">
          ANALYST TERMINAL
        </h1>
        <div className="flex items-center gap-4">
          <button
            type="button"
            onClick={() => setSoundEnabled((s) => !s)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium border transition-all
              ${soundEnabled
                ? 'bg-cyber-green/20 border-cyber-green/50 text-cyber-green hover:shadow-neon-sm'
                : 'bg-transparent border-slate-500/50 text-slate-500 hover:border-slate-400'
              }`}
            title={soundEnabled ? 'Sound on' : 'Sound off'}
          >
            <span className="text-sm">{soundEnabled ? '🔊' : '🔇'}</span>
            {soundEnabled ? 'ON' : 'OFF'}
          </button>
          <div className="flex items-center gap-2 text-cyber-green/90">
            <span className="w-2 h-2 rounded-full bg-cyber-green animate-pulse" />
            <span className="text-xs font-medium tracking-wider">CONNECTED</span>
          </div>
        </div>
      </header>

      {/* Chat area - full remaining height */}
      <main className="flex-1 flex flex-col min-h-0 p-4 md:p-6">
        <ChatContainer soundEnabled={soundEnabled} />
      </main>
    </div>
  );
}

export default App;
