import { useState, useCallback } from 'react';
import axios from 'axios';
import MessageList from './MessageList';
import ChatInput from './ChatInput';

const BACKEND_URL = 'http://127.0.0.1:8000/nlp?session_id=chat1';

export default function ChatContainer({ soundEnabled }) {
  const [chat, setChat] = useState([]);
  const [isTyping, setIsTyping] = useState(false);

  const sendMessage = useCallback(
    async (text) => {
      const userMessage = {
        role: 'user',
        text,
        timestamp: Date.now(),
      };
      setChat((prev) => [...prev, userMessage]);
      setIsTyping(true);

      try {
        const response = await axios.post(BACKEND_URL, { query: text });

        const botMessage = {
          role: 'bot',
          text: response.data.summary
            ? `${response.data.summary}\n\nMITRE: ${
                response.data.events?.[0]?.mitre_technique || 'N/A'
              }`
            : JSON.stringify(response.data, null, 2),
          timestamp: Date.now(),
        };

        setChat((prev) => [...prev, botMessage]);

        // Optional: play send sound
        if (soundEnabled) {
          try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            oscillator.frequency.value = 800;
            oscillator.type = 'sine';
            gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.1);
            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.1);
          } catch {
            /* ignore audio errors */
          }
        }
      } catch (error) {
        setChat((prev) => [
          ...prev,
          {
            role: 'bot',
            text: 'Error connecting to backend.',
            timestamp: Date.now(),
          },
        ]);
      } finally {
        setIsTyping(false);
      }
    },
    [soundEnabled]
  );

  return (
    <div className="flex flex-col flex-1 min-h-0 w-full max-w-3xl mx-auto bg-black/20 rounded-lg border border-cyber-green/20 overflow-hidden shadow-[0_0_30px_rgba(0,255,136,0.08)]">
      <MessageList messages={chat} isTyping={isTyping} />
      <ChatInput onSend={sendMessage} disabled={isTyping} />
    </div>
  );
}
