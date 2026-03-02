import { useState, useEffect, useCallback } from "react";
import axios from "axios";
import MessageList from "./MessageList";
import ChatInput from "./ChatInput";

const BACKEND_URL = "http://127.0.0.1:8000/nlp?session_id=chat1";

export default function ChatContainer({ soundEnabled }) {

  const [chat, setChat] = useState([]);
  const [isTyping, setIsTyping] = useState(false);
  const [timeline, setTimeline] = useState(null);
  const [report, setReport] = useState(null);
  const [events, setEvents] = useState([]); 


  // Welcome message
  useEffect(() => {
    const welcomeMessage = {
      role: "bot",
      text: `👋 Hi, I'm ThreatCopilot.

I help you investigate security logs using natural language.

Try queries like:
• Show failed vpn logins
• Show brute force attempts more than 2
• Show ssh failures yesterday
• Show malware detected events`,
      timestamp: Date.now(),
    };

    setChat([welcomeMessage]);
  }, []);


  const sendMessage = useCallback(
    async (text) => {

      const userMessage = {
        role: "user",
        text,
        timestamp: Date.now(),
      };

      setChat((prev) => [...prev, userMessage]);
      setIsTyping(true);

      try {

        const response = await axios.post(BACKEND_URL, { query: text });

        // store investigation events for report generation
        setEvents(response.data.events || []);

        const botMessage = {
          role: "bot",
          text: response.data.summary
            ? `${response.data.summary}

MITRE: ${response.data.events?.[0]?.mitre_technique || "N/A"}`
            : "Investigation completed.",
          timestamp: Date.now(),
        };

        setChat((prev) => [...prev, botMessage]);

        // timeline support
        if (response.data.timeline) {
          setTimeline(response.data.timeline);
        }

        // optional notification sound
        if (soundEnabled) {
         try {

            const audioContext =
              new (window.AudioContext || window.webkitAudioContext)();

            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();

            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);

            oscillator.frequency.value = 800;
            oscillator.type = "sine";

            gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(
              0.01,
              audioContext.currentTime + 0.1
            );

            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.1);

          } catch (err) {
            console.error("Audio error:", err);
          }

                }

    } catch {

      setChat((prev) => [
        ...prev,
        {
          role: "bot",
          text: "Error connecting to backend.",
          timestamp: Date.now(),
        },
      ]);

    } finally {
      setIsTyping(false);
    }

  },
  [soundEnabled]
);

          const generateReport = async () => {

            try {

              const response = await axios.post(
                "http://127.0.0.1:8000/generate-report",
                { events: events }
              );

              setReport(response.data.report);

            } catch (err) {

              console.error(err);
              alert("Report generation failed");

            }

          };


  return (

    <div className="flex h-[80vh] w-full max-w-6xl mx-auto gap-4">

     <div className="flex flex-col flex-1 min-h-0 bg-black/20 rounded-lg border border-cyber-green/20 overflow-hidden shadow-[0_0_30px_rgba(0,255,136,0.08)]">

  {/* SCROLLABLE CONTENT */}
  <div className="flex-1 overflow-y-auto px-2">

    <MessageList messages={chat} isTyping={isTyping} />

    {timeline && (
      <div className="p-4 border-t border-cyber-green/20">
        <h2 className="text-cyber-green font-mono mb-2">
          Attack Timeline
        </h2>

        <div className="space-y-1 font-mono text-sm">
          {timeline.map((e, i) => (
            <div key={i} className="flex gap-4">
              <span className="text-cyber-cyan">{e.time}</span>
              <span>{e.event}</span>

              {e.ip && (
                <span className="text-red-400">{e.ip}</span>
              )}

              {e.mitre && (
                <span className="text-yellow-400">{e.mitre}</span>
              )}
            </div>
          ))}
        </div>
      </div>
    )}

  </div>


  {/* FIXED INPUT BAR */}
  <div className="flex items-center gap-3 p-4 border-t border-cyber-green/20 bg-black/40">

    <div className="flex-1">
      <ChatInput onSend={sendMessage} disabled={isTyping} />
    </div>

    <button
      onClick={generateReport}
      className="px-6 py-2 border border-cyber-green text-cyber-green rounded hover:bg-cyber-green/10 font-mono"
    >
      Report
    </button>

  </div>

</div>

      {/* REPORT PANEL */}
      {report && (

        <div className="w-[380px] h-[80vh] bg-black/40 border border-cyber-green/30 rounded p-4 font-mono text-sm overflow-y-auto">

          <div className="flex justify-between mb-2">

            <span className="text-cyber-green font-semibold">
              SOC Incident Report
            </span>

            <button
              onClick={() => setReport(null)}
              className="text-red-400 text-xs"
            >
              ✕ Close
            </button>

          </div>

          <pre className="whitespace-pre-wrap">{report}</pre>

        </div>

      )}

    </div>

  );

}