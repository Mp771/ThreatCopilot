import { useEffect, useRef } from "react";
import MessageItem from "./MessageItem";

export default function MessageList({ messages, isTyping }) {

  const scrollRef = useRef(null);
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({
      behavior: "smooth"
    });
  }, [messages, isTyping]);

  return (
    <div
      ref={scrollRef}
      className="flex-1 overflow-y-auto overflow-x-hidden px-4 py-4 scrollbar-thin"
    >

      {messages.map((msg, index) => (
        <MessageItem
          key={index}
          role={msg.role}
          text={msg.text}
          timestamp={msg.timestamp}
        />
      ))}

      {isTyping && (
        <div className="flex justify-start mb-4 animate-fade-in">
          <div className="px-4 py-3 bg-slate-800/60 border border-cyber-cyan/20 rounded font-mono">

            <span className="text-cyber-cyan text-xs block mb-2 font-medium">
              ANALYST
            </span>

            <div className="flex gap-1">
              <span className="w-2 h-2 bg-cyber-green rounded-full animate-pulse" />
              <span
                className="w-2 h-2 bg-cyber-green rounded-full animate-pulse"
                style={{ animationDelay: "150ms" }}
              />
              <span
                className="w-2 h-2 bg-cyber-green rounded-full animate-pulse"
                style={{ animationDelay: "300ms" }}
              />
            </div>

          </div>
        </div>
      )}

      {/* Anchor for auto scroll */}
      <div ref={bottomRef} />

    </div>
  );
}