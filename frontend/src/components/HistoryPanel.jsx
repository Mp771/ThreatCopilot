import { useEffect, useState } from "react";
import axios from "axios";

export default function HistoryPanel({ onLoadInvestigation }) {

  const [history, setHistory] = useState([]);

  useEffect(() => {

    const fetchHistory = async () => {
      try {

        const res = await axios.get("http://127.0.0.1:8000/history");

        setHistory(res.data.history || []);

      } catch (err) {

        console.error("History fetch failed", err);

      }
    };

    fetchHistory();

  }, []);

  const loadInvestigation = async (id) => {

    try {

      const res = await axios.get(`http://127.0.0.1:8000/history/${id}`);

      if (onLoadInvestigation) {
        onLoadInvestigation(res.data);
      }

    } catch (err) {

      console.error("Failed to load investigation", err);

    }

  };

  return (

    <div className="w-[260px] bg-black/40 border border-cyber-green/30 rounded p-3 font-mono text-sm overflow-y-auto">

      <h2 className="text-cyber-green mb-3 font-semibold">
        Investigation History
      </h2>

      {history.length === 0 && (
        <div className="text-slate-400 text-xs">
          No investigations yet
        </div>
      )}

      {history.map((item) => (

        <div
          key={item.id}
          onClick={() => loadInvestigation(item.id)}
          className="p-2 mb-2 border border-cyber-green/20 rounded cursor-pointer hover:bg-cyber-green/10 transition"
        >

          <div className="text-cyber-cyan text-xs">
            {new Date(item.created_at).toLocaleString()}
          </div>

          <div className="text-slate-200 truncate">
            {item.query}
          </div>

        </div>

      ))}

    </div>

  );

}