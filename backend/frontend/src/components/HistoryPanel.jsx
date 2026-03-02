import { useEffect, useState } from "react";
import axios from "axios";

export default function HistoryPanel() {

  const [cases, setCases] = useState([]);

  useEffect(() => {
    axios.get("http://127.0.0.1:8000/history")
      .then(res => setCases(res.data));
  }, []);

  return (

    <div className="w-[260px] border border-cyber-green/30 bg-black/40 rounded p-3 font-mono text-sm overflow-y-auto">

      <div className="text-cyber-green mb-3">
        Investigation History
      </div>

      {cases.map(c => (

        <div key={c.case_id} className="mb-3 border-b border-cyber-green/20 pb-2">

          <div className="text-cyber-cyan text-xs">
            Case #{c.case_id}
          </div>

          <div className="text-slate-300">
            {c.query}
          </div>

          <div className="text-xs text-slate-500">
            {c.events} events
          </div>

        </div>

      ))}

    </div>

  );
}