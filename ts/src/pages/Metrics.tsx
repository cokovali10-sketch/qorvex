import React, { useEffect, useState } from "react";
import { get } from "../api";

type Metric = { label: string; value: string | number; delta?: string };

export function Metrics() {
  const [stats, setStats] = useState<Metric[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    get<{ checks: number; passed: number; failed: number; secrets: number; deps: number; licenses: number }>(
      "/metrics",
    )
      .then((m) => {
        setStats([
          { label: "Проверок запущено", value: m.checks },
          { label: "Пройдено", value: m.passed, delta: m.passed > 0 ? "+OK" : "" },
          { label: "Не пройдено", value: m.failed, delta: m.failed > 0 ? "⚠" : "" },
          { label: "Секретов найдено", value: m.secrets, delta: m.secrets > 0 ? "⚠" : "" },
          { label: "Зависимостей", value: m.deps },
          { label: "Лицензий", value: m.licenses },
        ]);
      })
      .catch(() => {
        setStats([
          { label: "Проверок запущено", value: "—" },
          { label: "Пройдено", value: "—" },
          { label: "Не пройдено", value: "—" },
          { label: "Секретов найдено", value: "—" },
          { label: "Зависимостей", value: "—" },
          { label: "Лицензий", value: "—" },
        ]);
      })
      .finally(() => setLoading(false));
  }, []);

  const deltaBadge = (d: string) => {
    if (!d) return null;
    return <span className={`badge ${d.includes("⚠") ? "badge-critical" : "badge-success"}`}>{d}</span>;
  };

  return (
    <div>
      <h1>Метрики / Metrics</h1>
      <p className="muted">Агрегированная статистика по пройденным проверкам конвейера Qorvex.</p>
      {loading ? (
        <div>Загрузка…</div>
      ) : (
        <div className="stats-grid">
          {stats.map((s, i) => (
            <div key={i} className="stat-card">
              <div className="stat-label">{s.label}</div>
              <div className="stat-value">{s.value}</div>
              {s.delta && deltaBadge(s.delta)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
