import React, { useState } from "react";
import { post } from "../api";

export function Settings() {
  const [webhookUrl, setWebhookUrl] = useState("");
  const [notifyToken, setNotifyToken] = useState("");
  const [notifyEmail, setNotifyEmail] = useState("");
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await post<{ ok: boolean }, { webhook_url: string; token: string; email: string }>(
        "/settings/notifications",
        { webhook_url: webhookUrl, token: notifyToken, email: notifyEmail },
      );
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err: any) {
      alert(err.message || "Failed to save settings");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <h1>Настройки / Settings</h1>
      <p className="muted">Уведомления о завершении проверок и критических рисках.</p>
      <form onSubmit={handleSave} className="panel" style={{ maxWidth: 600 }}>
        <div style={{ marginBottom: 16 }}>
          <label>Webhook URL</label><br />
          <input
            className="input"
            placeholder="https://hooks.example.com/qorvex"
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
          />
        </div>
        <div style={{ marginBottom: 16 }}>
          <label>API Token</label><br />
          <input
            className="input"
            type="password"
            placeholder="••••••••"
            value={notifyToken}
            onChange={(e) => setNotifyToken(e.target.value)}
          />
        </div>
        <div style={{ marginBottom: 16 }}>
          <label>Email для уведомлений</label><br />
          <input
            className="input"
            type="email"
            placeholder="security@example.com"
            value={notifyEmail}
            onChange={(e) => setNotifyEmail(e.target.value)}
          />
        </div>
        <button className="btn" disabled={saving}>
          {saving ? "Сохранение…" : "Сохранить настройки"}
        </button>
        {saved && <span className="badge success" style={{ marginLeft: 12 }}>Сохранено</span>}
      </form>
    </div>
  );
}
