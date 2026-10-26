import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Layout } from "./Layout";
import { Dashboard } from "./pages/Dashboard";
import { Projects } from "./pages/Projects";
import { ProjectDetail } from "./pages/ProjectDetail";
import { CheckDetail } from "./pages/CheckDetail";
import { Policies } from "./pages/Policies";
import { AuditLog } from "./pages/AuditLog";
import { Settings } from "./pages/Settings";
import { Metrics } from "./pages/Metrics";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/projects" element={<Projects />} />
          <Route path="/projects/:id" element={<ProjectDetail />} />
          <Route path="/checks/:id" element={<CheckDetail />} />
          <Route path="/policies" element={<Policies />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/metrics" element={<Metrics />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
);