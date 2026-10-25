import React from "react";
import { Outlet, Link } from "react-router-dom";

export function Layout() {
  return (
    <div className="app">
      <nav className="nav">
        <Link to="/" className="nav-logo">◈ Qorvex</Link>
        <div className="nav-links">
          <Link to="/">Dashboard</Link>
          <Link to="/projects">Projects</Link>
          <Link to="/policies">Policies</Link>
          <Link to="/audit">Audit</Link>
        </div>
      </nav>
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}