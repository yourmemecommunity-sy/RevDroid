import { NavLink, Route, Routes } from "react-router-dom";
import UploadPage from "./pages/UploadPage.jsx";
import ResultsPage from "./pages/ResultsPage.jsx";
import HistoryPage from "./pages/HistoryPage.jsx";
import ToolStatus from "./components/ToolStatus.jsx";

function NavItem({ to, children }) {
  return (
    <NavLink
      to={to}
      end
      className={({ isActive }) =>
        `rounded-lg px-3 py-1.5 text-sm font-medium transition ${
          isActive ? "bg-white/10 text-white" : "text-slate-300 hover:text-white"
        }`
      }
    >
      {children}
    </NavLink>
  );
}

export default function App() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-20 bg-slate-900/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center gap-4 px-4 py-3">
          <NavLink to="/" className="flex items-center gap-2 text-white">
            <img src="/favicon.svg" alt="" className="h-7 w-7" />
            <span className="text-lg font-semibold tracking-tight">RevDroid</span>
          </NavLink>
          <nav className="flex gap-1">
            <NavItem to="/">Analyze</NavItem>
            <NavItem to="/history">History</NavItem>
          </nav>
          <div className="ml-auto"><ToolStatus /></div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-8">
        <Routes>
          <Route path="/" element={<UploadPage />} />
          <Route path="/scans/:id" element={<ResultsPage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="*" element={<p className="text-slate-500">Page not found.</p>} />
        </Routes>
      </main>
      <footer className="border-t border-slate-200 py-4 text-center text-xs text-slate-500">
        RevDroid performs static analysis only. Analyze apps you own or are authorized to test.
      </footer>
    </div>
  );
}
