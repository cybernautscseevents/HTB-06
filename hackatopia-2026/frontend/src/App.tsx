import { CircleAlert } from "lucide-react";
import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./hooks/useAuth";
import Header from "./components/Header";
import AuditPage from "./pages/AuditPage";
import Dashboard from "./pages/Dashboard";
import History from "./pages/History";
import Landing from "./pages/Landing";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

export default function App() {
  const { auth, repos, reposLoading, authError, clearAuthError, signOut } = useAuth();

  return (
    <div className="min-h-screen bg-background pb-10">
      <Header auth={auth} onSignOut={signOut} />
      {authError && (
        <div className="mx-auto max-w-7xl px-4 pt-4 sm:px-6">
          <Alert variant="destructive">
            <CircleAlert />
            <AlertTitle>Sign-in failed</AlertTitle>
            <AlertDescription>{authError}</AlertDescription>
            <AlertAction><Button variant="ghost" size="sm" onClick={clearAuthError}>Dismiss</Button></AlertAction>
          </Alert>
        </div>
      )}
      <Routes>
        <Route path="/" element={<Landing auth={auth} />} />
        <Route path="/dashboard" element={<Dashboard auth={auth} repos={repos} reposLoading={reposLoading} />} />
        <Route path="/history" element={<History />} />
        <Route path="/audit/:runId" element={<AuditPage auth={auth} />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  );
}
