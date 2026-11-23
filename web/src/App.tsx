import { Navigate, Route, Routes } from "react-router-dom";
import { useSession } from "./auth";
import { KeyGate, Layout } from "./components/Layout";
import { Spinner } from "./components/ui";
import Tenants from "./pages/Tenants";
import Platform from "./pages/Platform";
import PlatformTenant from "./pages/PlatformTenant";
import Overview from "./pages/Overview";
import Contacts from "./pages/Contacts";
import Campaigns from "./pages/Campaigns";
import CampaignDetail from "./pages/CampaignDetail";
import Templates from "./pages/Templates";
import SendingProfiles from "./pages/SendingProfiles";
import Approvals from "./pages/Approvals";
import Activity from "./pages/Activity";
import Recon from "./pages/Recon";
import Settings from "./pages/Settings";

export default function App() {
  const { key, ready, isAdmin } = useSession();

  if (!ready) {
    return <Spinner label="Starting…" />;
  }
  if (!key) {
    return <KeyGate />;
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/overview" replace />} />
        <Route path="/overview" element={<Overview />} />
        <Route path="/campaigns" element={<Campaigns />} />
        <Route path="/campaigns/:id" element={<CampaignDetail />} />
        <Route path="/contacts" element={<Contacts />} />
        <Route path="/templates" element={<Templates />} />
        <Route path="/sending-profiles" element={<SendingProfiles />} />
        <Route path="/approvals" element={<Approvals />} />
        <Route path="/activity" element={<Activity />} />
        <Route path="/recon" element={<Recon />} />
        <Route path="/settings" element={<Settings />} />
        <Route
          path="/tenants"
          element={isAdmin ? <Tenants /> : <Navigate to="/campaigns" replace />}
        />
        <Route
          path="/platform"
          element={isAdmin ? <Platform /> : <Navigate to="/overview" replace />}
        />
        <Route
          path="/platform/:id"
          element={isAdmin ? <PlatformTenant /> : <Navigate to="/overview" replace />}
        />
        <Route path="*" element={<Navigate to="/campaigns" replace />} />
      </Routes>
    </Layout>
  );
}
