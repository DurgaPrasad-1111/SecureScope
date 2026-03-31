import { createBrowserRouter } from 'react-router';
import RequireAuth from './components/auth/RequireAuth';
import ReconLayout from './layouts/ReconLayout';
import Login from './pages/Login';
import Signup from './pages/Signup';
import Dashboard from './pages/recon/Dashboard';
import ReconDashboard from './pages/recon/ReconDashboard';
import AssetInventory from './pages/recon/AssetInventory';
import NewScan from './pages/recon/NewScan';
import ScanResults from './pages/recon/ScanResults';
import AdminRequests from './pages/AdminRequests';
import AdminCreateUser from './pages/AdminCreateUser';
import Landing from './pages/Landing';

export const router = createBrowserRouter([
  {
    path: '/signin',
    Component: Login,
  },
  {
    path: '/signup',
    Component: Signup,
  },
  {
    path: '/',
    Component: Landing,
  },
  {
    Component: RequireAuth,
    children: [
      {
        Component: ReconLayout,
        children: [
          // Canonical authenticated routes (no /app prefix)
          { path: '/app', Component: Dashboard },
          { path: '/overview', Component: ReconDashboard },
          { path: '/inventory', Component: AssetInventory },
          { path: '/new-scan', Component: NewScan },
          { path: '/scan/:id', Component: ScanResults },
          { path: '/admin/requests', Component: AdminRequests },
          { path: '/admin/users/new', Component: AdminCreateUser },

          // Backward-compatible aliases under /app
          { path: '/app/overview', Component: ReconDashboard },
          { path: '/app/inventory', Component: AssetInventory },
          { path: '/app/new-scan', Component: NewScan },
          { path: '/app/scan/:id', Component: ScanResults },
          { path: '/app/admin/requests', Component: AdminRequests },
          { path: '/app/admin/users/new', Component: AdminCreateUser },
        ],
      },
    ],
  },
  // Legacy SPA route (not used in container deployment because backend owns /login).
  {
    path: '/login',
    loader: () => {
      window.location.replace('/signin');
      return null;
    },
  },
]);
