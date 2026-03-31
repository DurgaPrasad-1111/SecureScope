import { apiRequest } from './client';

export type AdminRequest = {
  id: string;
  userId: string;
  status: 'pending' | 'approved' | 'denied' | string;
  reason: string;
  createdAt: string | null;
  reviewedAt: string | null;
  reviewedBy: string | null;
  decisionReason: string;
  user?: { id: string; name: string; username?: string; email: string };
};

export function createAdminRequest(reason: string) {
  return apiRequest<{ request: AdminRequest }>('/access-requests', { method: 'POST', body: { reason } });
}

export function getMyAdminRequests() {
  return apiRequest<{ requests: AdminRequest[] }>('/access-requests');
}

export function listAdminRequests(status: string = 'pending') {
  // We can filter by status client-side or server-side. For now server returns all for admins.
  const suffix = status ? `?status=${encodeURIComponent(status)}` : '';
  return apiRequest<{ requests: AdminRequest[] }>(`/access-requests${suffix}`);
}

export function approveAdminRequest(requestId: string, decisionReason?: string) {
  return apiRequest<{ request: AdminRequest }>(`/access-requests/${encodeURIComponent(requestId)}`, {
    method: 'PATCH',
    body: { status: 'approved', decision_reason: decisionReason || '' },
  });
}

export function rejectAdminRequest(requestId: string, decisionReason?: string) {
  return apiRequest<{ request: AdminRequest }>(`/access-requests/${encodeURIComponent(requestId)}`, {
    method: 'PATCH',
    body: { status: 'denied', decision_reason: decisionReason || '' },
  });
}
