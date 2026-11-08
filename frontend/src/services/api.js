import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  if (typeof FormData !== 'undefined' && config.data instanceof FormData) {
    delete config.headers['Content-Type'];
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    const status = err.response?.status;
    const url = err.config?.url || '';
    // Login/register auth failures must stay on the form — do not bounce the page.
    const isAuthAttempt = /\/auth\/(login|register|verify-email|forgot-password|reset-password|resend-verification)/.test(url);
    if (status === 401 && !isAuthAttempt) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(err);
  }
);

/**
 * Download a protected file.
 *
 * PDF reports sit behind @jwt_required, so the browser cannot fetch them with a
 * plain link. The response is pulled as a blob through the authenticated axios
 * instance and then handed to the browser as an object URL.
 */
function saveBlob(data, filename, mimeType) {
  const blob = data instanceof Blob ? data : new Blob([data], mimeType ? { type: mimeType } : undefined);
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = objectUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(objectUrl);
}

async function blobErrorMessage(payload, fallback = 'Download failed') {
  if (!(payload instanceof Blob)) {
    return payload?.error || fallback;
  }
  const text = await payload.text();
  try {
    const parsed = JSON.parse(text);
    return parsed.error || parsed.message || fallback;
  } catch {
    if (/requested URL was not found/i.test(text)) {
      return 'Forensic PDF route was not found. Restart the Flask backend and try again.';
    }
    return fallback;
  }
}

export async function downloadFile(url, filename) {
  try {
    const response = await api.get(url, { responseType: 'blob' });
    const data = response.data;
    const type = String(response.headers['content-type'] || data?.type || '').toLowerCase();
    if (type.includes('application/json') || type.includes('text/html')) {
      throw new Error(await blobErrorMessage(data));
    }
    saveBlob(data, filename);
  } catch (err) {
    const message = await blobErrorMessage(err.response?.data, err.message || 'Download failed');
    throw new Error(message);
  }
}

export async function downloadPost(url, body, filename) {
  try {
    const response = await api.post(url, body, { responseType: 'blob' });
    const data = response.data;
    const buffer = data instanceof Blob ? await data.arrayBuffer() : data;
    const bytes = new Uint8Array(buffer);
    const looksPdf = bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46;
    const type = String(response.headers['content-type'] || '').toLowerCase();
    if (!looksPdf && (type.includes('application/json') || type.includes('text/html') || bytes[0] === 0x7b)) {
      throw new Error(await blobErrorMessage(new Blob([buffer])));
    }
    saveBlob(new Blob([buffer], { type: 'application/pdf' }), filename, 'application/pdf');
  } catch (err) {
    const message = await blobErrorMessage(err.response?.data, err.message || 'Download failed');
    throw new Error(message);
  }
}

export default api;
