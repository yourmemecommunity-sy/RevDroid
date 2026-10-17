// Thin API client. All calls go to /api (proxied by Vite in dev and by nginx in Docker).
const BASE = import.meta.env.VITE_API_BASE || "/api";

async function request(path, options = {}) {
  let res;
  try {
    res = await fetch(`${BASE}${path}`, options);
  } catch {
    throw new Error("Cannot reach the RevDroid backend. Is it running on port 8000?");
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch { /* non-JSON error */ }
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export const api = {
  health: () => request("/health"),
  listScans: () => request("/scans"),
  getScan: (id) => request(`/scans/${id}`),
  getResult: (id) => request(`/scans/${id}/result`),
  deleteScan: (id) => request(`/scans/${id}`, { method: "DELETE" }),
  reportUrl: (id) => `${BASE}/scans/${id}/report.pdf`,

  // XHR instead of fetch: fetch cannot report upload progress.
  upload(file, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      const form = new FormData();
      form.append("file", file);
      xhr.open("POST", `${BASE}/scans`);
      xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(Math.round((e.loaded / e.total) * 100));
      xhr.onload = () => {
        let body = {};
        try { body = JSON.parse(xhr.responseText); } catch { /* ignore */ }
        if (xhr.status >= 200 && xhr.status < 300) resolve(body);
        else reject(new Error(body.detail || `Upload failed (${xhr.status})`));
      };
      xhr.onerror = () => reject(new Error("Upload failed: the backend is unreachable."));
      xhr.send(form);
    });
  },
};
