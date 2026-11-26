// Explicit HTTP boundary for portal API requests.

export function createApiClient(fetchFn = globalThis.fetch) {
  return async function api(method, path, body) {
    const r = await fetchFn('/api' + path, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
      cache: 'no-store',
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      throw new Error((data && data.error) || ('HTTP ' + r.status));
    }
    return data;
  };
}
