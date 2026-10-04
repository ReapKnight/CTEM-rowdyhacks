// ─────────────────────────────────────────────────────────────
// Talking to the backend.
//
// Settings live in .env.local in the project root:
//   NEXT_PUBLIC_API_BASE=http://127.0.0.1:8000   ← where the backend runs
//   NEXT_PUBLIC_USE_MOCKS=false                  ← true = rehearse without a backend
// Restart `npm run dev` after changing .env.local.
// ─────────────────────────────────────────────────────────────
import type { ApiErrorBody, ApiFindingsResponse, ApiRemediation, ApiValidation } from "./types";
import { mockFindings, mockRemediation, mockValidation } from "./mockData";

export const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://127.0.0.1:8000";
export const USE_MOCKS_DEFAULT = process.env.NEXT_PUBLIC_USE_MOCKS === "true";

export class ApiError extends Error {
  code: string;
  httpStatus: number | null;
  constructor(message: string, code: string, httpStatus: number | null) {
    super(message);
    this.code = code;
    this.httpStatus = httpStatus;
  }
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function request<T>(path: string, method: "GET" | "POST"): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { method });
  } catch {
    throw new ApiError(`Can't reach the backend at ${API_BASE}. Is it running?`, "NETWORK", null);
  }
  if (!res.ok) {
    let body: Partial<ApiErrorBody> = {};
    try {
      body = await res.json();
    } catch {
      /* not JSON */
    }
    throw new ApiError(
      body.error?.message ?? `Backend returned HTTP ${res.status}`,
      body.error?.code ?? "HTTP_ERROR",
      res.status,
    );
  }
  return (await res.json()) as T;
}

export async function fetchFindings(mock: boolean): Promise<ApiFindingsResponse> {
  if (mock) {
    await wait(300);
    return { ...mockFindings, generated_at: new Date().toISOString() };
  }
  return request<ApiFindingsResponse>("/api/findings", "GET");
}

export async function validateFinding(id: string, mock: boolean): Promise<ApiValidation> {
  if (mock) {
    await wait(1500);
    return mockValidation();
  }
  return request<ApiValidation>(`/api/findings/${encodeURIComponent(id)}/validate`, "POST");
}

export async function requestRemediation(id: string, mock: boolean): Promise<ApiRemediation> {
  if (mock) {
    await wait(600);
    return mockRemediation(id);
  }
  return request<ApiRemediation>(`/api/findings/${encodeURIComponent(id)}/remediation`, "POST");
}
