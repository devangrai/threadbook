import { invoke } from "@tauri-apps/api/core";

export type InvokeCommand = <T>(
  command: string,
  args?: Record<string, unknown>,
) => Promise<T>;

export const productionInvoke: InvokeCommand = invoke;
