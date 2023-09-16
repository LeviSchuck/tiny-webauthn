import { DataSource } from "./data.ts";

export type AppBindings = {
  ORIGINS: string[];
  RP_ID: string;
  DATA_SOURCE: DataSource;
};
export type AppVariables = Record<string, never>;
export type AppEnv = {
  Bindings: AppBindings;
  Variables: AppVariables;
};
