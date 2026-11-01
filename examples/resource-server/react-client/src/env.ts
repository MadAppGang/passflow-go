// Vite replaces these by literal name, so they cannot be read through a helper.
const values = {
  VITE_PASSFLOW_URL: import.meta.env.VITE_PASSFLOW_URL as string | undefined,
  VITE_PASSFLOW_APP_ID: import.meta.env.VITE_PASSFLOW_APP_ID as string | undefined,
  VITE_API_URL: import.meta.env.VITE_API_URL as string | undefined,
};

export const missingEnv = Object.entries(values)
  .filter(([, value]) => !value)
  .map(([name]) => name);

export const passflowUrl = values.VITE_PASSFLOW_URL ?? '';
export const passflowAppId = values.VITE_PASSFLOW_APP_ID ?? '';
export const apiUrl = (values.VITE_API_URL ?? '').replace(/\/+$/, '');
