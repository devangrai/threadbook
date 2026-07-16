/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_WARDROBE_REMOTE_RECOMMENDATIONS_RELEASE?: string;
  readonly VITE_WARDROBE_TRY_ON_RELEASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
