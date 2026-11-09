interface ImportMetaEnv {
  // Set by the Dockerfile from the AGENT_IMAGE build arg (release builds only).
  readonly VITE_AGENT_IMAGE?: string
}
