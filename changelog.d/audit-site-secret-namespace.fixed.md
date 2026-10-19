- **Site-scoped credentials can be created through the supported storage paths.**
  The store API, CLI and Vault table accept exact `site:<siteIdentifier>:<friendlyName>`
  namespaces for configured sites. Existing credentials retain their authenticated
  names and remain administrable after site rename/delete. Read-time resolution
  falls back to a global credential only for an actually missing namespaced row;
  denial, disabled state, expiry or decryption failure leaves the placeholder unresolved.
