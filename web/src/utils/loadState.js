/* Stan sekcji z danymi z useApi: 'ready' | 'error' | 'loading'.
   Blad PIERWSZEGO odczytu (brak danych) to 'error', nie wieczne ladowanie.
   Blad odswiezenia przy starych danych zostaje 'ready' - plakietka bledu
   obok danych wystarczy. */
export function loadState(res) {
  if (res.data) return 'ready';
  return res.error ? 'error' : 'loading';
}
