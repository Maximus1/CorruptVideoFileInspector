# Copilot / AI-Agent Quick Start — CorruptVideoFileInspector

Kurz, präzise und handlungsorientiert: dieses Projekt ist eine kleine, stand‑alone Python/Tkinter GUI, die Video-Dateien per FFmpeg auf Fehler prüft.

## Big Picture
- Single main module: `CorruptVideoInspector.py` (GUI, Control Flow, ffmpeg subprocess orchestration).
- FFmpeg ist die Kern-Dependency: die App startet für jede Datei ein `ffmpeg` subprocess (`-v error -progress pipe:1 -i <file> -f null -`) und wertet Return-Code + stderr/out aus.
- Laufzeit‑Artefakte: `_Logs.log` (textlog) und `_Results.csv` (Zwei-Spalten: `Video File`, `Corrupt` mit `0/1`).
- Packaging: Builds werden in `builds/` (macOS `.app` / Windows `.exe`) erzeugt; build-Hinweise in `build-app-instructions/`.

## So wirst du sofort produktiv
1. Read First: Öffne `CorruptVideoInspector.py`, `Readme.md` und `ruleset.md` bevor du Änderungen machst.
2. Local run: Stelle sicher, dass `ffmpeg` vorhanden ist (Projektroot: `ffmpeg` auf mac, `ffmpeg.exe` auf Windows oder system-ffmpeg). Dann:
   - Direkt starten: `python CorruptVideoInspector.py`
   - Wähle ein Verzeichnis, starte Scan, überprüfe `_Logs.log` und `_Results.csv`.
3. Debugging: Reproduziere den zugrunde liegenden ffmpeg-Aufruf manuell:
   - Beispiel: `ffmpeg -v error -progress pipe:1 -i "<path/to/video>" -f null -`
   - Prüfe stdout/stderr auf Fehlermeldungen und Rückgabecode.
4. Packaging examples (aus repo):
   - Windows (pyinstaller):
     `pyinstaller --add-binary="ffmpeg.exe;." --add-data="icon.ico;." --icon="icon.ico" --noconsole --onefile CorruptVideoInspector.py`
   - macOS (py2app):
     `python3 setup.py py2app` (siehe `builds/macOS` für fertige Beispiele)

## Projekt-spezifische Patterns & Fallen
- Platform helpers: `is_mac_os()`, `is_windows_os()`, `get_ffmpeg_path()` — respektiere Platform-spezifika bei Pfad- / Binary-Auflösung.
- UI/Threading: Die App startet die Datei-Inspektion in einem `Thread` und aktualisiert die UI via `tkinter.after` — vermeide Blocking-Edits im Hauptthread.
- Globals: Status-Variablen heißen `g_progress`, `g_count`, `g_currently_processing`, `g_cpu_status`, `g_ffmpeg_pid_var` — wenn du UI-Labels änderst, bleibe konsistent.
- FFmpeg-Lebensdauer: Wenn GUI abgestürzt/geschlossen wird, kann `ffmpeg` weiterlaufen. Tests/Änderungen sollten diesen Fall berücksichtigen (siehe `kill_ffmpeg()` und `kill_ffmpeg_warning()`).

## Validation & Testing (manuell)
- Kein Test-Framework vorhanden — validiere Änderungen manuell:
  1. `python CorruptVideoInspector.py` (funktionaler Smoke-Test)
  2. Scanne ein kleines Verzeichnis; kontrolliere `_Results.csv` / `_Logs.log` und die GUI-Farbmarkierung (grün/rot).
  3. Prüfe CPU-Tracking via `psutil` (UI `CPU: ...` Status).
- Für Build-Änderungen: Erzeuge ein lokales `--onefile` Windows-Build oder macOS `.app` und teste auf Ziel-OS (ffmpeg im Bundle!).

## Konventionen für AI-Agenten
- Lies `ruleset.md` — dort stehen die agent-spezifischen Regeln (Sprache: Deutsch, Read-before-edit, Sessions-Logs in `memory.md`, keine Datei-Neuerstellungen ohne Erlaubnis).
- Keep edits minimal: "edit in place" bevorzugt, keine unnötigen neue Dateien (außer der User verlangt es).
- Nach jeder produktiven Session: aktualisiere `memory.md` (was wurde geändert, Tests, Status). Regeln dazu im `ruleset.md`.

## Wichtige Dateien & Orte
- `CorruptVideoInspector.py` — primäre Logik, UI, ffmpeg orchestration
- `Readme.md` — Benutzungs- und Build-Hinweise
- `ruleset.md` — Projekt-spezifische Agent-Regeln
- `build-app-instructions/` — pyinstaller / py2app Befehle
- `builds/` — vorgefertigte App/Binär-Artefakte (Referenz)

---
Wenn etwas unklar ist oder du eine bestimmte Änderung im Sinn hast (z. B. Unit-Tests hinzufügen, CLI-Version extrahieren oder ffmpeg-Call robuster machen), sag genau welche Datei/Scope du möchtest — ich helfe bei einem präzisen Plan und den nötigen Änderungen.