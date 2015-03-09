#ifndef WINSERVICE_H
#define WINSERVICE_H

#include <Windows.h>

void parse_config();
void run_daemon();
void stop_daemon();

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode);

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

#endif