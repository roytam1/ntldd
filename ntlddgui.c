/*
    ntlddgui - GUI dependency walker for PE modules

    Copyright (C) 2025 Roy Tam (roytam1)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
*/

#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libntldd.h"

#ifndef WM_MOUSEWHEEL
#define WM_MOUSEWHEEL 0x020A
#endif

#ifndef UINT_PTR
#define UINT_PTR UINT
#endif

#ifndef GetXParam
#define GetXParam(lp) ((int)(short)LOWORD(lp))
#define GetYParam(lp) ((int)(short)HIWORD(lp))
#endif

/* ------------------------------------------------------------------ */
/* Win32 API pointers (Wow64 / SysWow64)                              */
/* ------------------------------------------------------------------ */

typedef BOOL (WINAPI *tW64P)(HANDLE, PBOOL);
typedef BOOL (WINAPI *tFSDisable)(PVOID*);
typedef BOOL (WINAPI *tFSRevert)(PVOID);
typedef UINT (WINAPI *tGetSystemWow64DirectoryA)(LPSTR, UINT);

static tW64P pIsWow64Func = NULL;
static tFSDisable pDisableFunc = NULL;
static tFSRevert pRevertFunc = NULL;
static tGetSystemWow64DirectoryA pGetSystemWow64DirectoryA = NULL;
static PVOID g_oldValue = NULL;
static BOOL g_bIsWow64 = FALSE;

/* ------------------------------------------------------------------ */
/* Document model                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    char filePath[MAX_PATH];
    struct DepTreeElement root;
    SearchPaths searchPaths;
    struct DepTreeElement *selected;
} Document;

static Document *g_doc = NULL;
static HWND g_hwndMain = NULL;
static HFONT g_font = NULL;

/* ------------------------------------------------------------------ */
/* Visible (flattened) tree nodes                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    struct DepTreeElement *node;
    int depth;
} VisNode;

static VisNode *g_visNodes = NULL;
static int g_visCount = 0;
static int g_visCap = 0;

static int g_scrollY = 0;
static int g_scrollMaxY = 0;
static int g_scrollX = 0;
static int g_scrollMaxX = 0;

/* Child controls */
static HWND g_hwndTree = NULL;
static HWND g_hwndDetails = NULL;
static HWND g_hwndImpLabel = NULL;
static HWND g_hwndImports = NULL;
static HWND g_hwndExpLabel = NULL;
static HWND g_hwndExports = NULL;

/* Menu ids */
#define ID_FILE_OPEN      1001
#define ID_FILE_EXIT      1002
#define ID_VIEW_EXPANDALL 1010
#define ID_VIEW_COLLAPSE  1011
#define ID_HELP_ABOUT     1020

/* ------------------------------------------------------------------ */
/* Utility helpers                                                    */
/* ------------------------------------------------------------------ */

static const char *BaseName(const char *path)
{
    const char *p;
    if (!path || !*path) return "";
    p = strrchr(path, '\\');
    if (!p) p = strrchr(path, '/');
    return p ? p + 1 : path;
}

static void FreeTree(struct DepTreeElement *node)
{
    uint64_t i;
    if (!node) return;
    for (i = 0; i < node->childs_len; i++)
        FreeTree(node->childs[i]);
    free(node->childs);
    node->childs = NULL;
    node->childs_len = 0;
    node->childs_size = 0;

    if (node->exports) {
        for (i = 0; i < node->exports_len; i++) {
            free(node->exports[i].name);
            free(node->exports[i].forward_str);
        }
        free(node->exports);
        node->exports = NULL;
        node->exports_len = 0;
    }
    if (node->imports) {
        for (i = 0; i < node->imports_len; i++)
            free(node->imports[i].name);
        free(node->imports);
        node->imports = NULL;
        node->imports_len = 0;
        node->imports_size = 0;
    }
    free(node->module);
    node->module = NULL;
    free(node->resolved_module);
    node->resolved_module = NULL;
    free(node->export_module);
    node->export_module = NULL;
}

static void FreeDocument(Document *doc)
{
    uint64_t i;
    if (!doc) return;
    FreeTree(&doc->root);
    if (doc->searchPaths.path) {
        for (i = 0; i < doc->searchPaths.count; i++)
            free(doc->searchPaths.path[i]);
        free(doc->searchPaths.path);
    }
    free(doc);
}

/* DragQueryFile wrapper */
#ifdef __TINYC__
#define HDROP HANDLE
#endif

typedef UINT (WINAPI *apiDragQueryFile)(HDROP, UINT, LPSTR, UINT);
UINT WINAPI MyDragQueryFile_fallback(HDROP hDrop, UINT iFile, LPSTR lpszFile, UINT cch) {
	return 0;
}

UINT WINAPI MyDragQueryFile_init(HDROP hDrop, UINT iFile, LPSTR lpszFile, UINT cch);
static apiDragQueryFile MyDragQueryFile = MyDragQueryFile_init;

UINT WINAPI MyDragQueryFile_init(HDROP hDrop, UINT iFile, LPSTR lpszFile, UINT cch) {
	HMODULE hShell32;
	if( MyDragQueryFile == MyDragQueryFile_init ) {
		hShell32 = GetModuleHandleA("SHELL32.DLL");
		// Try new name first
		MyDragQueryFile = (apiDragQueryFile)GetProcAddress(hShell32, "DragQueryFileA");
		if( !(MyDragQueryFile) ) {
			// if not found, try old name
			MyDragQueryFile = (apiDragQueryFile)GetProcAddress(hShell32, "DragQueryFile");
			if( !(MyDragQueryFile) ) {
				MyDragQueryFile = MyDragQueryFile_fallback;
			}
		}
	}

	return MyDragQueryFile( hDrop, iFile, lpszFile, cch );

}
/* end of DragQueryFile wrapper */

/* ------------------------------------------------------------------ */
/* Visible tree management                                            */
/* ------------------------------------------------------------------ */

static void PushVisible(struct DepTreeElement *node, int depth)
{
    if (g_visCount >= g_visCap) {
        int newCap;
        VisNode *n;
        newCap = g_visCap ? g_visCap * 2 : 256;
        n = (VisNode *)realloc(g_visNodes, newCap * sizeof(VisNode));
        if (!n) return;
        g_visNodes = n;
        g_visCap = newCap;
    }
    g_visNodes[g_visCount].node = node;
    g_visNodes[g_visCount].depth = depth;
    g_visCount++;
}

static void BuildVisible(struct DepTreeElement *node, int depth)
{
    uint64_t i;
    if (!node) return;
    PushVisible(node, depth);
    if (node->flags & DEPTREE_EXPANDED) {
        for (i = 0; i < node->childs_len; i++)
            BuildVisible(node->childs[i], depth + 1);
    }
}

static void RebuildVisible(void)
{
    uint64_t i;
    g_visCount = 0;
    if (!g_doc) return;
    for (i = 0; i < g_doc->root.childs_len; i++)
        BuildVisible(g_doc->root.childs[i], 0);
}

static void SetExpandedRecursive(struct DepTreeElement *node, int expanded)
{
    uint64_t i;
    if (!node) return;
    for (i = 0; i < node->childs_len; i++) {
        if (expanded)
            node->childs[i]->flags |= DEPTREE_EXPANDED;
        else
            node->childs[i]->flags &= ~DEPTREE_EXPANDED;
        SetExpandedRecursive(node->childs[i], expanded);
    }
}

/* ------------------------------------------------------------------ */
/* Panels update                                                      */
/* ------------------------------------------------------------------ */

static void UpdatePanels(Document *doc)
{
    struct DepTreeElement *mod;
    char buf[4096];
    char line[512];
    uint64_t i;

    buf[0] = '\0';
    if (!doc || !doc->selected) {
        SetWindowTextA(g_hwndDetails, "");
        SendMessageA(g_hwndImports, LB_RESETCONTENT, 0, 0);
        SendMessageA(g_hwndExports, LB_RESETCONTENT, 0, 0);
        return;
    }
    mod = doc->selected;

    sprintf(line, "Module: %s\r\n", mod->module ? mod->module : "(null)");
    strcat(buf, line);
    sprintf(line, "Resolved: %s\r\n", mod->resolved_module ? mod->resolved_module : "(unresolved)");
    strcat(buf, line);
    sprintf(line, "Mapped address: 0x%p\r\n", mod->mapped_address);
    strcat(buf, line);
    sprintf(line, "Machine type: 0x%04X\r\n", (unsigned)mod->machineType);
    strcat(buf, line);
    sprintf(line, "PE32+: %s\r\n", mod->isPE32plus ? "yes" : "no");
    strcat(buf, line);
    sprintf(line, "Exports: %lu\r\n", (unsigned long)mod->exports_len);
    strcat(buf, line);
    sprintf(line, "Imports: %lu\r\n", (unsigned long)mod->imports_len);
    strcat(buf, line);
    sprintf(line, "Dependencies: %lu\r\n", (unsigned long)mod->childs_len);
    strcat(buf, line);
    sprintf(line, "Unresolved: %s\r\n", (mod->flags & DEPTREE_UNRESOLVED) ? "yes" : "no");
    strcat(buf, line);
    SetWindowTextA(g_hwndDetails, buf);

    SendMessageA(g_hwndImports, LB_RESETCONTENT, 0, 0);
    for (i = 0; i < mod->imports_len; i++) {
        struct ImportTableItem *imp = &mod->imports[i];
        char modname[MAX_PATH];
        line[0] = '\0';
        if (imp->dll && imp->dll->module)
            strcpy(modname, BaseName(imp->dll->module));
        else
            strcpy(modname, "<missing>");
        if (imp->name)
            sprintf(line, "%s!%s", modname, imp->name);
        else if (imp->ordinal > 0)
            sprintf(line, "%s!#%d", modname, imp->ordinal);
        else
            sprintf(line, "%s!<null>", modname);
        if (imp->is_delayed)
            strcat(line, " (delayed)");
        if (!imp->dll)
            strcat(line, " <MODULE MISSING>");
        else if (imp->dll->flags & DEPTREE_UNRESOLVED)
            strcat(line, " <UNRESOLVED>");
        SendMessageA(g_hwndImports, LB_ADDSTRING, 0, (LPARAM)line);
    }

    SendMessageA(g_hwndExports, LB_RESETCONTENT, 0, 0);
    for (i = 0; i < mod->exports_len; i++) {
        struct ExportTableItem *exp = &mod->exports[i];
        if (exp->name)
            sprintf(line, "[%u] %s (0x%08lX)%s%s",
                    (unsigned)exp->ordinal,
                    exp->name,
                    (unsigned long)exp->address_offset,
                    exp->forward_str ? " -> " : "",
                    exp->forward_str ? exp->forward_str : "");
        else
            sprintf(line, "[%u] (0x%08lX)", (unsigned)exp->ordinal,
                    (unsigned long)exp->address_offset);
        SendMessageA(g_hwndExports, LB_ADDSTRING, 0, (LPARAM)line);
    }
}

/* ------------------------------------------------------------------ */
/* Load a module into the document                                    */
/* ------------------------------------------------------------------ */

static int LoadDocument(const char *path)
{
    Document *doc;
    SearchPaths sp;
    char full[MAX_PATH];
    char *p;
    uint64_t stack_len = 0, stack_size = 0;
    char **stack = NULL;
    BuildTreeConfig cfg;
    struct DepTreeElement *child;
    uint64_t i;
    char title[512];

    FreeDocument(g_doc);
    g_doc = NULL;
    g_visCount = 0;
    g_scrollY = 0;
    g_scrollX = 0;

    doc = (Document *)calloc(1, sizeof(Document));
    if (!doc) return -1;
    strncpy(doc->filePath, path, MAX_PATH - 1);

    memset(&sp, 0, sizeof(sp));
    sp.path = (char **)calloc(1, sizeof(char *));
    if (!sp.path) { free(doc); return -1; }

    if (pGetSystemWow64DirectoryA) {
        char dir[MAX_PATH];
        if (pGetSystemWow64DirectoryA(dir, MAX_PATH)) {
            sp.count++;
            sp.path = (char **)realloc(sp.path, sp.count * sizeof(char *));
            sp.path[sp.count - 1] = strdup(dir);
        }
    }

    GetFullPathNameA(path, MAX_PATH, full, &p);
    if (p) {
        *p = '\0';
        sp.count++;
        sp.path = (char **)realloc(sp.path, sp.count * sizeof(char *));
        sp.path[sp.count - 1] = strdup(full);
    }

    memset(&doc->root, 0, sizeof(doc->root));
    child = (struct DepTreeElement *)calloc(1, sizeof(struct DepTreeElement));
    if (!child) { free(doc); return -1; }
    child->module = strdup(path);

    if (doc->root.childs_len >= doc->root.childs_size) {
        uint64_t ns;
        struct DepTreeElement **nd;
        ns = doc->root.childs_size ? doc->root.childs_size * 2 : 64;
        nd = (struct DepTreeElement **)realloc(doc->root.childs, ns * sizeof(struct DepTreeElement *));
        if (!nd) { free(child->module); free(child); free(doc); return -1; }
        memset((unsigned char *)nd + doc->root.childs_size * sizeof(struct DepTreeElement *), 0,
               (size_t)((ns - doc->root.childs_size) * sizeof(struct DepTreeElement *)));
        doc->root.childs = nd;
        doc->root.childs_size = ns;
    }
    doc->root.childs[doc->root.childs_len++] = child;

    memset(&cfg, 0, sizeof(cfg));
    cfg.on_self = 0;
    cfg.datarelocs = 0;
    cfg.functionrelocs = 0;
    cfg.recursive = 1;
    cfg.stack = &stack;
    cfg.stack_len = &stack_len;
    cfg.stack_size = &stack_size;
    cfg.searchPaths = &sp;

    BuildDepTree(&cfg, (char *)path, &doc->root, child);
    ClearDepStatus(&doc->root, DEPTREE_VISITED | DEPTREE_PROCESSED);

    doc->searchPaths = sp;
    g_doc = doc;

    /* expand first level by default */
    for (i = 0; i < doc->root.childs_len; i++)
        doc->root.childs[i]->flags |= DEPTREE_EXPANDED;

    RebuildVisible();
    if (g_visCount > 0)
        doc->selected = g_visNodes[0].node;
    else
        doc->selected = (doc->root.childs_len > 0) ? doc->root.childs[0] : NULL;

    UpdatePanels(doc);

    sprintf(title, "ntlddgui - %s", path);
    SetWindowTextA(g_hwndMain, title);

    InvalidateRect(g_hwndTree, NULL, TRUE);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Tree window                                                        */
/* ------------------------------------------------------------------ */

static int TreeRowHeight(HDC hdc)
{
    TEXTMETRIC tm;
    HFONT old;
    old = (HFONT)SelectObject(hdc, g_font);
    GetTextMetrics(hdc, &tm);
    SelectObject(hdc, old);
    return tm.tmHeight + 4;
}

static int ComputeMaxWidth(HDC hdc)
{
    int maxW = 0;
    int i;
    HFONT old;
    old = (HFONT)SelectObject(hdc, g_font);
    for (i = 0; i < g_visCount; i++) {
        VisNode *vn = &g_visNodes[i];
        const char *name = BaseName(vn->node->module);
        SIZE sz;
        GetTextExtentPoint32A(hdc, name, (int)strlen(name), &sz);
        {
            int w = vn->depth * 16 + 16 + 4 + sz.cx + 8;
            if (w > maxW) maxW = w;
        }
    }
    SelectObject(hdc, old);
    return maxW;
}

static LRESULT CALLBACK TreeWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc;
        RECT rc;
        hdc = BeginPaint(hwnd, &ps);
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, (HBRUSH)GetStockObject(WHITE_BRUSH));

        if (g_visCount != 0) {
            int rowH;
            int visibleRows;
            int maxScroll;
            int maxW;
            int clientW;
            int maxScrollX;
            SCROLLINFO si;
            HFONT oldFont;
            int i;

            rowH = TreeRowHeight(hdc);
            visibleRows = rc.bottom / rowH;
            if (visibleRows < 1) visibleRows = 1;
            maxScroll = g_visCount - visibleRows;
            if (maxScroll < 0) maxScroll = 0;
            if (g_scrollY > maxScroll) g_scrollY = maxScroll;
            g_scrollMaxY = maxScroll;

            maxW = ComputeMaxWidth(hdc);
            clientW = rc.right - rc.left;
            maxScrollX = maxW - clientW;
            if (maxScrollX < 0) maxScrollX = 0;
            if (g_scrollX > maxScrollX) g_scrollX = maxScrollX;
            g_scrollMaxX = maxScrollX;

            si.cbSize = sizeof(si);
            si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
            si.nMin = 0;
            si.nMax = g_visCount > 0 ? g_visCount - 1 : 0;
            si.nPage = visibleRows;
            si.nPos = g_scrollY;
            SetScrollInfo(hwnd, SB_VERT, &si, TRUE);

            si.nMin = 0;
            si.nMax = maxW > 0 ? maxW : 0;
            si.nPage = clientW > 0 ? clientW : 1;
            si.nPos = g_scrollX;
            SetScrollInfo(hwnd, SB_HORZ, &si, TRUE);

            oldFont = (HFONT)SelectObject(hdc, g_font);
            for (i = 0; i < visibleRows && (g_scrollY + i) < g_visCount; i++) {
                VisNode *vn = &g_visNodes[g_scrollY + i];
                struct DepTreeElement *node = vn->node;
                int rowY = i * rowH;
                int indent = vn->depth * 16;
                int x = indent + 4 - g_scrollX;

                if (g_doc && node == g_doc->selected) {
                    RECT r;
                    r.left = 0; r.top = rowY; r.right = rc.right; r.bottom = rowY + rowH;
                    FillRect(hdc, &r, GetSysColorBrush(COLOR_HIGHLIGHT));
                    SetTextColor(hdc, GetSysColor(COLOR_HIGHLIGHTTEXT));
                } else {
                    SetTextColor(hdc, (node->flags & DEPTREE_UNRESOLVED) ? RGB(200, 0, 0) : GetSysColor(COLOR_WINDOWTEXT));
                }
                SetBkMode(hdc, TRANSPARENT);

                if (node->childs_len > 0) {
                    RECT box;
                    box.left = x; box.top = rowY + 2; box.right = x + 10; box.bottom = rowY + 12;
                    FrameRect(hdc, &box, (HBRUSH)GetStockObject(BLACK_BRUSH));
                    MoveToEx(hdc, x + 2, rowY + 7, NULL);
                    LineTo(hdc, x + 8, rowY + 7);
                    if (!(node->flags & DEPTREE_EXPANDED)) {
                        MoveToEx(hdc, x + 5, rowY + 4, NULL);
                        LineTo(hdc, x + 5, rowY + 10);
                    }
                }

                {
                    const char *name = BaseName(node->module);
                    TextOutA(hdc, x + 16, rowY + 2, name, (int)strlen(name));
                }
            }
            SelectObject(hdc, oldFont);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_VSCROLL: {
        int code;
        code = LOWORD(wParam);
        switch (code) {
        case SB_LINEUP: g_scrollY -= 1; break;
        case SB_LINEDOWN: g_scrollY += 1; break;
        case SB_PAGEUP: g_scrollY -= 10; break;
        case SB_PAGEDOWN: g_scrollY += 10; break;
        case SB_TOP: g_scrollY = 0; break;
        case SB_BOTTOM: g_scrollY = g_scrollMaxY; break;
        case SB_THUMBTRACK:
        case SB_THUMBPOSITION: {
            SCROLLINFO si;
            si.cbSize = sizeof(si);
            si.fMask = SIF_TRACKPOS;
            GetScrollInfo(hwnd, SB_VERT, &si);
            g_scrollY = si.nTrackPos;
            break;
        }
        }
        if (g_scrollY < 0) g_scrollY = 0;
        if (g_scrollY > g_scrollMaxY) g_scrollY = g_scrollMaxY;
        {
            SCROLLINFO si;
            si.cbSize = sizeof(si);
            si.fMask = SIF_POS;
            si.nPos = g_scrollY;
            SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
        }
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }
    case WM_HSCROLL: {
        int code;
        code = LOWORD(wParam);
        switch (code) {
        case SB_LINELEFT: g_scrollX -= 16; break;
        case SB_LINERIGHT: g_scrollX += 16; break;
        case SB_PAGELEFT: g_scrollX -= 80; break;
        case SB_PAGERIGHT: g_scrollX += 80; break;
        case SB_THUMBTRACK:
        case SB_THUMBPOSITION: {
            SCROLLINFO si;
            si.cbSize = sizeof(si);
            si.fMask = SIF_TRACKPOS;
            GetScrollInfo(hwnd, SB_HORZ, &si);
            g_scrollX = si.nTrackPos;
            break;
        }
        }
        if (g_scrollX < 0) g_scrollX = 0;
        if (g_scrollX > g_scrollMaxX) g_scrollX = g_scrollMaxX;
        {
            SCROLLINFO si;
            si.cbSize = sizeof(si);
            si.fMask = SIF_POS;
            si.nPos = g_scrollX;
            SetScrollInfo(hwnd, SB_HORZ, &si, TRUE);
        }
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }
    case WM_MOUSEWHEEL: {
        int delta;
        delta = (short)HIWORD(wParam);
        g_scrollY -= (delta / 120) * 3;
        if (g_scrollY < 0) g_scrollY = 0;
        if (g_scrollY > g_scrollMaxY) g_scrollY = g_scrollMaxY;
        {
            SCROLLINFO si;
            si.cbSize = sizeof(si);
            si.fMask = SIF_POS;
            si.nPos = g_scrollY;
            SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
        }
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }
    case WM_LBUTTONDOWN: {
        HDC hdc;
        int rowH;
        int y;
        int idx;
        hdc = GetDC(hwnd);
        rowH = TreeRowHeight(hdc);
        ReleaseDC(hwnd, hdc);
        y = GetYParam(lParam);
        idx = g_scrollY + (rowH > 0 ? y / rowH : 0);
        if (idx >= 0 && idx < g_visCount) {
            VisNode *vn = &g_visNodes[idx];
            int x;
            int indent;
            int boxX;
            int rowY;
            int inBox;
            x = GetXParam(lParam);
            indent = vn->depth * 16;
            boxX = indent + 4 - g_scrollX;
            rowY = (idx - g_scrollY) * rowH;
            inBox = (vn->node->childs_len > 0) &&
                    (x >= boxX && x <= boxX + 10 &&
                     y >= rowY + 2 && y <= rowY + 12);
            if (inBox) {
                vn->node->flags ^= DEPTREE_EXPANDED;
                RebuildVisible();
                InvalidateRect(hwnd, NULL, TRUE);
            } else {
                if (g_doc) {
                    g_doc->selected = vn->node;
                    UpdatePanels(g_doc);
                    InvalidateRect(hwnd, NULL, TRUE);
                }
            }
        }
        return 0;
    }
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

/* ------------------------------------------------------------------ */
/* Layout                                                             */
/* ------------------------------------------------------------------ */

static void LayoutMainWindow(HWND hwnd)
{
    RECT rc;
    int margin = 8;
    int topH, leftW, detailX, detailW, bottomY, bottomH, listW, labelH = 16;
    GetClientRect(hwnd, &rc);
    if (rc.right < 200 || rc.bottom < 200) return;

    topH = rc.bottom * 6 / 10;
    if (topH < 100) topH = 100;
    leftW = rc.right * 3 / 5;
    if (leftW < 120) leftW = 120;
    detailX = leftW + margin;
    detailW = rc.right - detailX - margin;
    if (detailW < 80) detailW = 80;

    MoveWindow(g_hwndTree, margin, margin, leftW - 2 * margin, topH - 2 * margin, TRUE);
    MoveWindow(g_hwndDetails, detailX, margin, detailW, topH - 2 * margin, TRUE);

    bottomY = topH + margin;
    bottomH = rc.bottom - bottomY - margin;
    if (bottomH < 60) bottomH = 60;
    listW = (rc.right - 3 * margin) / 2;
    if (listW < 80) listW = 80;

    MoveWindow(g_hwndImpLabel, margin, bottomY, listW, labelH, TRUE);
    MoveWindow(g_hwndImports, margin, bottomY + labelH + 2, listW, bottomH - labelH - 2, TRUE);

    MoveWindow(g_hwndExpLabel, margin + listW + margin, bottomY, listW, labelH, TRUE);
    MoveWindow(g_hwndExports, margin + listW + margin, bottomY + labelH + 2, listW, bottomH - labelH - 2, TRUE);
}

/* ------------------------------------------------------------------ */
/* Main window                                                        */
/* ------------------------------------------------------------------ */

static void DoOpenFile(HWND hwnd)
{
    OPENFILENAMEA ofn;
    char szFile[MAX_PATH];
    memset(szFile, 0, sizeof(szFile));
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = "PE modules\0*.exe;*.dll;*.ocx;*.sys\0All files\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if (GetOpenFileNameA(&ofn)) {
        if (LoadDocument(szFile) != 0) {
            MessageBoxA(hwnd, "Failed to load module.", "ntlddgui", MB_OK | MB_ICONERROR);
        }
    }
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        HMENU hMenu;
        HMENU hFile;
        HMENU hView;
        HMENU hHelp;
        hMenu = CreateMenu();
        hFile = CreatePopupMenu();
        hView = CreatePopupMenu();
        hHelp = CreatePopupMenu();
        AppendMenuA(hFile, MF_STRING, ID_FILE_OPEN, "&Open...\tCtrl+O");
        AppendMenuA(hFile, MF_SEPARATOR, 0, NULL);
        AppendMenuA(hFile, MF_STRING, ID_FILE_EXIT, "E&xit");
        AppendMenuA(hView, MF_STRING, ID_VIEW_EXPANDALL, "Expand &All");
        AppendMenuA(hView, MF_STRING, ID_VIEW_COLLAPSE, "&Collapse All");
        AppendMenuA(hHelp, MF_STRING, ID_HELP_ABOUT, "&About");
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hFile, "&File");
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hView, "&View");
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hHelp, "&Help");
        SetMenu(hwnd, hMenu);

        g_hwndTree = CreateWindowExA(0, "NtlddGuiTree", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL,
            0, 0, 100, 100, hwnd, NULL, GetModuleHandle(NULL), NULL);
        g_hwndDetails = CreateWindowExA(0, "EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
            0, 0, 100, 100, hwnd, NULL, GetModuleHandle(NULL), NULL);
        g_hwndImpLabel = CreateWindowExA(0, "STATIC", "Imports",
            WS_CHILD | WS_VISIBLE, 0, 0, 100, 16, hwnd, NULL, GetModuleHandle(NULL), NULL);
        g_hwndImports = CreateWindowExA(0, "LISTBOX", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT,
            0, 0, 100, 100, hwnd, NULL, GetModuleHandle(NULL), NULL);
        g_hwndExpLabel = CreateWindowExA(0, "STATIC", "Exports",
            WS_CHILD | WS_VISIBLE, 0, 0, 100, 16, hwnd, NULL, GetModuleHandle(NULL), NULL);
        g_hwndExports = CreateWindowExA(0, "LISTBOX", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT,
            0, 0, 100, 100, hwnd, NULL, GetModuleHandle(NULL), NULL);
        return 0;
    }
    case WM_SIZE:
        LayoutMainWindow(hwnd);
        return 0;
    case WM_COMMAND: {
        WORD id;
        id = LOWORD(wParam);
        switch (id) {
        case ID_FILE_OPEN:
            DoOpenFile(hwnd);
            break;
        case ID_FILE_EXIT:
            PostQuitMessage(0);
            break;
        case ID_VIEW_EXPANDALL:
            if (g_doc) {
                uint64_t i;
                for (i = 0; i < g_doc->root.childs_len; i++)
                    SetExpandedRecursive(g_doc->root.childs[i], 1);
                for (i = 0; i < g_doc->root.childs_len; i++)
                    g_doc->root.childs[i]->flags |= DEPTREE_EXPANDED;
                RebuildVisible();
                InvalidateRect(g_hwndTree, NULL, TRUE);
            }
            break;
        case ID_VIEW_COLLAPSE:
            if (g_doc) {
                uint64_t i;
                for (i = 0; i < g_doc->root.childs_len; i++) {
                    g_doc->root.childs[i]->flags |= DEPTREE_EXPANDED;
                    SetExpandedRecursive(g_doc->root.childs[i], 0);
                }
                RebuildVisible();
                InvalidateRect(g_hwndTree, NULL, TRUE);
            }
            break;
        case ID_HELP_ABOUT:
            MessageBoxA(hwnd, "ntlddgui - dependency walker for PE modules\n\nUses ntldd PE parser.", "About ntlddgui", MB_OK | MB_ICONINFORMATION);
            break;
        }
        return 0;
    }
    case WM_DROPFILES: {
        HDROP hDrop = (HDROP)wParam;
        char szDropFile[MAX_PATH];

        // Get the count of dropped files (we only care about the first one)
        if (MyDragQueryFile(hDrop, 0, szDropFile, MAX_PATH)) {
            SetForegroundWindow(hwnd);
            LoadDocument(szDropFile);
        }

        // Must release the handle allocated by the shell
        DragFinish(hDrop);
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

/* ------------------------------------------------------------------ */
/* WinMain                                                            */
/* ------------------------------------------------------------------ */

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASSA wc;
    MSG msg;
    HWND hwnd;
    HMODULE hKernel;
    (void)hPrev;

    /* Wow64 setup */
    hKernel = GetModuleHandleA("kernel32.dll");
    if (hKernel) {
        pIsWow64Func = (tW64P)GetProcAddress(hKernel, "IsWow64Process");
        pDisableFunc = (tFSDisable)GetProcAddress(hKernel, "Wow64DisableWow64FsRedirection");
        pRevertFunc = (tFSRevert)GetProcAddress(hKernel, "Wow64RevertWow64FsRedirection");
        pGetSystemWow64DirectoryA = (tGetSystemWow64DirectoryA)GetProcAddress(hKernel, "GetSystemWow64DirectoryA");
    }
    if (pIsWow64Func) {
        pIsWow64Func(GetCurrentProcess(), &g_bIsWow64);
        if (g_bIsWow64 && pDisableFunc && pRevertFunc) {
            pDisableFunc(&g_oldValue);
        }
    }

    g_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    /* Register tree window class */
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = TreeWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = "NtlddGuiTree";
    RegisterClassA(&wc);

    /* Register main window class */
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "NtlddGuiMain";
    RegisterClassA(&wc);

    hwnd = CreateWindowExA(WS_EX_ACCEPTFILES, "NtlddGuiMain", "ntlddgui",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 900, 600,
        NULL, NULL, hInstance, NULL);
    g_hwndMain = hwnd;

    /* If a file path was passed on the command line, open it */
    if (lpCmdLine && lpCmdLine[0]) {
        char path[MAX_PATH];
        int i = 0;
        int j = 0;
        while (lpCmdLine[i] && j < MAX_PATH - 1) {
            if (lpCmdLine[i] == '"') { i++; continue; }
            path[j++] = lpCmdLine[i++];
        }
        path[j] = '\0';
        if (path[0])
            LoadDocument(path);
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    /* cleanup */
    FreeDocument(g_doc);
    g_doc = NULL;
    free(g_visNodes);
    g_visNodes = NULL;

    if (g_bIsWow64 && pRevertFunc) {
        pRevertFunc(g_oldValue);
    }

    return (int)msg.wParam;
}
