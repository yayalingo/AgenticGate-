import { useState } from 'react';
import { Check, Copy, Download } from 'lucide-react';
import { PYTHON_MODULES, type PythonModuleSpec } from '../lib/pythonTemplates';

export function PythonReferenceView() {
  const [activeId, setActiveId] = useState<PythonModuleSpec['id']>('mcp_lock');
  const [copied, setCopied] = useState(false);

  const activeModule =
    PYTHON_MODULES.find((m) => m.id === activeId) ?? PYTHON_MODULES[0];

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(activeModule.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  };

  const handleDownload = () => {
    const blob = new Blob([activeModule.code], { type: 'text/x-python' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = activeModule.filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="bg-white border border-slate-200 rounded-lg p-5">
        <div className="text-xs font-mono text-slate-500">
          Python 3.12+ Zero-Dependency Standard Library · hashlib / unicodedata / secrets / dataclasses
        </div>
        <h1 className="text-xl font-bold text-slate-900 mt-1">
          Deterministic Pure Python Reference Modules for Agent Core Loops
        </h1>
      </div>

      {/* Module Selector Tabs */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-b border-slate-200 bg-slate-50">
          <div className="flex flex-wrap items-center gap-1.5" role="tablist" aria-label="Python Module Tabs">
            {PYTHON_MODULES.map((mod) => {
              const active = mod.id === activeModule.id;
              return (
                <button
                  key={mod.id}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  onClick={() => {
                    setActiveId(mod.id);
                    setCopied(false);
                  }}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    active
                      ? 'bg-slate-900 text-white'
                      : 'bg-white text-slate-700 border border-slate-200 hover:bg-slate-100'
                  }`}
                >
                  {mod.title}
                </button>
              );
            })}
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={handleCopy}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded-md hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-600" aria-hidden="true" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Copy Source</span>
                </>
              )}
            </button>
            <button
              type="button"
              onClick={handleDownload}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-slate-900 rounded-md hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Download {activeModule.filename}</span>
            </button>
          </div>
        </div>

        <div className="px-5 py-3 border-b border-slate-100 flex flex-wrap items-center justify-between gap-2 text-xs">
          <span className="font-mono font-semibold text-slate-900">
            {activeModule.filename}
          </span>
          <span className="text-slate-600">{activeModule.subtitle}</span>
        </div>

        <pre className="p-5 bg-slate-950 text-slate-100 text-xs font-mono leading-relaxed overflow-x-auto">
          <code>{activeModule.code}</code>
        </pre>
      </div>
    </div>
  );
}
