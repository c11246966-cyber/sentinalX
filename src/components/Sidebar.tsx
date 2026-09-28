import React from 'react';
import {
  LayoutDashboard,
  BellRing,
  Radio,
  FolderKanban,
  Server,
  FileCode2,
  Globe2,
  FileText,
  Settings,
  Lock,
  Workflow,
  CheckCircle2,
  ShieldCheck,
} from 'lucide-react';

interface SidebarProps {
  activeTab: string;
  onSelectTab: (tabId: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onSelectTab }) => {
  const navSections = [
    {
      title: 'SOC Operations',
      items: [
        { id: 'dashboard', label: 'SOC Dashboard', icon: LayoutDashboard, badge: 'Phase 1 Active', active: true },
        { id: 'alerts', label: 'Alert Triage', icon: BellRing, badge: 'Phase 4', active: false },
        { id: 'events', label: 'Event Telemetry', icon: Radio, badge: 'Phase 3', active: false },
        { id: 'incidents', label: 'Incidents', icon: FolderKanban, badge: 'Phase 5', active: false },
        { id: 'hosts', label: 'Host Inventory', icon: Server, badge: 'Phase 6', active: false },
      ],
    },
    {
      title: 'Detection & Intel',
      items: [
        { id: 'rules', label: 'Detection Rules', icon: FileCode2, badge: 'Phase 4', active: false },
        { id: 'threat_intel', label: 'Threat Intelligence', icon: Globe2, badge: 'Phase 8', active: false },
        { id: 'pipeline', label: 'Architecture & Pipeline', icon: Workflow, badge: 'Phase 1 Active', active: true },
      ],
    },
    {
      title: 'Governance & Admin',
      items: [
        { id: 'audit', label: 'Audit Logs', icon: FileText, badge: 'Phase 2', active: false },
        { id: 'auth', label: 'RBAC & Auth', icon: Lock, badge: 'Phase 2', active: false },
        { id: 'settings', label: 'Settings & Health', icon: Settings, badge: 'Phase 1 Active', active: true },
      ],
    },
  ];

  return (
    <aside className="w-64 shrink-0 border-r border-slate-800 bg-slate-950 p-4 hidden lg:flex flex-col justify-between">
      <div className="space-y-6">
        {navSections.map((section) => (
          <div key={section.title} className="space-y-1">
            <h2 className="px-3 text-[11px] font-mono uppercase tracking-wider text-slate-500">
              {section.title}
            </h2>
            <div className="space-y-1 pt-1">
              {section.items.map((item) => {
                const Icon = item.icon;
                const isSelected = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onSelectTab(item.id)}
                    className={`group flex w-full items-center justify-between rounded-md px-3 py-2 text-xs font-medium transition cursor-pointer ${
                      isSelected
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                        : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200 border border-transparent'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <Icon className={`h-4 w-4 ${isSelected ? 'text-emerald-400' : 'text-slate-500 group-hover:text-slate-300'}`} />
                      <span>{item.label}</span>
                    </div>
                    {item.badge && (
                      <span
                        className={`rounded px-1.5 py-0.5 text-[9px] font-mono ${
                          item.badge.includes('Active')
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : 'bg-slate-900 text-slate-500 border border-slate-800'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Security posture summary footer */}
      <div className="rounded-lg border border-slate-800/80 bg-slate-900/50 p-3 text-xs font-mono">
        <div className="flex items-center gap-2 text-emerald-400 font-semibold mb-1">
          <ShieldCheck className="h-4 w-4" />
          <span>PHASE 1 SKELETON</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          FastAPI backend, PostgreSQL schema, Redis broker, and Docker compose configuration initialized.
        </p>
        <div className="mt-2 flex items-center gap-1.5 text-[10px] text-slate-500">
          <CheckCircle2 className="h-3 w-3 text-emerald-500" />
          <span>15/15 automated tests passing</span>
        </div>
      </div>
    </aside>
  );
};
