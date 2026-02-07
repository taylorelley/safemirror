'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import {
  LayoutDashboard,
  Package,
  ShieldAlert,
  FileCheck,
  CheckSquare,
  Users,
  Database,
  BarChart3,
  ScrollText,
  Settings,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { useState } from 'react';

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Packages', href: '/packages', icon: Package },
  { name: 'Approvals', href: '/approvals', icon: CheckSquare },
  {
    name: 'Reports',
    icon: FileCheck,
    children: [
      { name: 'Vulnerabilities', href: '/reports/vulnerabilities', icon: ShieldAlert },
      { name: 'Compliance', href: '/reports/compliance', icon: FileCheck },
    ],
  },
  { name: 'Analytics', href: '/analytics', icon: BarChart3 },
  { name: 'Audit Log', href: '/audit', icon: ScrollText },
  {
    name: 'Settings',
    icon: Settings,
    children: [
      { name: 'Users & Roles', href: '/settings/users', icon: Users },
      { name: 'Mirrors', href: '/settings/mirrors', icon: Database },
      { name: 'Policies', href: '/settings/policies', icon: ShieldAlert },
      { name: 'System', href: '/settings', icon: Settings },
    ],
  },
];

export function Sidebar() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const [expandedItems, setExpandedItems] = useState<string[]>(['Reports', 'Settings']);

  const toggleExpanded = (name: string) => {
    setExpandedItems((prev) =>
      prev.includes(name) ? prev.filter((n) => n !== name) : [...prev, name]
    );
  };

  return (
    <aside
      className={cn(
        'flex flex-col border-r bg-card transition-all duration-300',
        collapsed ? 'w-16' : 'w-64'
      )}
    >
      <div className="flex h-16 items-center justify-between border-b px-4">
        {!collapsed && (
          <Link href="/" className="flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-primary" />
            <span className="font-bold text-lg">SafeMirror</span>
          </Link>
        )}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="rounded-md p-1.5 hover:bg-accent"
        >
          {collapsed ? <ChevronRight className="h-5 w-5" /> : <ChevronLeft className="h-5 w-5" />}
        </button>
      </div>
      <nav className="flex-1 space-y-1 p-2 overflow-y-auto">
        {navigation.map((item) =>
          item.children ? (
            <div key={item.name}>
              <button
                onClick={() => toggleExpanded(item.name)}
                className={cn(
                  'flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium hover:bg-accent',
                  collapsed && 'justify-center'
                )}
              >
                <item.icon className="h-5 w-5" />
                {!collapsed && <span className="flex-1 text-left">{item.name}</span>}
              </button>
              {!collapsed && expandedItems.includes(item.name) && (
                <div className="ml-4 mt-1 space-y-1">
                  {item.children.map((child) => (
                    <Link
                      key={child.href}
                      href={child.href}
                      className={cn(
                        'flex items-center gap-3 rounded-md px-3 py-2 text-sm hover:bg-accent',
                        pathname === child.href && 'bg-accent text-accent-foreground'
                      )}
                    >
                      <child.icon className="h-4 w-4" />
                      <span>{child.name}</span>
                    </Link>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <Link
              key={item.href}
              href={item.href!}
              className={cn(
                'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium hover:bg-accent',
                pathname === item.href && 'bg-accent text-accent-foreground',
                collapsed && 'justify-center'
              )}
              title={collapsed ? item.name : undefined}
            >
              <item.icon className="h-5 w-5" />
              {!collapsed && <span>{item.name}</span>}
            </Link>
          )
        )}
      </nav>
    </aside>
  );
}
