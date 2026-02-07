"use client";

import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Shield,
  Package,
  ClipboardCheck,
  FileText,
  Users,
  BarChart3,
  Settings,
  Lock,
  CheckCircle2,
  ArrowRight,
  Zap,
  Eye,
  KeyRound,
  ShieldCheck,
  FileSearch,
  Bell,
} from "lucide-react";

const features = [
  {
    icon: Package,
    title: "Multi-Format Scanning",
    description:
      "Comprehensive security scanning for DEB, RPM, APK, PyPI, and NPM packages. One platform for all your package security needs.",
  },
  {
    icon: ClipboardCheck,
    title: "Policy-Based Approvals",
    description:
      "Automated approval workflows based on configurable policies with manual override capabilities for edge cases.",
  },
  {
    icon: FileText,
    title: "Comprehensive Audit",
    description:
      "Immutable audit logs and detailed compliance reports. Export to PDF for stakeholders and auditors.",
  },
  {
    icon: Users,
    title: "RBAC & Permissions",
    description:
      "Five default roles with granular access control. Admin, Security Team, Developer, Viewer, and API-only access levels.",
  },
  {
    icon: BarChart3,
    title: "Real-Time Monitoring",
    description:
      "Live dashboard with security metrics, alerts, and notifications. Stay informed about your package security posture.",
  },
  {
    icon: Settings,
    title: "Enterprise Ready",
    description:
      "SSO integration, API key management, and rate limiting. Built for production workloads at scale.",
  },
];

const securityFeatures = [
  {
    icon: ShieldCheck,
    title: "OWASP Top 10 Compliance",
    description: "Built following OWASP security guidelines to protect against common vulnerabilities.",
  },
  {
    icon: FileSearch,
    title: "Static Analysis (SAST)",
    description: "Automated static code analysis to identify security issues before deployment.",
  },
  {
    icon: Lock,
    title: "TLS Encryption",
    description: "All communications encrypted in transit. Your data stays secure.",
  },
  {
    icon: Eye,
    title: "Complete Audit Trail",
    description: "Every action logged with timestamps and user attribution for full traceability.",
  },
  {
    icon: KeyRound,
    title: "API Key Security",
    description: "Scoped API keys with expiration, rate limiting, and usage tracking.",
  },
  {
    icon: Bell,
    title: "Security Alerts",
    description: "Real-time notifications for policy violations and security events.",
  },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-background">
      {/* Navigation */}
      <nav className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 sticky top-0 z-50">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            <span className="text-xl font-bold">SafeMirror</span>
          </div>
          <div className="flex items-center gap-4">
            <a href="#features" className="text-sm text-muted-foreground hover:text-foreground transition-colors hidden sm:inline">
              Features
            </a>
            <a href="#security" className="text-sm text-muted-foreground hover:text-foreground transition-colors hidden sm:inline">
              Security
            </a>
            <Link href="/login">
              <Button>Sign In</Button>
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative overflow-hidden py-20 sm:py-32">
        {/* Background gradient */}
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-background to-primary/10" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-primary/20 via-transparent to-transparent opacity-50" />
        
        {/* Grid pattern overlay */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#8882_1px,transparent_1px),linear-gradient(to_bottom,#8882_1px,transparent_1px)] bg-[size:14px_24px] [mask-image:radial-gradient(ellipse_80%_50%_at_50%_0%,#000_70%,transparent_110%)]" />

        <div className="container mx-auto px-4 relative">
          <div className="max-w-4xl mx-auto text-center">
            {/* Badge */}
            <div className="inline-flex items-center gap-2 rounded-full bg-primary/10 px-4 py-1.5 text-sm font-medium text-primary mb-8 border border-primary/20">
              <Zap className="h-4 w-4" />
              Enterprise-Grade Package Security
            </div>

            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-6 bg-gradient-to-br from-foreground to-foreground/70 bg-clip-text">
              Enterprise Package Security,{" "}
              <span className="text-primary">Simplified</span>
            </h1>

            <p className="text-lg sm:text-xl text-muted-foreground mb-10 max-w-2xl mx-auto leading-relaxed">
              Multi-format scanning, policy-based approvals, and comprehensive audit trails
              for your software supply chain security. Protect your organization from vulnerable packages.
            </p>

            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link href="/login">
                <Button size="lg" className="w-full sm:w-auto text-base px-8 gap-2 group">
                  Sign In
                  <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
                </Button>
              </Link>
              <a href="#features">
                <Button size="lg" variant="outline" className="w-full sm:w-auto text-base px-8">
                  Learn More
                </Button>
              </a>
            </div>

            {/* Trust indicators */}
            <div className="mt-16 pt-8 border-t border-border/50">
              <p className="text-sm text-muted-foreground mb-4">Trusted by security teams for</p>
              <div className="flex flex-wrap justify-center gap-8 text-muted-foreground">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                  <span className="text-sm font-medium">Supply Chain Security</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                  <span className="text-sm font-medium">Compliance Auditing</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                  <span className="text-sm font-medium">Vulnerability Detection</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 sm:py-28 bg-muted/30">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold mb-4">
              Everything You Need for Package Security
            </h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              A complete platform for scanning, approving, and auditing packages across your organization.
            </p>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6 max-w-6xl mx-auto">
            {features.map((feature, index) => (
              <Card key={index} className="group hover:shadow-lg transition-all duration-300 hover:border-primary/50 bg-card/50 backdrop-blur">
                <CardHeader>
                  <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                    <feature.icon className="h-6 w-6 text-primary" />
                  </div>
                  <CardTitle className="text-xl">{feature.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-base leading-relaxed">
                    {feature.description}
                  </CardDescription>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Security & Compliance Section */}
      <section id="security" className="py-20 sm:py-28">
        <div className="container mx-auto px-4">
          <div className="max-w-6xl mx-auto">
            <div className="grid lg:grid-cols-2 gap-12 items-center">
              {/* Left side - Content */}
              <div>
                <div className="inline-flex items-center gap-2 rounded-full bg-green-500/10 px-4 py-1.5 text-sm font-medium text-green-600 dark:text-green-400 mb-6 border border-green-500/20">
                  <Shield className="h-4 w-4" />
                  Security First
                </div>
                <h2 className="text-3xl sm:text-4xl font-bold mb-6">
                  Built with Security & Compliance in Mind
                </h2>
                <p className="text-lg text-muted-foreground mb-8 leading-relaxed">
                  SafeMirror is designed from the ground up with enterprise security requirements.
                  Every feature is built to help you maintain compliance and protect your software supply chain.
                </p>

                <div className="space-y-4">
                  <div className="flex items-start gap-3">
                    <CheckCircle2 className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
                    <div>
                      <span className="font-medium">Immutable Audit Logs</span>
                      <p className="text-sm text-muted-foreground">
                        Every action is logged and cannot be modified or deleted.
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <CheckCircle2 className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
                    <div>
                      <span className="font-medium">PDF Compliance Reports</span>
                      <p className="text-sm text-muted-foreground">
                        Generate detailed reports for auditors and stakeholders.
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <CheckCircle2 className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
                    <div>
                      <span className="font-medium">Role-Based Access Control</span>
                      <p className="text-sm text-muted-foreground">
                        Granular permissions ensure least-privilege access.
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Right side - Security feature cards */}
              <div className="grid sm:grid-cols-2 gap-4">
                {securityFeatures.map((feature, index) => (
                  <div
                    key={index}
                    className="p-4 rounded-lg border bg-card/50 backdrop-blur hover:border-primary/50 transition-colors"
                  >
                    <feature.icon className="h-8 w-8 text-primary mb-3" />
                    <h3 className="font-semibold mb-1">{feature.title}</h3>
                    <p className="text-sm text-muted-foreground">{feature.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 sm:py-28 bg-gradient-to-br from-primary/10 via-primary/5 to-background">
        <div className="container mx-auto px-4">
          <div className="max-w-3xl mx-auto text-center">
            <h2 className="text-3xl sm:text-4xl font-bold mb-6">
              Ready to Secure Your Package Pipeline?
            </h2>
            <p className="text-lg text-muted-foreground mb-8">
              Start protecting your software supply chain today. Sign in to access your dashboard
              and configure your security policies.
            </p>
            <Link href="/login">
              <Button size="lg" className="text-base px-8 gap-2 group">
                Get Started
                <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 border-t bg-muted/30">
        <div className="container mx-auto px-4">
          <div className="max-w-6xl mx-auto">
            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-8 mb-12">
              {/* Brand */}
              <div className="lg:col-span-2">
                <div className="flex items-center gap-2 mb-4">
                  <Shield className="h-6 w-6 text-primary" />
                  <span className="text-lg font-bold">SafeMirror</span>
                </div>
                <p className="text-sm text-muted-foreground max-w-sm">
                  Enterprise package security scanning platform. Protect your software supply chain
                  with automated scanning, policy-based approvals, and comprehensive audit trails.
                </p>
              </div>

              {/* Resources */}
              <div>
                <h4 className="font-semibold mb-4">Resources</h4>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li>
                    <a href="/docs" className="hover:text-foreground transition-colors">
                      Documentation
                    </a>
                  </li>
                  <li>
                    <a href="/api/docs" className="hover:text-foreground transition-colors">
                      API Reference
                    </a>
                  </li>
                  <li>
                    <a href="#features" className="hover:text-foreground transition-colors">
                      Features
                    </a>
                  </li>
                </ul>
              </div>

              {/* Support */}
              <div>
                <h4 className="font-semibold mb-4">Support</h4>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li>
                    <a href="/help" className="hover:text-foreground transition-colors">
                      Help Center
                    </a>
                  </li>
                  <li>
                    <a href="/contact" className="hover:text-foreground transition-colors">
                      Contact Us
                    </a>
                  </li>
                  <li>
                    <a href="#security" className="hover:text-foreground transition-colors">
                      Security
                    </a>
                  </li>
                </ul>
              </div>
            </div>

            {/* Bottom bar */}
            <div className="pt-8 border-t flex flex-col sm:flex-row justify-between items-center gap-4">
              <p className="text-sm text-muted-foreground">
                © {new Date().getFullYear()} SafeMirror. All rights reserved.
              </p>
              <div className="flex items-center gap-4 text-sm text-muted-foreground">
                <a href="/privacy" className="hover:text-foreground transition-colors">
                  Privacy Policy
                </a>
                <a href="/terms" className="hover:text-foreground transition-colors">
                  Terms of Service
                </a>
              </div>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
