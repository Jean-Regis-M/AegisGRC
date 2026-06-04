import React, { useState, useEffect, useRef } from "react";
import { 
  ShieldCheck, 
  ShieldAlert, 
  Terminal, 
  FileText, 
  RefreshCw, 
  Play, 
  ArrowRight, 
  GitCommit, 
  Lock, 
  Unlock, 
  Settings, 
  CheckCircle, 
  XCircle, 
  Plus, 
  Search, 
  Database, 
  BookOpen, 
  Cpu, 
  History, 
  MessageSquare, 
  Clock, 
  ExternalLink,
  Wrench,
  AlertTriangle,
  Send,
  Sparkles,
  ChevronRight,
  User,
  Activity,
  FolderTree,
  Folder,
  FileCode
} from "lucide-react";
import { Finding, ScanResult, DriftAlert, AuditTrailLog, Severity } from "./types";
import { REPO_FILES } from "./repoFiles";
import RiskHeatmap from "./components/RiskHeatmap";
import InfrastructureInventory from "./components/InfrastructureInventory";

const SPECIMENS = {
  insecure: `# Insecure AWS Infrastructure Stack
# AegisGRC Policy Violator Specimen

resource "aws_s3_bucket" "prod_logs" {
  bucket = "aegis-prod-application-logs"
  tags = {
    Environment = "Production"
  }
}

resource "aws_s3_bucket" "public_assets" {
  bucket = "aegis-raw-public-materials"
}

resource "aws_s3_bucket_public_access_block" "public_block_assets" {
  bucket                  = aws_s3_bucket.public_assets.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_security_group" "ssh_ingress_all" {
  name        = "allow-ssh-from-anywhere"
  description = "Insecure SSH configuration that permits global ingress"

  ingress {
    description      = "SSH Access"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "privileged_executor" {
  name = "aegis-unrestricted-executor"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
      }
    ]
  })
}

resource "aws_kms_key" "data_key" {
  description             = "Aegis customer asset encryption key"
  enable_key_rotation     = false
}

resource "aws_cloudtrail" "audit_trail" {
  name                          = "aegis-activity-monitor"
  s3_bucket_name                = aws_s3_bucket.prod_logs.id
  enable_log_file_validation    = false
}`,

  secure: `# AegisGRC - Production Cryptographically Sealed Stack
# All resources conform to SOC2 CC6, ISO 27001, and NIST CSF v2.0 parameters

resource "aws_s3_bucket" "prod_logs" {
  bucket = "aegis-prod-application-logs"
  tags = {
    Environment = "Production"
    Compliance  = "SOC2-CC6"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "prod_logs_encryption" {
  bucket = aws_s3_bucket.prod_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket" "public_assets" {
  bucket = "aegis-raw-public-materials"
}

resource "aws_s3_bucket_public_access_block" "public_block_assets" {
  bucket                  = aws_s3_bucket.public_assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "ssh_ingress_all" {
  name        = "allow-ssh-from-anywhere"
  description = "Secured SSH configuration restricting port access to private corporate boundaries"

  ingress {
    description      = "SSH Access restricted to Office VPN Gateway"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["192.168.10.12/32"]
  }
}

resource "aws_iam_role" "privileged_executor" {
  name = "aegis-unrestricted-executor"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::112233445566:root"
        }
      }
    ]
  })
}

resource "aws_kms_key" "data_key" {
  description             = "Aegis customer asset encryption key"
  enable_key_rotation     = true
}

resource "aws_cloudtrail" "audit_trail" {
  name                          = "aegis-activity-monitor"
  s3_bucket_name                = aws_s3_bucket.prod_logs.id
  enable_log_file_validation    = true
}`
};

export default function App() {
  const [activeTab, setActiveTab] = useState<"dashboard" | "scan" | "chat" | "rego" | "logs" | "repository" | "inventory">("dashboard");
  const [tfCode, setTfCode] = useState<string>(SPECIMENS.insecure);
  const [currentSpecimen, setCurrentSpecimen] = useState<"insecure" | "secure" | "custom">("insecure");
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [logs, setLogs] = useState<AuditTrailLog[]>([]);
  const [drifts, setDrifts] = useState<DriftAlert[]>([]);
  const [frameworks, setFrameworks] = useState<any>(null);
  
  // Chat Assistant States
  const [chatMessages, setChatMessages] = useState<Array<{ role: "user" | "assistant"; content: string }>>([
    { role: "assistant", content: "Greetings! I am **Aegis-AI Auditing Intelligence**. I am continuously linked to our policy-as-code libraries and corporate catalog frameworks (SOC2, ISO 27001, and NIST CSF). Type any compliance concern or press a quick-guide button below to inspect configuration boundaries!" }
  ]);
  const [chatInput, setChatInput] = useState<string>("");
  const [isSendingChat, setIsSendingChat] = useState<boolean>(false);

  // Pipeline Simulator States
  const [pipelineStep, setPipelineStep] = useState<string>("idle");
  const [pipelineTerminal, setPipelineTerminal] = useState<string[]>([]);
  const [pipelineSpecSource, setPipelineSpecSource] = useState<"insecure" | "secure">("insecure");
  const [pipelineScore, setPipelineScore] = useState<number | null>(null);
  const [prComment, setPrComment] = useState<any>(null);

  // Expanded finding for details & AI Cert
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [selectedRepoFile, setSelectedRepoFile] = useState<string>("readme");

  useEffect(() => {
    fetchInitialData();
  }, []);

  const fetchInitialData = async () => {
    try {
      const fwRes = await fetch("/api/frameworks");
      const fwData = await fwRes.json();
      setFrameworks(fwData.frameworks);

      const logRes = await fetch("/api/logs");
      const logData = await logRes.json();
      setLogs(logData);

      const driftRes = await fetch("/api/drift");
      const driftData = await driftRes.json();
      setDrifts(driftData);

      // Perform default specimen scan on mount
      runScan(SPECIMENS.insecure, false);
    } catch (err) {
      console.error("Error loading full-stack baseline metrics:", err);
    }
  };

  const runScan = async (codeToScan: string, pushToLogs = true) => {
    setIsScanning(true);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: codeToScan })
      });
      const data = await res.json();
      if (data.success) {
        setScanResult(data.scan);
        setExpandedFinding(data.scan.findings[0]?.id || null);
        if (pushToLogs) {
          // Re-fetch system logs
          const logRes = await fetch("/api/logs");
          const logData = await logRes.json();
          setLogs(logData);
        }
      }
    } catch (err) {
      console.error("Scanning operation error:", err);
    } finally {
      setIsScanning(false);
    }
  };

  const handleRemediateSnippet = (correctedBlock: string, findingId: string) => {
    // Dynamically replace the failing piece inside the tfCode editor text
    let updatedCode = tfCode;
    
    if (findingId.includes("prod_logs_UNENCRYPTED")) {
      // Append encrypted block
      updatedCode += `\n\n# REMEDIATION BLOCK COMPLIANT CC6.1\n${correctedBlock}`;
    } else if (findingId.includes("public_assets_PUBLIC")) {
      // Replace public read true parameters
      updatedCode = updatedCode.replace(
        /resource "aws_s3_bucket_public_access_block" "public_block_assets" \{[\s\S]*?\}/,
        correctedBlock
      );
    } else if (findingId.includes("PORT_22")) {
      // Replace open port SSH entry
      updatedCode = updatedCode.replace(
        /ingress \{[\s\S]*?cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\]\s*\}/,
        `ingress {
    description      = "SSH Access restricted to Office VPN Router"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["192.168.10.12/32"] # Vault protected
  }`
      );
    } else if (findingId.includes("WILDCARD")) {
      // Replace IAM wildcard assume trust principal
      updatedCode = updatedCode.replace(
        /AWS\s*=\s*"\*"/,
        `AWS = "arn:aws:iam::112233445566:root" # Sealed root access context`
      );
    } else if (findingId.includes("NO_ROTATION")) {
      // Replace rotation false parameters
      updatedCode = updatedCode.replace(
        /enable_key_rotation\s*=\s*false/,
        "enable_key_rotation     = true # Safe automated annual rotate"
      );
    } else if (findingId.includes("NO_VALIDATION")) {
      // Replace file logs verification disabled parameters
      updatedCode = updatedCode.replace(
        /enable_log_file_validation\s*=\s*false/,
        "enable_log_file_validation    = true # Assures tamper proof validation hashes"
      );
    }

    setTfCode(updatedCode);
    setCurrentSpecimen("custom");
    
    // Automatically trigger re-audit for maximum reactive satisfaction
    setTimeout(() => {
      runScan(updatedCode, true);
    }, 150);
  };

  // Chat Q&A Request handler
  const sendChatMessage = async (presetText?: string) => {
    const textToSend = presetText || chatInput;
    if (!textToSend.trim()) return;

    const userMsg = { role: "user" as const, content: textToSend };
    setChatMessages(prev => [...prev, userMsg]);
    setChatInput("");
    setIsSendingChat(true);

    try {
      const res = await fetch("/api/ai-chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question: textToSend,
          history: chatMessages.slice(-6) // Include context history up to 3 roundtrips
        })
      });
      const data = await res.json();
      setChatMessages(prev => [...prev, { role: "assistant", content: data.answer }]);
    } catch (err) {
      console.error("AI assistant chat query failed:", err);
      setChatMessages(prev => [...prev, { role: "assistant", content: "Aegis engine experienced API routing timeout. Verify server context is responsive." }]);
    } finally {
      setIsSendingChat(false);
    }
  };

  // Self-Healing Action for drift items
  const handleFixDrift = async (alertId: string) => {
    try {
      const res = await fetch("/api/drift/remediate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: alertId })
      });
      const data = await res.json();
      if (data.success) {
        // Update drifts array
        setDrifts(prev => prev.map(d => d.id === alertId ? { ...d, remediated: true, actualValue: d.expectedValue } : d));
        // Refresh logs
        const logRes = await fetch("/api/logs");
        const logData = await logRes.json();
        setLogs(logData);
      }
    } catch (err) {
      console.error("Self-healing transaction failed:", err);
    }
  };

  // Simulated Git Push CI/CD Pipeline pipeline
  const runPipelineSimulation = () => {
    setPipelineStep("step_1");
    setPipelineTerminal([]);
    setPipelineScore(null);
    setPrComment(null);

    const logsList = [
      { step: "step_1", msg: "⚡ [04:38:01] git commit hook intercepted inside feature branch 'dev-secops-compliance'" },
      { step: "step_1", msg: "📦 [04:38:02] cloned source repository context (main.tf)..." },
      { step: "step_2", msg: "🔍 [04:38:03] initiating Aegis-IaC parser engine - building resource AST maps..." },
      { step: "step_2", msg: `🔍 [04:38:04] identified ${pipelineSpecSource === "insecure" ? "6" : "7"} declarations for verification.` },
      { step: "step_3", msg: "🛡️ [04:38:05] compiling OPA constraint profiles using 'soc2_cc6.rego' package rules..." },
      { step: "step_3", msg: pipelineSpecSource === "insecure" 
        ? "⚠️ [04:38:06] OPA DENIAL MATCHED: 'soc2.cc6.ingress_administrative_unrestricted' found in SG.ssh_ingress_all" 
        : "✅ [04:38:06] OPA checks PASSED. Absolute regulatory alignment achieved." },
      { step: "step_4", msg: "📋 [04:38:07] mapping validation violations to framework controls metrics..." },
      { step: "step_4", msg: pipelineSpecSource === "insecure" 
        ? "📋 [04:38:07] resolved criteria mappings: CC6.1 Logical access, CC6.3 Access point blocks, CC6.4 Network borders" 
        : "📋 [04:38:07] 100% compliant alignment verified: SOC2 (TSC-2017), ISO 27001, NIST CSF." },
      { step: "step_5", msg: "🤖 [04:38:08] invoking server Gemini AI evidence models for signed audit trail records..." },
      { step: "step_5", msg: "🤖 [04:38:09] generated compliance statements, risk ratings, and cryptographical certificates." },
      { step: "step_6", msg: "📝 [04:38:10] configuring check results and publishing git pull request annotations..." },
      { step: "completed", msg: pipelineSpecSource === "insecure"
        ? "❌ [04:38:11] GITHUB ACTION EXITED WITH STATE 'FAILED'. PR BLOCKED BY AEGIS GUARDRAILS."
        : "✅ [04:38:11] GITHUB ACTION EXITED WITH STATE 'SUCCESS'. PR APPROVED FOR CD AUTO-DEPLOYMENT." }
    ];

    let currentLogIndex = 0;
    const interval = setInterval(() => {
      if (currentLogIndex < logsList.length) {
        const item = logsList[currentLogIndex];
        setPipelineTerminal(prev => [...prev, item.msg]);
        
        // Advance pipeline steps visual progress bar
        if (item.step !== undefined) {
          setPipelineStep(item.step);
        }
        currentLogIndex++;
      } else {
        clearInterval(interval);
        setPipelineStep("completed");
        setPipelineScore(pipelineSpecSource === "insecure" ? 16 : 100);
        
        // Build formal PR Comment layout
        setPrComment({
          repo: "AegisGRC/infrastructure-source",
          prNumber: 42,
          author: "mukizaregis26@gmail.com",
          status: pipelineSpecSource === "insecure" ? "BLOCKED" : "APPROVED",
          timestamp: new Date().toLocaleTimeString(),
          details: pipelineSpecSource === "insecure" 
            ? "Aegis continuous scanner flagged 5 corporate control deviations. Action required. Please secure S3 encryption, terminate global SSH ingress gateways (port 22 on 0.0.0.0/0), and enforce KMS CMK key rotations."
            : "All resources satisfy SOC2 CC6, ISO 27001 Annex constraints, and NIST CSF v2.0 profiles. Signed GRC audit certificates generated and synchronized."
        });

        // Insert new timeline log item
        const newLogAction: AuditTrailLog = {
          id: `log_sim_${Date.now()}`,
          timestamp: new Date().toISOString(),
          action: "CD Pipeline CompletedScan",
          actor: "github-actions-bot",
          details: `Scan run for PR #42 finished in ${pipelineSpecSource === "insecure" ? "BLOCKED" : "APPROVED"} state. Final compliance score evaluated at ${pipelineSpecSource === "insecure" ? "16" : "100"}%.`,
          status: pipelineSpecSource === "insecure" ? "alert" : "success"
        };
        setLogs(prev => [newLogAction, ...prev]);
      }
    }, 600); // Step speed
  };

  // Calculated overall compliance statistics from drift & latest scan
  const currentComplianceScore = scanResult ? scanResult.complianceScore : 84;
  const unremediatedDriftCount = drifts.filter(d => !d.remediated).length;

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#F5F5F5] font-sans selection:bg-[#00FF00] selection:text-[#000000] antialiased">
      
      {/* Executive Portal Header */}
      <header className="sticky top-0 z-50 bg-[#0A0A0A]/95 backdrop-blur-md border-b border-[#222]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-20 flex items-center justify-between">
          
          {/* Logo Brand */}
          <div className="flex items-center space-x-4">
            <div className="w-10 h-10 bg-[#00FF00] rounded-none flex items-center justify-center shrink-0">
              <div className="w-5 h-5 border-2 border-black rotate-45"></div>
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-2xl font-black tracking-tighter uppercase text-white">AEGIS<span className="text-[#888]">GRC</span></span>
                <span className="text-[10px] bg-[#111] text-[#00FF00] px-2.5 py-0.5 border border-[#222] rounded-none font-bold font-mono tracking-widest">PRO</span>
              </div>
              <p className="text-[9px] text-[#555] uppercase tracking-widest font-mono font-bold mt-0.5">Continuous Policy-as-Code & AI Shield</p>
            </div>
          </div>

          {/* Core Telemetry Indicators */}
          <div className="flex items-center space-x-6">
            <div className="hidden md:flex items-center space-x-2 text-[#888]">
              <Clock className="w-3.5 h-3.5 text-[#555]" />
              <span className="text-xs font-mono tracking-tight text-[#888]">UTC: 2026-06-04 10:44</span>
            </div>

            <div className="flex items-center space-x-3 bg-[#111] px-3 py-1.5 border border-[#222] rounded-none">
              <div className="w-2 h-2 bg-[#00FF00] rounded-full animate-pulse"></div>
              <span className="text-[10px] font-mono text-[#00FF00] uppercase tracking-tighter font-semibold">Cloud-Scan-Active</span>
            </div>
          </div>

        </div>
      </header>

      {/* Corporate Dashboard Interface Layout */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        {/* Navigation Selector Rail */}
        <div className="flex flex-wrap border border-[#222] bg-[#111] p-1 mb-10 max-w-fit">
          <button 
            id="tab-btn-dashboard"
            onClick={() => setActiveTab("dashboard")}
            className={`flex items-center space-x-2 px-5 py-3 text-xs font-bold uppercase tracking-widest transition-all cursor-pointer ${activeTab === "dashboard" ? "bg-[#0A0A0A] text-[#00FF00] border border-[#222] font-black" : "text-[#888] hover:text-white"}`}
          >
            <Activity className="w-4 h-4 shrink-0" />
            <span>Dashboard</span>
          </button>
          
          <button 
            id="tab-btn-scan"
            onClick={() => setActiveTab("scan")}
            className={`flex items-center space-x-2 px-5 py-3 text-xs font-bold uppercase tracking-widest transition-all cursor-pointer ${activeTab === "scan" ? "bg-[#0A0A0A] text-[#00FF00] border border-[#222] font-black" : "text-[#888] hover:text-white"}`}
          >
            <Cpu className="w-4 h-4 shrink-0" />
            <span>Laboratory</span>
          </button>

          <button 
            id="tab-btn-inventory"
            onClick={() => setActiveTab("inventory")}
            className={`flex items-center space-x-2 px-5 py-3 text-xs font-bold uppercase tracking-widest transition-all cursor-pointer ${activeTab === "inventory" ? "bg-[#0A0A0A] text-[#00FF00] border border-[#222] font-black" : "text-[#888] hover:text-white"}`}
          >
            <Database className="w-4 h-4 shrink-0" />
            <span>Inventory</span>
          </button>

          <button 
            id="tab-btn-chat"
            onClick={() => setActiveTab("chat")}
            className={`flex items-center space-x-2 px-5 py-3 text-xs font-bold uppercase tracking-widest transition-all cursor-pointer ${activeTab === "chat" ? "bg-[#0A0A0A] text-[#00FF00] border border-[#222] font-black" : "text-[#888] hover:text-white"}`}
          >
            <Sparkles className="w-4 h-4 shrink-0" />
            <span>Auditor Chat</span>
          </button>

          <button 
            id="tab-btn-rego"
            onClick={() => setActiveTab("rego")}
            className={`flex items-center space-x-2 px-5 py-3 text-xs font-bold uppercase tracking-widest transition-all cursor-pointer ${activeTab === "rego" ? "bg-[#0A0A0A] text-[#00FF00] border border-[#222] font-black" : "text-[#888] hover:text-white"}`}
          >
            <BookOpen className="w-4 h-4 shrink-0" />
            <span>Rego Rules</span>
          </button>

          <button 
            id="tab-btn-logs"
            onClick={() => setActiveTab("logs")}
            className={`flex items-center space-x-2 px-5 py-3 text-xs font-bold uppercase tracking-widest transition-all cursor-pointer ${activeTab === "logs" ? "bg-[#0A0A0A] text-[#00FF00] border border-[#222] font-black" : "text-[#888] hover:text-white"}`}
          >
            <Terminal className="w-4 h-4 shrink-0" />
            <span>Audit Trail</span>
          </button>

          <button 
            id="tab-btn-repository"
            onClick={() => setActiveTab("repository")}
            className={`flex items-center space-x-2 px-5 py-3 text-xs font-bold uppercase tracking-widest transition-all cursor-pointer ${activeTab === "repository" ? "bg-[#0A0A0A] text-[#00FF00] border border-[#222] font-black" : "text-[#888] hover:text-white"}`}
          >
            <FolderTree className="w-4 h-4 shrink-0" />
            <span>Repository</span>
          </button>
        </div>

        {/* ==================== TAB 1: EXECUTIVE DASHBOARD OVERVIEW ==================== */}
        {activeTab === "dashboard" && (
          <div className="space-y-8 animate-fade-in">
            
            {/* Top Score & Frame Coverage Bento Row */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              
              {/* Compliance Score Widget */}
              <div id="widget-compliance-score" className="bg-[#111] border border-[#222] p-8 flex flex-col justify-between shadow-none relative overflow-hidden">
                <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#555] block mb-4">Compliance Readiness Index</span>
                
                <div className="my-auto flex items-baseline space-x-2">
                  <span className="text-8xl font-black tracking-tighter leading-none text-white select-none">{currentComplianceScore}</span>
                  <span className="text-2xl font-bold text-[#00FF00] align-top">%</span>
                </div>

                <div className="mt-6">
                  <div className="flex items-center space-x-2">
                    <div className={`w-2.5 h-2.5 rounded-full ${currentComplianceScore >= 90 ? "bg-[#00FF00]" : currentComplianceScore >= 70 ? "bg-[#F27D26]" : "bg-[#FF3E3E]"} animate-pulse`}></div>
                    <span className="text-xs font-bold uppercase tracking-widest text-[#FFF]">
                      {currentComplianceScore >= 90 ? "Audit-Ready Compliant" : currentComplianceScore >= 70 ? "Drift Detected" : "CRITICAL REMEDIATION REQUIRED"}
                    </span>
                  </div>
                  <p className="text-xs text-[#888] mt-2 font-sans leading-relaxed">
                    Evaluated from live state maps, custom policy matrices, and {unremediatedDriftCount === 0 ? "clean container limits" : `${unremediatedDriftCount} active drift anomalies`}.
                  </p>
                </div>
              </div>

              {/* Framework Coverage Progress Indicators */}
              <div id="widget-frameworks-progress" className="bg-[#111] border border-[#222] p-8 flex flex-col justify-between shadow-none">
                <div>
                  <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#555] block mb-4">Regulatory Frameworks Map</span>
                  
                  <div className="space-y-5">
                    {/* SOC2 Progress */}
                    <div>
                      <div className="flex items-center justify-between text-xs font-bold mb-1.5">
                        <span className="text-white">SOC2 Trust Services Principles</span>
                        <span className="font-mono text-[#00FF00]">88% Aligned</span>
                      </div>
                      <div className="w-full bg-[#1a1a1a] h-1.5">
                        <div className="bg-[#00FF00] h-full" style={{ width: "88%" }}></div>
                      </div>
                      <p className="text-[10px] text-[#888] mt-1 font-serif italic">Secures CC6.1 - CC6.4 boundaries for data secrecy policies.</p>
                    </div>

                    {/* ISO27001 Progress */}
                    <div>
                      <div className="flex items-center justify-between text-xs font-bold mb-1.5">
                        <span className="text-white">ISO/IEC 27001:2022 ISMS</span>
                        <span className="font-mono text-[#00FF00]">72% Aligned</span>
                      </div>
                      <div className="w-full bg-[#1a1a1a] h-1.5">
                        <div className="bg-[#00FF00] h-full" style={{ width: "72%" }}></div>
                      </div>
                      <p className="text-[10px] text-[#888] mt-1 font-serif italic">Covers cryptography key lifecycles & logs validation standards.</p>
                    </div>

                    {/* NIST CSF Progress */}
                    <div>
                      <div className="flex items-center justify-between text-xs font-bold mb-1.5">
                        <span className="text-white">NIST CSF v2.0 Matrix</span>
                        <span className="font-mono text-[#00FF00]">65% Aligned</span>
                      </div>
                      <div className="w-full bg-[#1a1a1a] h-1.5">
                        <div className="bg-[#00FF00] h-full" style={{ width: "65%" }}></div>
                      </div>
                      <p className="text-[10px] text-[#888] mt-1 font-serif italic">Validates data-at-rest encryption & continuous compliance history.</p>
                    </div>
                  </div>
                </div>

                <div className="pt-4 border-t border-[#222] mt-6 flex items-center justify-between">
                  <span className="text-[10px] text-[#555] uppercase font-mono font-bold">3 Regulatory Standards</span>
                  <button onClick={() => setActiveTab("scan")} className="text-xs text-[#00FF00] uppercase font-mono font-bold tracking-widest flex items-center space-x-1 hover:underline cursor-pointer">
                    <span>Manage</span>
                    <ChevronRight className="w-3 h-3" />
                  </button>
                </div>
              </div>

              {/* Violations Severity Breakout widget */}
              <div id="widget-severity-breakout" className="bg-[#111] border border-[#222] p-8 flex flex-col justify-between shadow-none">
                <div>
                  <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#555] block mb-4">Open Policy Findings</span>
                  
                  {scanResult && scanResult.findings.length > 0 ? (
                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-4 bg-[#1e1111] border border-[#FF3E3E]/30 rounded-none text-center">
                        <span className="text-[10px] font-bold text-[#FF3E3E] uppercase tracking-wider block">Critical</span>
                        <span className="text-3xl font-mono font-black text-white block mt-1">
                          {scanResult.findings.filter(f => f.severity === "critical").length}
                        </span>
                      </div>
                      <div className="p-4 bg-[#1c1611] border border-[#F27D26]/30 rounded-none text-center">
                        <span className="text-[10px] font-bold text-[#F27D26] uppercase tracking-wider block">High Risk</span>
                        <span className="text-3xl font-mono font-black text-white block mt-1">
                          {scanResult.findings.filter(f => f.severity === "high").length}
                        </span>
                      </div>
                      <div className="p-4 bg-[#11141c] border border-[#222] rounded-none col-span-2 flex items-center justify-around">
                        <div>
                          <span className="text-[10px] font-bold text-[#888] uppercase tracking-wider block">Medium Risk</span>
                          <span className="text-xl font-mono font-bold text-white block mt-1 text-center">
                            {scanResult.findings.filter(f => f.severity === "medium").length}
                          </span>
                        </div>
                        <div className="w-px h-8 bg-[#222]"></div>
                        <div>
                          <span className="text-[10px] font-bold text-[#888] uppercase tracking-wider block">Low Warns</span>
                          <span className="text-xl font-mono font-bold text-white block mt-1 text-center">
                            {scanResult.findings.filter(f => f.severity === "low").length}
                          </span>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center h-28 py-4 text-[#00FF00] text-center bg-[#111] border border-[#222] rounded-none">
                      <CheckCircle className="w-8 h-8 mb-2" />
                      <span className="text-xs font-mono font-bold uppercase tracking-widest">ZERO INFRACTIONS</span>
                    </div>
                  )}
                </div>

                <div className="mt-4 pt-4 border-t border-[#222] flex items-center justify-between">
                  <span className="text-[10px] text-[#555] font-mono uppercase font-bold">Live GRC Assessment</span>
                  <button onClick={() => setActiveTab("scan")} className="text-xs text-[#00FF00] uppercase font-mono font-bold tracking-widest flex items-center space-x-1 hover:underline cursor-pointer">
                    <span>Inspect</span>
                    <ChevronRight className="w-3 h-3" />
                  </button>
                </div>
              </div>

            </div>

            {/* Simulated DevOps pipeline and Live Drift monitoring Row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              
              {/* Continuous CD Pipeline Simulator */}
              <div id="pipeline-simulator-board" className="bg-[#111] text-[#F5F5F5] border border-[#222] p-8 shadow-none flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center space-x-2">
                      <Cpu className="w-5 h-5 text-[#00FF00]" />
                      <span className="text-[10px] font-bold tracking-[0.2em] text-[#555] uppercase">Pipeline Engine</span>
                    </div>
                    {/* Segment Source selector */}
                    <div className="flex items-center space-x-2">
                      <span className="text-[9px] text-[#888] font-mono uppercase font-bold">Source:</span>
                      <select 
                        value={pipelineSpecSource} 
                        onChange={(e: any) => setPipelineSpecSource(e.target.value)}
                        className="bg-[#050505] text-white border border-[#222] text-[10px] rounded p-1.5 focus:outline-none font-mono font-bold"
                      >
                        <option value="insecure">Insecure Specimen.tf</option>
                        <option value="secure">Sealed Compliant.tf</option>
                      </select>
                    </div>
                  </div>

                  <p className="text-xs text-[#888] font-sans leading-relaxed mb-6">
                    Aegis intercepts cloud commits inside continuous workflows. Evaluate compliance parameters, gate policy-violating pull requests, and deploy signed GRC trail parameters automatically.
                  </p>

                  {/* Horizontal CI Pipeline Progress visual row */}
                  <div className="grid grid-cols-6 gap-2 mb-6">
                    {[
                      { step: "step_1", label: "Source" },
                      { step: "step_2", label: "AST Map" },
                      { step: "step_3", label: "OPA Rule" },
                      { step: "step_4", label: "GRC Matrix" },
                      { step: "step_5", label: "Gemini AI" },
                      { step: "step_6", label: "Gating" }
                    ].map((stepSpec, idx) => {
                      const isCurrent = pipelineStep === stepSpec.step;
                      const isCompleted = "step_2,step_3,step_4,step_5,step_6,completed".includes(pipelineStep) && idx < 5 || pipelineStep === "completed";
                      return (
                        <div key={stepSpec.step} className="text-center">
                          <div className={`w-8 h-8 rounded-none mx-auto flex items-center justify-center transition-all border ${isCompleted ? "bg-[#00FF00] text-black border-black font-bold" : isCurrent ? "bg-[#FFF] text-black border-black font-extrabold animate-pulse" : "bg-[#050505] text-[#555] border-[#222]"}`}>
                            {idx + 1}
                          </div>
                          <span className={`text-[9px] block mt-1.5 truncate font-mono font-bold uppercase tracking-tighter ${isCurrent ? "text-white font-black" : isCompleted ? "text-[#00FF00]" : "text-[#555]"}`}>
                            {stepSpec.label}
                          </span>
                        </div>
                      );
                    })}
                  </div>

                  {/* Emulator Terminal logs output console */}
                  <div className="bg-[#050505] border border-[#222] p-4 font-mono text-[10px] leading-relaxed h-44 overflow-y-auto tracking-wide text-[#AAA]">
                    {pipelineTerminal.length === 0 ? (
                      <span className="text-[#555] italic block">// Idle. Trigger simulated engineering sequence...</span>
                    ) : (
                      pipelineTerminal.map((logStr, i) => (
                        <p key={i} className="mb-1 truncate">{logStr}</p>
                      ))
                    )}
                  </div>
                </div>

                <div className="mt-6 flex items-center justify-between border-t border-[#222] pt-4">
                  <span className="text-[9px] text-[#555] font-mono uppercase font-bold">TRIGGER WORKSPACE GATING</span>
                  <button 
                    onClick={runPipelineSimulation}
                    className="bg-[#00FF00] text-black text-xs px-5 py-2.5 rounded-none font-extrabold uppercase tracking-widest flex items-center space-x-1.5 hover:bg-white hover:text-black active:scale-95 transition-all cursor-pointer"
                  >
                    <Play className="w-3.5 h-3.5 fill-black text-black" />
                    <span>Deploy</span>
                  </button>
                </div>
              </div>

              {/* Drift Management and active alarms widget */}
              <div id="drift-management-dashboard" className="bg-[#111] border border-[#222] p-8 shadow-none flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#555] block">Active Out-of-band drifts</span>
                    <span className="text-[9px] bg-[#1a1111] text-[#FF3E3E] px-3 py-1 border border-[#FF3E3E]/30 rounded-none font-bold tracking-widest font-mono uppercase">Continuously Monitored</span>
                  </div>

                  <p className="text-xs text-[#888] font-sans leading-relaxed mb-4">
                    Manual alterations bypass declarative code constraints. Aegis detects drift anomalies automatically and executes immediate self-healing scripts:
                  </p>

                  <div className="space-y-4 max-h-56 overflow-y-auto pr-1">
                    {drifts.map(drift => (
                      <div key={drift.id} className={`p-4 rounded-none border transition-all ${drift.remediated ? "bg-[#050505]/40 border-[#222] opacity-40" : "bg-[#1C1111] border-[#FF3E3E]/30"}`}>
                        <div className="flex items-start justify-between">
                          <div>
                            <div className="flex items-center space-x-2">
                              <span className="text-xs font-mono font-bold text-white">{drift.resource}</span>
                              <span className="text-[9px] bg-[#222] text-[#888] px-2 py-0.5 rounded font-mono uppercase font-bold">{drift.resourceType}</span>
                              {drift.remediated ? (
                                <span className="text-[9px] text-[#00FF00] font-bold font-mono">SEALED</span>
                              ) : (
                                <span className="text-[9px] text-[#FF3E3E] font-bold font-mono animate-pulse">DRIFTED</span>
                              )}
                            </div>
                            <p className="text-[10px] text-[#888] mt-2 font-mono">
                              Discrepancy <code className="font-mono bg-[#050505] px-1 py-0.5 text-[#FF3E3E] border border-[#222]">{drift.parameterChanged}</code> live: <span className="text-[#FF3E3E] font-bold">{drift.actualValue}</span> | expected: <span className="text-[#00FF00] font-bold">{drift.expectedValue}</span>
                            </p>
                          </div>

                          {!drift.remediated && (
                            <button 
                              onClick={() => handleFixDrift(drift.id)}
                              className="text-[10px] bg-white hover:bg-[#00FF00] text-black font-extrabold uppercase tracking-wider py-1 px-3 rounded-none flex items-center space-x-1 shrink-0 active:scale-95 transition-all cursor-pointer"
                            >
                              <Wrench className="w-3 h-3" />
                              <span>Heal</span>
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="pt-4 border-t border-[#222] mt-4 text-right">
                  <span className="text-[10px] text-[#555] font-mono uppercase font-bold">Sync loop: 1.5s active</span>
                </div>
              </div>

            </div>

            {/* Risk Heatmap Component */}
            {scanResult && (
              <RiskHeatmap 
                findings={scanResult.findings}
                setActiveTab={setActiveTab}
                setExpandedFinding={setExpandedFinding}
                onRemediateFinding={handleRemediateSnippet}
              />
            )}

            {/* Simulation Pull Request Git Annotation Modal / Frame display if complete */}
            {prComment && (
              <div className="border border-[#222] bg-[#111] p-8 animate-fade-in">
                <div className="flex items-center justify-between border-b border-[#222] pb-4 mb-6">
                  <div className="flex items-center space-x-3">
                    <CheckCircle className={`w-6 h-6 ${prComment.status === "APPROVED" ? "text-[#00FF00]" : "text-[#FF3E3E]"}`} />
                    <span className="text-sm font-bold uppercase tracking-wider text-white">Github Action Log: PR #{prComment.prNumber}</span>
                  </div>
                  <span className={`text-xs font-mono font-bold px-3 py-1 border ${prComment.status === "APPROVED" ? "bg-[#111e11] text-[#00FF00] border-[#00FF00]/30" : "bg-[#1e1111] text-[#FF3E3E] border-[#FF3E3E]/30"}`}>
                    STATUS: {prComment.status}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs text-[#888]">
                  <div className="space-y-1.5 font-mono">
                    <p>Repository: <span className="text-white font-bold">{prComment.repo}</span></p>
                    <p>Operator: <span className="text-white font-bold">{prComment.author}</span></p>
                    <p>Sealed timestamp: <span className="text-white font-bold">{prComment.timestamp}</span></p>
                  </div>
                  <div className="bg-[#050505] border border-[#222] rounded-none p-4 font-serif text-sm italic text-[#AAA] leading-relaxed">
                    <p className="font-sans text-[10px] font-bold text-[#888] uppercase tracking-widest mb-1.5 block not-italic">Review Comment Log:</p>
                    "{prComment.details}"
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
         {/* ==================== TAB 2: COMPLIANCE PLAYGROUND & SCANNER ==================== */}
        {activeTab === "scan" && (
          <div className="space-y-8 animate-fade-in">
            
            {/* Top Config row */}
            <div className="bg-[#111] border border-[#222] p-5 flex flex-col sm:flex-row items-center justify-between gap-4 shadow-none">
              <div className="flex items-center space-x-3">
                <Database className="w-5 h-5 text-[#00FF00]" />
                <div>
                  <h3 className="font-sans font-black text-sm text-white uppercase tracking-wider">Aegis Policy-as-Code Sandbox</h3>
                  <p className="text-xs text-[#888]">Choose a default specimen profile or input custom Terraform script blocks:</p>
                </div>
              </div>

              {/* Specimen Buttons */}
              <div className="flex bg-[#050505] p-1 border border-[#222] text-xs">
                <button 
                  id="specimen-insecure"
                  onClick={() => {
                    setTfCode(SPECIMENS.insecure);
                    setCurrentSpecimen("insecure");
                  }}
                  className={`px-4 py-2 font-mono font-bold uppercase transition-all cursor-pointer ${currentSpecimen === "insecure" ? "bg-[#FF3E3E] text-black" : "text-[#888] hover:text-white"}`}
                >
                  Insecure AWS
                </button>
                <button 
                  id="specimen-secure"
                  onClick={() => {
                    setTfCode(SPECIMENS.secure);
                    setCurrentSpecimen("secure");
                  }}
                  className={`px-4 py-2 font-mono font-bold uppercase transition-all cursor-pointer ${currentSpecimen === "secure" ? "bg-[#00FF00] text-black" : "text-[#888] hover:text-white"}`}
                >
                  Sealed Secure
                </button>
              </div>
            </div>

            {/* Editor Workspace Panel Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-start">
              
              {/* Left Column: Terraform Textarea Editor */}
              <div className="bg-[#111] border border-[#222] overflow-hidden shadow-none">
                <div className="bg-[#050505] border-b border-[#222] px-5 py-3 flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <FileText className="w-4 h-4 text-[#888]" />
                    <span className="text-xs font-mono font-black text-[#DDD]">src/aws_infra/main.tf</span>
                  </div>
                  <span className="text-[10px] text-[#555] font-mono uppercase font-bold">HCL Code Module</span>
                </div>

                <div className="relative">
                  <textarea 
                    id="terraform-code-textarea"
                    value={tfCode}
                    onChange={(e) => {
                      setTfCode(e.target.value);
                      setCurrentSpecimen("custom");
                    }}
                    className="w-full h-[620px] p-6 font-mono text-xs leading-relaxed bg-black text-[#00FF00] focus:outline-none resize-none"
                    placeholder="# Input custom HCL code modules here..."
                  />
                </div>

                <div className="bg-[#050505] border-t border-[#222] px-5 py-4 flex items-center justify-between">
                  <span className="text-[10px] text-[#555] font-mono uppercase font-bold">Lines under test: {tfCode.split("\n").length}</span>
                  <button 
                    id="trigger-audit-btn"
                    onClick={() => runScan(tfCode, true)}
                    disabled={isScanning}
                    className="bg-[#00FF00] text-black hover:bg-white disabled:bg-[#222] disabled:text-[#555] text-xs py-2.5 px-6 font-mono font-black uppercase tracking-widest transition-all shrink-0 cursor-pointer"
                  >
                    {isScanning ? (
                      <span className="flex items-center space-x-1.5 animate-pulse">
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Evaluating...</span>
                      </span>
                    ) : (
                      <span className="flex items-center space-x-1.5">
                        <Play className="w-3.5 h-3.5 fill-black" />
                        <span>Evaluate OPA</span>
                      </span>
                    )}
                  </button>
                </div>
              </div>

              {/* Right Column: Scan Outputs & Finding Cards */}
              <div className="space-y-4">
                
                {/* Score and Overview Block inside Playground tab */}
                {scanResult && (
                  <div className="bg-[#111] border border-[#222] p-6 shadow-none flex items-center justify-between gap-6">
                    <div>
                      <span className="text-[10px] tracking-widest font-mono text-[#555] font-bold uppercase block">Playground Audit Report</span>
                      <h4 className="text-lg font-sans font-black text-white mt-1 uppercase tracking-wider">Compliance: {scanResult.complianceScore}%</h4>
                      <p className="text-xs text-[#888] mt-1 leading-relaxed">
                        Detected {scanResult.violationsCount} structural policy infractions. SHA256 integrity digest synced.
                      </p>
                    </div>

                    <div className="text-center shrink-0">
                      <div className={`w-16 h-16 border-2 flex items-center justify-center font-mono font-black text-lg ${scanResult.complianceScore >= 95 ? "border-[#00FF00] text-[#00FF00]" : scanResult.complianceScore >= 70 ? "border-[#F27D26] text-[#F27D26]" : "border-[#FF3E3E] text-[#FF3E3E]"}`}>
                        {scanResult.complianceScore}%
                      </div>
                    </div>
                  </div>
                )}

                {/* Scrutinized Findings mapping cards */}
                {scanResult && scanResult.findings.length > 0 ? (
                  <div className="space-y-4 max-h-[520px] overflow-y-auto pr-1">
                    {scanResult.findings.map(finding => {
                      const isExpanded = expandedFinding === finding.id;
                      return (
                        <div key={finding.id} className="bg-[#111] border border-[#222] p-0 shadow-none transition-all">
                          
                          {/* Finding Summary Bar */}
                          <div 
                            onClick={() => setExpandedFinding(isExpanded ? null : finding.id)}
                            className="p-5 flex items-center justify-between cursor-pointer hover:bg-[#050505] transition-all select-none"
                          >
                            <div className="flex items-center space-x-4 bg-transparent">
                              <span className={`w-1.5 h-10 shrink-0 ${finding.severity === "critical" ? "bg-[#FF3E3E] animate-pulse" : "bg-[#F27D26]"}`}></span>
                              <div>
                                <div className="flex items-center space-x-2">
                                  <span className={`text-[9px] font-mono font-black px-2 py-0.5 uppercase tracking-wider ${finding.severity === "critical" ? "bg-[#1e1111] border border-[#FF3E3E]/30 text-[#FF3E3E]" : "bg-[#1c1611] text-[#F27D26]"}`}>
                                    {finding.severity}
                                  </span>
                                  <span className="text-[10px] bg-[#050505] text-[#AAA] px-2 py-0.5 font-bold font-mono border border-[#222]">{finding.controlId}</span>
                                </div>
                                <h5 className="font-sans font-bold text-xs text-white mt-2 truncate max-w-xs md:max-w-md">{finding.resource}</h5>
                              </div>
                            </div>

                            <span className="text-[10px] text-[#888] shrink-0 font-mono font-bold uppercase tracking-wider">
                              Risk Index: <span className="font-extrabold text-[#00FF00]">{finding.riskScore}</span>
                            </span>
                          </div>

                          {/* Expanded Details - AI Explainers & AI Evidence cert & Mitigations */}
                          {isExpanded && (
                            <div className="border-t border-[#222] p-6 bg-[#050505]/60 space-y-5 text-xs text-[#AAA] leading-relaxed">
                              
                              {/* Why it happened explainer with active sparkle */}
                              <div className="bg-[#111] border border-[#222] p-4 font-sans leading-relaxed">
                                <div className="flex items-center space-x-1.5 text-white font-bold mb-2">
                                  <Sparkles className="w-4 h-4 text-[#00FF00] shrink-0 animate-pulse" />
                                  <span className="font-mono text-[10px] text-[#00FF00] uppercase tracking-widest font-black">Gemini AI Audit Explainer:</span>
                                </div>
                                <p className="text-[#AAA] font-sans leading-relaxed">{finding.whyItHappened}</p>
                              </div>

                              {/* Cryptographical signed auditor certificate evidence */}
                              <div className="bg-[#050505] text-[#AAA] font-mono text-[10px] p-4 border border-[#222] leading-relaxed max-h-56 overflow-y-auto">
                                <div className="flex items-center space-x-1 px-1 text-[9px] text-[#555] tracking-[0.2em] font-bold border-b border-[#222] pb-2 mb-2 uppercase">
                                  <Database className="w-3.5 h-3.5 text-[#555]" />
                                  <span>GRC Evidence Record</span>
                                </div>
                                <p className="whitespace-pre-line leading-relaxed">{finding.evidenceText}</p>
                              </div>

                              {/* Action Remediator and code panel */}
                              <div className="space-y-2">
                                <div className="text-[10px] font-mono font-black text-white flex items-center space-x-1.5 uppercase tracking-widest">
                                  <Wrench className="w-3.5 h-3.5 text-[#00FF00]" />
                                  <span>Secure OPA Mitigation Checklist:</span>
                                </div>
                                <div className="relative">
                                  <pre className="p-4 bg-black text-[#00FF00] font-mono text-[10px] border border-[#222] overflow-x-auto select-all leading-relaxed">
                                    {finding.reremedyDoc !== undefined ? (finding as any).reremedyDoc : finding.reremediation !== undefined ? (finding as any).reremediation : finding.remediation}
                                  </pre>
                                </div>
                              </div>

                              {/* Core action button button */}
                              <div className="pt-2 text-right">
                                <button 
                                  onClick={() => handleRemediateSnippet(finding.remediation, finding.id)}
                                  className="bg-[#00FF00] text-black hover:bg-white hover:text-black font-mono font-black uppercase tracking-wider py-2 px-4 flex items-center space-x-1 inline-flex shrink-0 text-xs transition-all active:scale-95 cursor-pointer"
                                >
                                  <Terminal className="w-3.5 h-3.5" />
                                  <span>Apply Fix to HCL</span>
                                </button>
                              </div>

                            </div>
                          )}

                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="bg-[#111] border border-[#222] text-[#AAA] p-8 flex flex-col items-center justify-center text-center">
                    <CheckCircle className="w-12 h-12 text-[#00FF00] mb-4" />
                    <h5 className="font-mono font-black text-white uppercase tracking-widest">Infrastructure Sealed</h5>
                    <p className="text-xs text-[#888] mt-2 max-w-sm leading-relaxed">
                      Congratulations! Aegis did not discover any policy-as-code violations. Configurations fully conform to designated SOC2 CC6 Access Controls and ISO metrics.
                    </p>
                  </div>
                )}

              </div>
            </div>

          </div>
        )}

        {/* ==================== TAB 3: AEGIS-AI GRC CHAT ASSISTANT ==================== */}
        {activeTab === "chat" && (
          <div className="bg-[#111] border border-[#222] overflow-hidden h-[630px] flex flex-col justify-between animate-fade-in max-w-4xl mx-auto">
            
            {/* Chat Pane Header */}
            <div className="bg-[#050505] border-b border-[#222] p-5 flex items-center justify-between">
              <div className="flex items-center space-x-3 bg-transparent">
                <div className="w-8 h-8 bg-white text-black flex items-center justify-center font-bold">
                  <Sparkles className="w-4.5 h-4.5 text-black" />
                </div>
                <div>
                  <h4 className="font-sans font-black text-sm text-white uppercase tracking-wider">Aegis GRC Audit Architect</h4>
                  <p className="text-[10px] text-[#888] font-mono">Powered by server-side Gemini AI model</p>
                </div>
              </div>
              <span className="text-[9px] font-mono tracking-widest font-bold text-[#00FF00] bg-[#111] border border-[#222] px-3 py-1 uppercase">Audit Expert Panel</span>
            </div>

            {/* Conversation Core Messages wrapper */}
            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              {chatMessages.map((msg, i) => {
                const isUser = msg.role === "user";
                return (
                  <div key={i} className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
                    <div className={`max-w-xl p-4 text-xs leading-relaxed ${isUser ? "bg-white text-black font-semibold" : "bg-[#050505] text-[#AAA] border border-[#222]"}`}>
                      <div className="flex items-center space-x-1.5 font-mono font-bold mb-1 uppercase tracking-wider text-[10px]">
                        {isUser ? (
                          <>
                            <User className="w-3.5 h-3.5 text-black shrink-0" />
                            <span className="text-black font-black">User / Assessor</span>
                          </>
                        ) : (
                          <>
                            <Cpu className="w-3.5 h-3.5 text-[#00FF00] shrink-0" />
                            <span className="text-[#00FF00] font-black">Aegis Auditor</span>
                          </>
                        )}
                      </div>
                      <p className="whitespace-pre-line font-sans mt-2 tracking-wide leading-relaxed">{msg.content}</p>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Quick action buttons row */}
            <div className="px-6 py-3 bg-[#050505] border-t border-[#222] overflow-x-auto gap-2 flex items-center shrink-0">
              <span className="text-[9px] text-[#555] uppercase font-mono font-bold shrink-0">Inquire GRC:</span>
              {[
                "Why is CC6.3 critical design S3 block?",
                "Remediation checklist for AWS wildcard principal role trust",
                "Explain formula: Risk = Likelihood * Impact * Exposure"
              ].map((preset, idx) => (
                <button
                  key={idx}
                  onClick={() => sendChatMessage(preset)}
                  className="text-[10px] bg-[#111] border border-[#222] text-[#AAA] py-1.5 px-3 rounded-none hover:bg-white hover:text-black shrink-0 font-mono font-bold uppercase active:scale-95 transition-all cursor-pointer"
                >
                  {preset.substring(0, 32)}...
                </button>
              ))}
            </div>

            {/* Form Input fields */}
            <div className="p-4 border-t border-[#222] bg-[#050505] flex items-center space-x-2.5 shrink-0">
              <input 
                id="search-matrix-input-query"
                type="text"
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && sendChatMessage()}
                placeholder="Ask OPA questions, SOC2 mapping triggers, or query resource remediation rules..."
                className="flex-1 bg-black border border-[#222] text-xs px-4 py-3 text-white font-mono focus:outline-none focus:ring-1 focus:ring-[#00FF00] placeholder-[#555]"
              />
              <button 
                onClick={() => sendChatMessage()}
                disabled={isSendingChat}
                className="bg-[#00FF00] text-black py-3 px-5 font-mono font-black uppercase tracking-wider hover:bg-white hover:text-black disabled:bg-[#222] disabled:text-[#555] active:scale-95 transition-all cursor-pointer"
              >
                <Send className="w-4 h-4" />
              </button>
            </div>

          </div>
        )}

        {/* ==================== TAB 4: ACTIVE OPA REGO LIBRARY ==================== */}
        {activeTab === "rego" && (
          <div className="max-w-4xl mx-auto space-y-6 animate-fade-in">
            
            {/* Cover pane */}
            <div className="bg-[#111] border border-[#222] p-8 shadow-none">
              <div className="flex items-center space-x-3 mb-6">
                <BookOpen className="w-6 h-6 text-[#00FF00]" />
                <div>
                  <h3 className="font-sans font-black text-lg text-white uppercase tracking-wider">OPA Rego Source Library</h3>
                  <p className="text-xs text-[#888]">Live system policies read directly from <code className="font-mono bg-black text-[#00FF00] border border-[#222] px-2 py-0.5">/opa-policies/soc2_cc6.rego</code></p>
                </div>
              </div>

              <p className="text-xs text-[#888] leading-relaxed mb-6 font-sans">
                Open Policy Agent constraints are coded in Rego, a declarative script language explicitly structured to scrutinize semi-structured JSON objects representing server variables or Terraform attributes. Findings are dynamically aligned:
              </p>

              <div className="relative">
                <pre className="p-6 bg-slate-950 text-slate-350 font-mono text-[10.5px] rounded-xl overflow-x-auto border border-slate-800 leading-relaxed max-h-[500px]">
{`package soc2.cc6

# Deny Rules for S3 Public Access Block
deny[msg] {
  bucket := input.aws_s3_bucket[_]
  not has_public_access_block(bucket.id)
  msg := sprintf("SOC2 CC6.3 Violation: Bucket '%s' is missing public access block.", [bucket.id])
}

# Deny S3 Buckets which explicitly allow public traffic
deny[msg] {
  block := input.aws_s3_bucket_public_access_block[_]
  block.block_public_acls == false
  msg := sprintf("SOC2 CC6.3 Violation: block_public_acls de-activated for '%s'.", [block.bucket])
}

# Deny S3 Buckets with no Server Side Encryption Block
deny[msg] {
  bucket := input.aws_s3_bucket[_]
  not is_encrypted(bucket.id)
  msg := sprintf("SOC2 CC6.1 Violation: S3 Bucket '%s' lacks default KMS or AES encryption.", [bucket.bucket])
}

# Deny AWS Security Group ingress allowing CIDR 0.0.0.0/0 on ssh gateway
deny[msg] {
  sg := input.aws_security_group[_]
  ingress := sg.ingress[_]
  ingress.from_port <= 22
  ingress.to_port >= 22
  is_globally_open(ingress.cidr_blocks)
  msg := sprintf("SOC2 CC6.4 Violation: Security Group '%s' open to port 22.", [sg.name])
}`}
                </pre>
              </div>

              <div className="mt-6 pt-4 border-t border-[#222] flex items-center justify-between text-xs text-[#555] font-mono uppercase font-bold">
                <span>Rules compiled at node start: Package soc2.cc6 active</span>
                <span className="text-[#00FF00]">State: SIGNED COMPILER STATE</span>
              </div>
            </div>

          </div>
        )}

        {/* ==================== TAB 5: UNIFIED AUDIT LEDGER TIMELINE ==================== */}
        {activeTab === "logs" && (
          <div className="max-w-4xl mx-auto space-y-6 animate-fade-in">
            
            <div className="bg-[#111] border border-[#222] p-8 shadow-none">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center space-x-3 bg-transparent">
                  <Terminal className="w-6 h-6 text-[#00FF00]" />
                  <div>
                    <h3 className="font-sans font-black text-lg text-white uppercase tracking-wider">Aegis Continuous GRC Audit Trail</h3>
                    <p className="text-xs text-[#888]">Log ledger tracing system startups, policy evaluations, and self-healing actions.</p>
                  </div>
                </div>
                <div className="flex items-center space-x-2.5">
                  <button 
                    id="sync-ledger-btn"
                    onClick={fetchInitialData}
                    className="flex items-center space-x-1.5 bg-[#050505] text-[#AAA] hover:bg-white hover:text-black border border-[#222] text-xs px-4 py-2 font-mono font-bold uppercase transition-all cursor-pointer"
                  >
                    <RefreshCw className="w-3.5 h-3.5 shrink-0" />
                    <span>Sync Timeline</span>
                  </button>
                  <button 
                    id="download-report-btn"
                    onClick={() => {
                      window.open("/api/download-report", "_blank");
                    }}
                    className="flex items-center space-x-1.5 bg-[#00FF00]/10 text-[#00FF00] hover:bg-[#00FF00] hover:text-black border border-[#00FF00]/20 hover:border-[#00FF00] text-xs px-4 py-2 font-mono font-bold uppercase transition-all cursor-pointer"
                  >
                    <FileText className="w-3.5 h-3.5 shrink-0" />
                    <span>Download Report</span>
                  </button>
                </div>
              </div>

              {/* Log Timeline list items */}
              <div className="space-y-4">
                {logs.map((log) => (
                  <div key={log.id} className="p-4 border border-[#222] bg-[#050505]/40 hover:bg-[#050505] transition-all">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center space-x-2.5 flex-wrap">
                        <span className={`w-2 h-2 rounded-full shrink-0 ${log.status === "success" ? "bg-[#00FF00]" : log.status === "warning" ? "bg-[#F27D26]" : "bg-[#FF3E3E] animate-pulse"}`}></span>
                        <span className="text-xs font-mono font-black text-white uppercase tracking-widest">{log.action}</span>
                        <span className="text-[10px] bg-[#111] text-[#AAA] px-2 py-0.5 border border-[#222] font-mono font-semibold">{log.actor}</span>
                      </div>
                      <span className="text-[10px] text-[#555] font-mono">{new Date(log.timestamp).toLocaleString()}</span>
                    </div>
                    <p className="text-[11px] text-[#888] mt-2 font-mono tracking-wide leading-relaxed pl-4 border-l border-[#222]">
                      {log.details}
                    </p>
                  </div>
                ))}
              </div>

              <div className="mt-8 pt-4 border-t border-[#222] text-center">
                <span className="text-[10px] text-[#555] font-mono uppercase tracking-widest font-bold">Signed compliant GRC journal logs • Secured context</span>
              </div>
            </div>

          </div>
        )}

        {/* ==================== TAB 5.5: INFRASTRUCTURE INVENTORY ==================== */}
        {activeTab === "inventory" && (
          <InfrastructureInventory 
            rawCode={tfCode}
            findings={scanResult ? scanResult.findings : []}
            setActiveTab={setActiveTab}
            setExpandedFinding={setExpandedFinding}
            onRemediateFinding={handleRemediateSnippet}
          />
        )}

        {/* ==================== TAB 6: BACKEND REPOSITORY CORE ==================== */}
        {activeTab === "repository" && (
          <div className="max-w-6xl mx-auto space-y-6 animate-fade-in text-[#F5F5F5]">
            <div className="bg-[#111] border border-[#222] p-8 shadow-none">
              
              <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
                <div className="flex items-center space-x-3 bg-transparent text-[#F5F5F5]">
                  <FolderTree className="w-6 h-6 text-[#00FF00]" />
                  <div>
                    <h3 className="font-sans font-black text-lg text-white uppercase tracking-wider">Aegis GRC Core Source Codebase</h3>
                    <p className="text-xs text-[#888]">Fully compiled Python + Policy backend stack running apart from the client web app.</p>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  <span className="text-[10px] font-mono tracking-widest font-bold text-[#00FF00] bg-black border border-[#222] px-3 py-1 uppercase">
                    Status: ACTIVE COMPILED
                  </span>
                </div>
              </div>

              <p className="text-xs text-[#888] leading-relaxed mb-8 max-w-4xl font-sans">
                Below is the authenticated directory tree of the Aegis GRC background daemon. You can browse all FastAPI endpoints, Open Policy Agent Rego engines, database model orchestrations, and CI test matrices.
              </p>

              {/* IDE Split Pane layout */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 min-h-[555px] border border-[#222] bg-[#050505]">
                
                {/* Left Sidebar List Explorer */}
                <div className="lg:col-span-4 border-r border-[#222] p-4 font-mono text-xs select-none max-h-[600px] overflow-y-auto">
                  <div className="text-[10px] uppercase font-bold text-[#555] tracking-widest pb-3 mb-4 border-b border-[#222] flex items-center justify-between">
                    <span>EXPLORER - aegisgrc /</span>
                    <span>23 FILES</span>
                  </div>

                  <div className="space-y-4">
                    
                    {/* Folder 1: .github/workflows */}
                    <div>
                      <div className="flex items-center space-x-2 text-white font-bold mb-1.5">
                        <Folder className="w-3.5 h-3.5 text-[#00FF00]" />
                        <span>.github/workflows/</span>
                      </div>
                      <div className="pl-6 space-y-1">
                        <button 
                          onClick={() => setSelectedRepoFile("ci_workflow")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "ci_workflow" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>ci.yml</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("scan_workflow")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "scan_workflow" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>compliance-scan.yml</span>
                        </button>
                      </div>
                    </div>

                    {/* Folder 2: api */}
                    <div>
                      <div className="flex items-center space-x-2 text-white font-bold mb-1.5">
                        <Folder className="w-3.5 h-3.5 text-[#00FF00]" />
                        <span>api/</span>
                      </div>
                      <div className="pl-6 space-y-1.5">
                        <button 
                          onClick={() => setSelectedRepoFile("main_py")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "main_py" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>main.py</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("dependencies")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "dependencies" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>dependencies.py</span>
                        </button>
                        
                        <div className="pl-4">
                          <div className="flex items-center space-x-1.5 text-white/70 py-0.5">
                            <Folder className="w-3 h-3 text-[#00FF00]/60" />
                            <span className="text-[11px]">routers/</span>
                          </div>
                          <button 
                            onClick={() => setSelectedRepoFile("scans_router")}
                            className={`flex items-center space-x-2 w-full text-left pl-4 py-0.5 hover:text-[#00FF00] transition-colors cursor-pointer text-[11px] ${selectedRepoFile === "scans_router" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                          >
                            <FileCode className="w-2.5 h-2.5 shrink-0" />
                            <span>scans.py</span>
                          </button>
                        </div>

                        <div className="pl-4">
                          <div className="flex items-center space-x-1.5 text-white/70 py-0.5">
                            <Folder className="w-3 h-3 text-[#00FF00]/60" />
                            <span className="text-[11px]">schemas/</span>
                          </div>
                          <button 
                            onClick={() => setSelectedRepoFile("scan_schema")}
                            className={`flex items-center space-x-2 w-full text-left pl-4 py-0.5 hover:text-[#00FF00] transition-colors cursor-pointer text-[11px] ${selectedRepoFile === "scan_schema" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                          >
                            <FileCode className="w-2.5 h-2.5 shrink-0" />
                            <span>scan.py</span>
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Folder 3: core */}
                    <div>
                      <div className="flex items-center space-x-2 text-white font-bold mb-1.5">
                        <Folder className="w-3.5 h-3.5 text-[#00FF00]" />
                        <span>core/</span>
                      </div>
                      <div className="pl-6 space-y-1">
                        <button 
                          onClick={() => setSelectedRepoFile("config")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "config" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>config.py</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("exceptions")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "exceptions" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>exceptions.py</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("logging")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "logging" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>logging.py</span>
                        </button>
                      </div>
                    </div>

                    {/* Folder 4: db */}
                    <div>
                      <div className="flex items-center space-x-2 text-white font-bold mb-1.5">
                        <Folder className="w-3.5 h-3.5 text-[#00FF00]" />
                        <span>db/</span>
                      </div>
                      <div className="pl-6 space-y-1">
                        <button 
                          onClick={() => setSelectedRepoFile("base")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "base" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>base.py</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("models")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "models" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>models.py</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("session")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "session" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>session.py</span>
                        </button>
                      </div>
                    </div>

                    {/* Folder 5: engine */}
                    <div>
                      <div className="flex items-center space-x-2 text-white font-bold mb-1.5">
                        <Folder className="w-3.5 h-3.5 text-[#00FF00]" />
                        <span>engine/</span>
                      </div>
                      <div className="pl-6 space-y-1">
                        <button 
                          onClick={() => setSelectedRepoFile("ai_evidence")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "ai_evidence" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>ai_evidence.py</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("opa_client")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "opa_client" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>opa.py</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("hcl_parser")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "hcl_parser" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>parser.py</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("scorer")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "scorer" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>scorer.py</span>
                        </button>
                      </div>
                    </div>

                    {/* Folder 6: policies */}
                    <div>
                      <div className="flex items-center space-x-2 text-white font-bold mb-1.5">
                        <Folder className="w-3.5 h-3.5 text-[#00FF00]" />
                        <span>policies/soc2/</span>
                      </div>
                      <div className="pl-6 space-y-1">
                        <button 
                          onClick={() => setSelectedRepoFile("rego_policy")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "rego_policy" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>cc6_1.rego</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("rego_mapping")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "rego_mapping" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>mapping.json</span>
                        </button>
                      </div>
                    </div>

                    {/* Folder 7: terraform */}
                    <div>
                      <div className="flex items-center space-x-2 text-white font-bold mb-1.5">
                        <Folder className="w-3.5 h-3.5 text-[#00FF00]" />
                        <span>terraform/</span>
                      </div>
                      <div className="pl-6 space-y-1">
                        <button 
                          onClick={() => setSelectedRepoFile("sample_infra")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "sample_infra" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>sample_infra.tf</span>
                        </button>
                      </div>
                    </div>

                    {/* Folder 8: tests */}
                    <div>
                      <div className="flex items-center space-x-2 text-white font-bold mb-1.5">
                        <Folder className="w-3.5 h-3.5 text-[#00FF00]" />
                        <span>tests/</span>
                      </div>
                      <div className="pl-6 space-y-1">
                        <button 
                          onClick={() => setSelectedRepoFile("test_api")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "test_api" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>test_api.py</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("test_engine")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "test_engine" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>test_engine.py</span>
                        </button>
                      </div>
                    </div>

                    {/* Root level files */}
                    <div className="pt-2 border-t border-[#222]">
                      <div className="text-[10px] uppercase font-bold text-[#444] mb-2 tracking-[0.15em]">ROOT FILES</div>
                      <div className="space-y-1">
                        <button 
                          onClick={() => setSelectedRepoFile("readme")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "readme" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>README.md</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("architecture")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "architecture" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>ARCHITECTURE.md</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("threat_model")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "threat_model" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>THREAT_MODEL.md</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("compliance_mapping")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "compliance_mapping" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>COMPLIANCE_MAPPING.md</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("contributing")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "contributing" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>CONTRIBUTING.md</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("security")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "security" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>SECURITY.md</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("dockerfile")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "dockerfile" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>Dockerfile</span>
                        </button>
                        <button 
                          onClick={() => setSelectedRepoFile("docker_compose")}
                          className={`flex items-center space-x-2 w-full text-left py-1 hover:text-[#00FF00] transition-colors cursor-pointer ${selectedRepoFile === "docker_compose" ? "text-[#00FF00] font-black" : "text-[#888]"}`}
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          <span>docker-compose.yml</span>
                        </button>
                      </div>
                    </div>

                  </div>
                </div>

                {/* Right Source Code Editor Pane */}
                <div className="lg:col-span-8 flex flex-col justify-between max-h-[600px] overflow-hidden">
                  
                  {/* Editor Header */}
                  <div className="bg-[#0e0e0e] border-b border-[#222] p-4 flex items-center justify-between shrink-0 select-none">
                    <div className="flex items-center space-x-3">
                      <FileCode className="w-4 h-4 text-[#00FF00]" />
                      <div>
                        <span className="text-xs font-bold text-white uppercase tracking-wider">
                          {REPO_FILES[selectedRepoFile]?.name || "Source file"}
                        </span>
                        <div className="text-[10px] text-[#555] font-mono mt-0.5">
                          Location: <code className="text-[#00FF00]/90">/{REPO_FILES[selectedRepoFile]?.path}</code>
                        </div>
                      </div>
                    </div>
                    <span className="text-[9px] font-mono uppercase bg-black border border-[#222] text-[#888] px-2.5 py-0.5 select-none font-semibold">
                      {REPO_FILES[selectedRepoFile]?.language || "text"}
                    </span>
                  </div>

                  {/* Code Block Content */}
                  <div className="flex-1 overflow-auto bg-[#050505] p-5 font-mono text-[11px] leading-relaxed select-text">
                    <pre className="text-slate-300">
                      {REPO_FILES[selectedRepoFile]?.content || "(Empty)"}
                    </pre>
                  </div>

                  {/* IDE Footer Status Bar */}
                  <div className="bg-[#0e0e0e] border-t border-[#222] px-4 py-2 flex items-center justify-between text-[10px] text-[#555] font-mono shrink-0 select-none">
                    <span>UTF-8 • python-formatter-v4</span>
                    <span className="text-[#00FF00]">Lines: {(REPO_FILES[selectedRepoFile]?.content.split("\n").length) || 0}</span>
                  </div>

                </div>

              </div>
              
              {/* Export Helper panel */}
              <div className="mt-6 p-4 bg-[#11141c] border border-[#222] flex items-center space-x-3.5">
                <CheckCircle className="w-5 h-5 text-[#00FF00] shrink-0" />
                <p className="text-xs text-[#888] font-sans">
                  <strong className="text-white">Workspace Persistence Verification:</strong> Every file shown here resides inside your Docker-sandboxed workspace environment root folder <code className="font-mono text-xs bg-black text-[#00FF00] border border-[#222] px-1.5 py-0.5 font-bold">/aegisgrc/</code>. Access via the side file-manager or compile locally.
                </p>
              </div>

            </div>
          </div>
        )}

      </main>

      {/* Footer information bar */}
      <footer className="bg-[#050505] border-t border-[#222] py-16 mt-20 text-xs text-[#555]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center space-y-4">
          <div className="flex justify-center space-x-6 font-mono text-[10px] uppercase tracking-widest font-bold text-[#888]">
            <span>SOC2 Type II TSC 2017 compliant</span>
            <span>•</span>
            <span>ISO 27001 ISMS audited</span>
            <span>•</span>
            <span>NIST CSF v2.0 aligned</span>
          </div>
          <p className="font-sans leading-relaxed max-w-2xl mx-auto text-[#888]">
            AegisGRC. Built for elite enterprise Policy-as-Code GRC evaluations. Signed compliance hashes are sealed under continuous SHA-256 protocols.
          </p>
          <p className="font-mono text-[9px] text-[#555]">
            Active Container Engine Ingress: http://0.0.0.0:3000 | System clock synchronized via NTP server.
          </p>
        </div>
      </footer>

    </div>
  );
}
